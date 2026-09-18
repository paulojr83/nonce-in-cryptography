const crypto = require('crypto');

const API = process.env.API || 'http://localhost:4000/graphql';
const EMAIL = process.env.EMAIL || 'user@example.com';
const PASSWORD = process.env.PASSWORD || 'DemoPassword123!';
const REALM = 'nonce-todo';

let passed = 0;
let failed = 0;

function check(name, ok) {
  if (ok) {
    console.log(`  PASS  ${name}`);
    passed += 1;
  } else {
    console.log(`  FAIL  ${name}`);
    failed += 1;
  }
}

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const post = (body, headers = {}) =>
  fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }).then((response) => response.json());

const messageKey = (secret, nid, direction) =>
  Buffer.from(
    crypto.hkdfSync(
      'sha256',
      secret,
      Buffer.from(nid, 'hex'),
      Buffer.from(`nonce-transport-v1|${direction}`),
      32
    )
  );

function seal(plaintext, key, nid) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(nid, 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { v: 1, nid, iv: iv.toString('base64'), ct: ciphertext.toString('base64') };
}

function open(envelope, key) {
  const raw = Buffer.from(envelope.ct, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(Buffer.from(envelope.nid, 'utf8'));
  decipher.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([
    decipher.update(raw.subarray(0, raw.length - 16)),
    decipher.final(),
  ]).toString('utf8');
}

const isEnvelope = (value) =>
  Boolean(value) &&
  value.v === 1 &&
  typeof value.nid === 'string' &&
  typeof value.iv === 'string' &&
  typeof value.ct === 'string';

/** Does this wire payload leak any of these strings? */
const leaks = (payload, ...secrets) => {
  const text = JSON.stringify(payload);
  return secrets.some((secret) => secret && text.includes(secret));
};

async function main() {
  console.log('== 1. Handshake ==');
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();

  const challenge = await post({
    query: `mutation($u:String!,$k:String){getNonce(username:$u,clientPublicKey:$k){nonce serverPublicKey}}`,
    variables: { u: EMAIL, k: ecdh.getPublicKey().toString('base64') },
  });

  const { nonce: challengeNonce, serverPublicKey } = challenge.data?.getNonce ?? {};
  check('the server answers with its public key', Boolean(serverPublicKey));
  check('the challenge is issued', Boolean(challengeNonce));

  const secret = ecdh.computeSecret(Buffer.from(serverPublicKey, 'base64'));
  check('both sides agree on a 32-byte secret', secret.length === 32);

  console.log('== 2. Login goes out sealed ==');
  const cnonce = crypto.randomBytes(16).toString('hex');
  const ha1 = sha256(`${EMAIL}:${REALM}:${PASSWORD}`);
  const digest = sha256(`${ha1}:${challengeNonce}:${cnonce}`);
  const loginNid = sha256(challengeNonce);

  const loginBody = JSON.stringify({
    query: `mutation($u:String!,$n:String!,$c:String!,$r:String!){login(username:$u,nonce:$n,cnonce:$c,response:$r){token nonce}}`,
    variables: { u: EMAIL, n: challengeNonce, c: cnonce, r: digest },
  });

  const loginEnvelope = seal(loginBody, messageKey(secret, loginNid, 'req'), loginNid);
  check('the request on the wire is an envelope', isEnvelope(loginEnvelope));
  check('it carries no username or digest', !leaks(loginEnvelope, EMAIL, digest, PASSWORD));

  const loginReply = await post(loginEnvelope);
  check('the reply on the wire is an envelope', isEnvelope(loginReply));

  const login = JSON.parse(open(loginReply, messageKey(secret, loginNid, 'res')));
  const token = login.data?.login?.token;
  let current = login.data?.login?.nonce;
  check('the token only exists after opening it', Boolean(token) && !leaks(loginReply, token));
  check('so does the first session nonce', Boolean(current) && !leaks(loginReply, current));

  const call = async (body) => {
    const nid = sha256(current);
    const sealed = seal(
      JSON.stringify({ ...body, nonce: current }),
      messageKey(secret, nid, 'req'),
      nid
    );
    const reply = await post(sealed, { Authorization: `Bearer ${token}` });
    const opened = JSON.parse(open(reply, messageKey(secret, nid, 'res')));
    const payload = Object.values(opened.data ?? {})[0];
    const rotated = payload?.nonce;
    if (rotated) {
      current = rotated;
    }
    return { sealed, reply, opened, rotated };
  };

  console.log('== 3. A mutation crosses sealed in both directions ==');
  const spent = current;
  const created = await call({
    query: `mutation($i:CreateTodoInput!){createTodo(input:$i){todo{id title} nonce}}`,
    variables: { i: { title: 'sealed channel check' } },
  });

  const todoId = created.opened.data?.createTodo?.todo?.id;
  check('the todo is created', Boolean(todoId));
  check('the title never appears on the wire', !leaks(created.sealed, 'sealed channel check'));
  check('neither does the nonce it spent', !leaks(created.sealed, spent));
  check('nor the rotated one coming back', Boolean(created.rotated) && !leaks(created.reply, created.rotated));

  console.log('== 4. The server stores it in the clear ==');
  const listed = await call({ query: `query{todos(first:50){edges{node{id title}}}}` });
  const titles = (listed.opened.data?.todos?.edges ?? []).map((edge) => edge.node.title);
  check('the todo reads back as plain text', titles.includes('sealed channel check'));

  console.log('== 5. A tampered envelope is refused ==');
  const nid = sha256(current);
  const honest = seal(
    JSON.stringify({ query: `query{me{id}}`, nonce: current }),
    messageKey(secret, nid, 'req'),
    nid
  );
  const flipped = Buffer.from(honest.ct, 'base64');
  flipped[0] ^= 0xff;
  const tampered = await post(
    { ...honest, ct: flipped.toString('base64') },
    { Authorization: `Bearer ${token}` }
  );
  check(
    'a flipped byte breaks the tag',
    tampered.errors?.[0]?.extensions?.error_code === 'TRANSPORT_UNREADABLE'
  );

  const unknown = await post(
    { v: 1, nid: sha256('never issued'), iv: honest.iv, ct: honest.ct },
    { Authorization: `Bearer ${token}` }
  );
  check(
    'an unknown nonce cannot be used to open one',
    unknown.errors?.[0]?.extensions?.error_code === 'TRANSPORT_UNREADABLE'
  );

  if (todoId) {
    console.log('== 6. Clean up ==');
    const removed = await call({
      query: `mutation($id:ID!){deleteTodo(id:$id){todo{id} nonce}}`,
      variables: { id: todoId },
    });
    check('the todo is removed', Boolean(removed.opened.data?.deleteTodo));
  }

  console.log(`\npassed: ${passed}   failed: ${failed}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('verification could not run:', error.message);
  process.exit(1);
});
