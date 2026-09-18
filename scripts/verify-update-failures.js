const crypto = require('crypto');

const API = process.env.API || 'http://localhost:4000/graphql';
const EMAIL = process.env.EMAIL || 'user@example.com';
const PASSWORD = process.env.PASSWORD || 'DemoPassword123!';
const REALM = 'nonce-todo';

let passed = 0;
let failed = 0;

function check(name, ok, detail) {
  if (ok) {
    console.log(`  PASS  ${name}`);
    passed += 1;
  } else {
    console.log(`  FAIL  ${name}${detail ? ` (got ${detail})` : ''}`);
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

/** Challenge-response sign-in, without a handshake: this client sends in the clear. */
async function signIn() {
  const challenge = await post({
    query: `mutation($u:String!){getNonce(username:$u){nonce}}`,
    variables: { u: EMAIL },
  });

  const nonce = challenge.data.getNonce.nonce;
  const cnonce = crypto.randomBytes(16).toString('hex');
  const digest = sha256(`${sha256(`${EMAIL}:${REALM}:${PASSWORD}`)}:${nonce}:${cnonce}`);

  const login = await post({
    query: `mutation($u:String!,$n:String!,$c:String!,$r:String!){login(username:$u,nonce:$n,cnonce:$c,response:$r){token nonce}}`,
    variables: { u: EMAIL, n: nonce, c: cnonce, r: digest },
  });

  return login.data.login;
}

const codeOf = (reply) => reply.errors?.[0]?.extensions?.error_code ?? (reply.data ? 'SUCCESS' : 'UNKNOWN');

/** A rotated nonce arrives in the payload on success, in the error otherwise. */
const rotatedNonce = (reply) =>
  reply.errors?.[0]?.extensions?.nonce ?? Object.values(reply.data ?? {})[0]?.nonce ?? null;

const UPDATE = `mutation($id:ID!,$i:UpdateTodoInput!){updateTodo(id:$id,input:$i){todo{id title completed} nonce}}`;

async function main() {
  const session = await signIn();
  const token = session.token;
  let nonce = session.nonce;

  const update = (variables, { nonce: withNonce = nonce, ...headers } = {}) =>
    post(
      { query: UPDATE, variables },
      {
        Authorization: `Bearer ${token}`,
        ...(withNonce ? { 'X-NONCE': withNonce } : {}),
        ...headers,
      }
    );

  // Something disposable to fail against
  const created = await post(
    { query: `mutation($i:CreateTodoInput!){createTodo(input:$i){todo{id} nonce}}`, variables: { i: { title: 'target for the failure checks' } } },
    { Authorization: `Bearer ${token}`, 'X-NONCE': nonce }
  );
  const todoId = created.data.createTodo.todo.id;
  nonce = created.data.createTodo.nonce;

  console.log('== 1. The nonce was spent, then the mutation failed on its own rules ==');

  const blankTitle = await update({ id: todoId, i: { title: '   ' } });
  check('an empty title is refused', codeOf(blankTitle) === 'INVALID_CREDENTIALS', codeOf(blankTitle));
  const afterBlank = rotatedNonce(blankTitle);
  check('it hands back a replacement nonce', Boolean(afterBlank));
  nonce = afterBlank ?? nonce;

  const missingTodo = await update({ id: 'todo_does_not_exist', i: { completed: true } });
  check('an unknown id is refused', codeOf(missingTodo) === 'TODO_NOT_FOUND', codeOf(missingTodo));
  const afterMissing = rotatedNonce(missingTodo);
  check('it hands back a replacement nonce too', Boolean(afterMissing));
  nonce = afterMissing ?? nonce;

  const recovered = await update({ id: todoId, i: { completed: true } });
  check('the replacement actually works', codeOf(recovered) === 'SUCCESS', codeOf(recovered));
  nonce = rotatedNonce(recovered) ?? nonce;

  console.log('== 2. The nonce itself is the problem ==');

  const spent = nonce;
  const consumed = await update({ id: todoId, i: { completed: false } });
  nonce = rotatedNonce(consumed) ?? nonce;

  const replayed = await update({ id: todoId, i: { completed: true } }, { nonce: spent });
  check('a replayed nonce is refused', codeOf(replayed) === 'NONCE_ALREADY_USED', codeOf(replayed));

  const noNonce = await update({ id: todoId, i: { completed: true } }, { nonce: null });
  check('no nonce at all is refused', codeOf(noNonce) === 'NONCE_MISSING', codeOf(noNonce));

  const forged = await update({ id: todoId, i: { completed: true } }, { nonce: 'f'.repeat(64) });
  check('a forged nonce is refused', codeOf(forged) === 'NONCE_INVALID', codeOf(forged));

  const doubled = await post(
    { query: `mutation{ a: updateTodo(id:"${todoId}",input:{completed:true}){todo{id}} b: updateTodo(id:"${todoId}",input:{completed:false}){todo{id}} }` },
    { Authorization: `Bearer ${token}`, 'X-NONCE': nonce }
  );
  check('two mutations on one nonce are refused', codeOf(doubled) === 'NONCE_MULTIPLE_OPERATIONS', codeOf(doubled));

  const other = await signIn();
  const wrongSession = await post(
    { query: UPDATE, variables: { id: todoId, i: { completed: true } } },
    { Authorization: `Bearer ${other.token}`, 'X-NONCE': nonce }
  );
  check('a nonce from another session is refused', codeOf(wrongSession) === 'NONCE_BINDING_MISMATCH', codeOf(wrongSession));

  const wrongAgent = await update({ id: todoId, i: { completed: true } }, { 'User-Agent': 'not-this-client/9.9' });
  check('a nonce from another client is refused', codeOf(wrongAgent) === 'NONCE_BINDING_MISMATCH', codeOf(wrongAgent));

  console.log('== 3. Before the nonce is even looked at ==');

  const anonymous = await post(
    { query: UPDATE, variables: { id: todoId, i: { completed: true } } },
    { 'X-NONCE': nonce }
  );
  check('no token is refused', codeOf(anonymous) === 'NOT_AUTHENTICATED', codeOf(anonymous));

  console.log('== 4. Many requests, one nonce ==');

  const CONCURRENT = 12;
  const answers = await Promise.all(
    Array.from({ length: CONCURRENT }, () => update({ id: todoId, i: { completed: true } }))
  );
  const winners = answers.filter((reply) => codeOf(reply) === 'SUCCESS');
  check(`exactly one of ${CONCURRENT} simultaneous requests wins`, winners.length === 1, `${winners.length}`);
  check(
    'the rest are refused as already used',
    answers.filter((reply) => codeOf(reply) === 'NONCE_ALREADY_USED').length === CONCURRENT - 1
  );
  nonce = rotatedNonce(winners[0]) ?? nonce;

  console.log(`
  Note: the losers report NONCE_ALREADY_USED, never NONCE_RACE_CONDITION.
  That 409 needs two requests to pass validation before either consumes, and
  with an in-memory repository there is nothing between those two steps but
  microtasks - Node will not interleave another request there. The compare-and-
  set is what makes this deterministic; the 409 becomes reachable the day a
  repository does real I/O in that gap, which is the case it exists for.

  NONCE_EXPIRED is not here either: it needs the TTL to pass. Restart the API
  with NONCE_TTL=60000 (the minimum), hold a nonce for 61 seconds, then use it.
`);

  const fresh = await post({ query: `mutation{refreshNonce{nonce}}` }, { Authorization: `Bearer ${token}` });
  await post(
    { query: `mutation($id:ID!){deleteTodo(id:$id){todo{id}}}`, variables: { id: todoId } },
    { Authorization: `Bearer ${token}`, 'X-NONCE': fresh.data.refreshNonce.nonce }
  );

  console.log(`passed: ${passed}   failed: ${failed}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('verification could not run:', error.message);
  process.exit(1);
});
