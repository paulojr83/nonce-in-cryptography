/**
 * Sign-in, as the article draws it:
 *
 *   client → server   getNonce(username, clientPublicKey)
 *   server → client   nonce, serverPublicKey
 *   client → server   login(username, cnonce, sha256(ha1 : nonce : cnonce))
 *   server → client   token
 *
 * The password does not appear in any of those messages. What the client sends
 * is a digest over the server's challenge, its own cnonce and the password;
 * the server recomputes it from a stored verifier. Capturing the exchange buys
 * nothing: the challenge is a nonce, spent by the attempt it answers.
 *
 * The key agreement rides along on the first message, so the second one - and
 * the token and first session nonce coming back - are already encrypted.
 *
 * This is plain fetch rather than a Relay mutation on purpose: it is two round
 * trips that establish the very things the Relay network layer reads (token,
 * nonce, secret), so it cannot go through that layer without a cycle.
 */

import { postGraphQL, saveSecret } from './channel';
import { sha256Hex, startHandshake } from './transport';

const DIGEST_REALM = 'nonce-todo';

const GET_NONCE = `
  mutation GetNonce($username: String!, $clientPublicKey: String) {
    getNonce(username: $username, clientPublicKey: $clientPublicKey) {
      nonce
      serverPublicKey
    }
  }
`;

const LOGIN = `
  mutation Login($username: String!, $nonce: String!, $cnonce: String!, $response: String!) {
    login(username: $username, nonce: $nonce, cnonce: $cnonce, response: $response) {
      user { id email createdAt }
      session { id userId expiresAt status }
      token
      nonce
    }
  }
`;

export interface LoginResult {
  user: { id: string; email: string; createdAt?: string };
  token: string;
  nonce: string;
}

interface GraphQLReply<T> {
  data?: T | null;
  errors?: Array<{ message?: string }> | null;
}

function firstError(reply: GraphQLReply<unknown>): string | null {
  const message = reply.errors?.[0]?.message;
  return message ?? null;
}

/** A client-chosen nonce, so the server does not get to pick every input. */
function generateCnonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export async function signIn(
  endpoint: string,
  username: string,
  password: string,
  fetchFn: typeof fetch = fetch
): Promise<LoginResult> {
  const handshake = await startHandshake();

  const challengeReply = (await postGraphQL({
    endpoint,
    payload: {
      query: GET_NONCE,
      operationName: 'GetNonce',
      variables: { username, clientPublicKey: handshake.publicKey },
    },
    fetchFn,
  }).then((result) => result.json)) as GraphQLReply<{
    getNonce: { nonce: string; serverPublicKey: string | null };
  }>;

  const challenge = challengeReply.data?.getNonce;
  if (!challenge) {
    throw new Error(firstError(challengeReply) ?? 'Could not start sign in');
  }

  const secret = challenge.serverPublicKey
    ? await handshake.complete(challenge.serverPublicKey)
    : null;

  // The password is used here and nowhere else: it goes into a digest and is
  // dropped with this function's stack frame.
  const cnonce = generateCnonce();
  const ha1 = await sha256Hex(`${username.toLowerCase().trim()}:${DIGEST_REALM}:${password}`);
  const response = await sha256Hex(`${ha1}:${challenge.nonce}:${cnonce}`);

  const loginReply = (await postGraphQL({
    endpoint,
    payload: {
      query: LOGIN,
      operationName: 'Login',
      variables: { username, nonce: challenge.nonce, cnonce, response },
    },
    // Sealed with the challenge and the secret just agreed, so the token and
    // the first session nonce come back encrypted.
    nonce: secret ? challenge.nonce : null,
    secret,
    fetchFn,
  }).then((result) => result.json)) as GraphQLReply<{
    login: { user: LoginResult['user']; token: string; nonce: string };
  }>;

  const login = loginReply.data?.login;
  if (!login) {
    throw new Error(firstError(loginReply) ?? 'Sign in failed. Please try again.');
  }

  if (secret) {
    saveSecret(secret);
  }

  return { user: login.user, token: login.token, nonce: login.nonce };
}

export default signIn;
