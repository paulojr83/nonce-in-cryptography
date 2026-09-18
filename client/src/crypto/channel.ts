/**
 * Where the agreed secret lives, and how a request gets sealed with it.
 *
 * The secret sits in sessionStorage next to the token and the nonce, with the
 * same lifetime: it is established at sign-in and gone at sign-out. Same caveat
 * as the token, too - script running on this origin can read it - which is the
 * reason this channel is not a replacement for TLS, only a demonstration of
 * what a nonce can do inside one.
 */

import { fromBase64, isTransportEnvelope, open, seal, sha256Hex, toBase64 } from './transport';

export const CHANNEL_STORAGE_KEY = 'channel.secret';

export function saveSecret(secret: Uint8Array): void {
  try {
    window.sessionStorage.setItem(CHANNEL_STORAGE_KEY, toBase64(secret));
  } catch {
    // A tab that cannot persist falls back to sending in the clear
  }
}

export function readSecret(): Uint8Array | null {
  try {
    const stored = window.sessionStorage.getItem(CHANNEL_STORAGE_KEY);
    return stored ? fromBase64(stored) : null;
  } catch {
    return null;
  }
}

export function clearSecret(): void {
  try {
    window.sessionStorage.removeItem(CHANNEL_STORAGE_KEY);
  } catch {
    // Nothing kept, nothing to clear
  }
}

export interface SealedPostOptions {
  endpoint: string;
  /** The GraphQL request: query, variables, operationName */
  payload: Record<string, unknown>;
  token?: string | null;
  /** The nonce that keys this message. Also what the server's replay check reads. */
  nonce?: string | null;
  secret?: Uint8Array | null;
  fetchFn?: typeof fetch;
}

/**
 * POST a GraphQL request, sealed when there is a secret and a nonce to seal it
 * with, in the clear otherwise.
 *
 * Sending in the clear is not a silent downgrade: it is the state a client is
 * in before it has completed a handshake, and the server treats the two the
 * same way on purpose so curl and GraphiQL keep working.
 */
export async function postGraphQL({
  endpoint,
  payload,
  token,
  nonce,
  secret,
  fetchFn = fetch,
}: SealedPostOptions): Promise<{ json: unknown; wasSealed: boolean }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (!secret || !nonce) {
    // No channel: the nonce travels as a header, the way it did before there
    // was one, and the way curl still sends it.
    if (nonce) {
      headers['X-NONCE'] = nonce;
    }

    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    return { json: await response.json(), wasSealed: false };
  }

  // The nonce goes inside the envelope, not in a header: the server lifts it
  // back out after decrypting, so the replay check still sees it and a
  // listener never does.
  const nonceHash = await sha256Hex(nonce);
  const envelope = await seal(JSON.stringify({ ...payload, nonce }), secret, nonceHash);

  const response = await fetchFn(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(envelope),
  });

  const body = await response.json();

  if (!isTransportEnvelope(body)) {
    // The server answered before it could seal anything - a transport error,
    // or a request it could not open at all.
    return { json: body, wasSealed: false };
  }

  const plaintext = await open(body, secret);
  if (plaintext === null) {
    throw new Error('The server reply could not be opened');
  }

  return { json: JSON.parse(plaintext), wasSealed: true };
}
