/**
 * Ask the server for a fresh nonce.
 *
 * This is a plain fetch rather than a Relay mutation on purpose: the nonce
 * provider sits above the Relay environment in the tree - the environment is
 * built with the provider's setters - so it cannot reach back into Relay
 * without a cycle. The request is a single mutation with no cache to update,
 * which is exactly the case Relay adds nothing to.
 */

import { postGraphQL, readSecret } from '../crypto/channel';

const REFRESH_NONCE_DOCUMENT = `mutation RefreshNonce { refreshNonce { nonce } }`;

interface RefreshNonceResponse {
  data?: { refreshNonce?: { nonce?: string | null } | null } | null;
  errors?: Array<{ message?: string }> | null;
}

export interface RequestFreshNonceOptions {
  endpoint: string;
  getToken: () => string | null;
  /** The nonce this request is sealed with, if the client still has one */
  getNonce?: () => string | null;
  getSecret?: () => Uint8Array | null;
  fetchFn?: typeof fetch;
}

/**
 * Returns a usable nonce, or null when there is no session to issue one for.
 *
 * Callers treat null as "the user has to sign in again"; it never throws for an
 * ordinary unauthenticated answer.
 */
export async function requestFreshNonce({
  endpoint,
  getToken,
  getNonce = () => null,
  getSecret = readSecret,
  fetchFn = fetch,
}: RequestFreshNonceOptions): Promise<string | null> {
  const token = getToken();
  if (!token) {
    return null;
  }

  // Sealed when there is still a nonce to key it with. A client that has lost
  // its nonce entirely falls back to the clear, which is the one case where
  // this request cannot be encrypted - and the one case where it carries
  // nothing worth hiding.
  const { json } = await postGraphQL({
    endpoint,
    payload: {
      query: REFRESH_NONCE_DOCUMENT,
      operationName: 'RefreshNonce',
    },
    token,
    nonce: getNonce(),
    secret: getSecret(),
    fetchFn,
  });

  const nonce = (json as RefreshNonceResponse).data?.refreshNonce?.nonce;

  return typeof nonce === 'string' && nonce ? nonce : null;
}

export default requestFreshNonce;
