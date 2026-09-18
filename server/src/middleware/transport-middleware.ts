/**
 * Payload encryption at the edge, before GraphQL sees anything.
 *
 * A request arrives as `{ v, nid, iv, ct }`. `nid` names the nonce whose key
 * this message uses; everything else - the query, the variables, and the raw
 * nonce itself - is inside `ct`. The reply goes back the same way, which is why
 * a rotated nonce is never visible on the wire either.
 *
 * Plain JSON still works and is left alone. curl, GraphiQL and the verification
 * script are all clients without a handshake, and a demonstration you cannot
 * poke at with curl teaches less.
 */

import { storage } from '../data/storage-layer';
import { logger } from '../utils/logger';
import {
  deriveMessageKey,
  isTransportEnvelope,
  open,
  seal,
  TRANSPORT_VERSION,
  type TransportEnvelope,
} from '../crypto/transport-cipher';

export interface DecodedRequest {
  /** The GraphQL request body, decrypted if it needed to be */
  body: string;
  /** Present when the body arrived sealed: how to seal the answer */
  sealWith?: { nonceHash: string; sharedSecret: Buffer };
  /** The raw nonce that travelled inside the envelope, if any */
  nonce?: string;
}

export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransportError';
  }
}

/**
 * The secret behind a `nid`.
 *
 * A login challenge carries its own - agreed before there was a session to
 * keep it on. Every other nonce takes its session's.
 */
async function resolveSecret(nonceHash: string): Promise<Buffer | null> {
  const nonce = await storage.nonces.findByHash(nonceHash);
  if (!nonce) {
    return null;
  }

  if (nonce.transport_key) {
    return Buffer.from(nonce.transport_key, 'hex');
  }

  const session = await storage.sessions.findById(nonce.session_id);
  if (!session?.transport_key) {
    return null;
  }

  return Buffer.from(session.transport_key, 'hex');
}

/**
 * Turn what arrived into a GraphQL body.
 *
 * Throws TransportError when a sealed message cannot be opened - a wrong key,
 * a tampered byte, an unknown nonce. The caller answers 400 without saying
 * which, because the difference is only useful to someone guessing.
 */
export async function decodeRequest(rawBody: string): Promise<DecodedRequest> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawBody);
  } catch {
    // Not JSON at all: hand it on untouched and let GraphQL complain
    return { body: rawBody };
  }

  if (!isTransportEnvelope(parsed)) {
    return { body: rawBody };
  }

  const envelope = parsed as TransportEnvelope;
  const sharedSecret = await resolveSecret(envelope.nid);

  if (!sharedSecret) {
    logger.warn('Sealed request referenced a nonce with no transport key');
    throw new TransportError('This message could not be opened');
  }

  const plaintext = open(envelope, deriveMessageKey(sharedSecret, envelope.nid, 'req'));

  if (plaintext === null) {
    logger.warn('Sealed request failed authentication');
    throw new TransportError('This message could not be opened');
  }

  // The nonce rides inside the envelope, so the value the replay check needs
  // is never on the wire in the clear. It is lifted out here and handed to the
  // nonce middleware as a header on the inner request.
  let nonce: string | undefined;
  let body = plaintext;

  try {
    const payload = JSON.parse(plaintext) as { nonce?: unknown };
    if (typeof payload.nonce === 'string' && payload.nonce) {
      nonce = payload.nonce;
      const { nonce: _removed, ...rest } = payload as Record<string, unknown>;
      body = JSON.stringify(rest);
    }
  } catch {
    // Decrypted to something that is not JSON. GraphQL will reject it.
  }

  logger.debug('Opened a sealed request', { nid: envelope.nid, carriedNonce: Boolean(nonce) });

  return {
    body,
    sealWith: { nonceHash: envelope.nid, sharedSecret },
    nonce,
  };
}

/** Seal a GraphQL response for a client that sealed its request. */
export function encodeResponse(
  body: string,
  sealWith: { nonceHash: string; sharedSecret: Buffer }
): string {
  const { iv, ct } = seal(
    body,
    deriveMessageKey(sealWith.sharedSecret, sealWith.nonceHash, 'res'),
    sealWith.nonceHash
  );

  const envelope: TransportEnvelope = {
    v: TRANSPORT_VERSION,
    nid: sealWith.nonceHash,
    iv,
    ct,
  };

  return JSON.stringify(envelope);
}
