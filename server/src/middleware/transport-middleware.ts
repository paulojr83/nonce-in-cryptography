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
  body: string;
  sealWith?: { nonceHash: string; sharedSecret: Buffer };
  nonce?: string;
}

export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransportError';
  }
}

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
