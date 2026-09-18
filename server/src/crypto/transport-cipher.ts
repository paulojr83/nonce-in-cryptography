import crypto from 'crypto';

/**
 * Encryption of the GraphQL payload itself, in both directions.
 *
 * Why not key it with the nonce alone: the nonce has to reach the server for
 * the replay check, so a key derived from it is a key an eavesdropper picks up
 * with the message it protects. Instead the two sides agree on a secret at
 * login, over ECDH, and nothing that secret is derived from ever crosses the
 * wire.
 *
 * The nonce's job here is the one it is good at. Each message's key is derived
 * from the shared secret salted with that message's nonce, so a key covers one
 * exchange and no more - the same "used once" rule the replay protection runs
 * on, applied to key material.
 *
 * The salt is the nonce's SHA-256, not the nonce: the server stores only the
 * hash and should not need the raw value to read a message. An HKDF salt does
 * not have to be secret, so nothing is lost by using the public half.
 *
 * What this does not do: ECDH with no certificate stops a passive listener, not
 * an active one who substitutes their own public key for the server's. Proving
 * the key belongs to the server is what TLS certificates are for, and this
 * demonstration has no substitute for them.
 */

export const TRANSPORT_VERSION = 1;

const HKDF_INFO_PREFIX = 'nonce-transport-v1';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const CURVE = 'prime256v1'; // P-256, the curve WebCrypto offers

export type Direction = 'req' | 'res';

/** The wire format. Only `ct` is secret; the rest is routing. */
export interface TransportEnvelope {
  v: number;
  /** sha256 of the nonce whose key this message uses - how the server finds it */
  nid: string;
  iv: string;
  ct: string;
}

export function isTransportEnvelope(value: unknown): value is TransportEnvelope {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<TransportEnvelope>;
  return (
    candidate.v === TRANSPORT_VERSION &&
    typeof candidate.nid === 'string' &&
    typeof candidate.iv === 'string' &&
    typeof candidate.ct === 'string'
  );
}

/**
 * Complete the key agreement the client started.
 *
 * Takes the client's public point (raw, uncompressed, as WebCrypto exports it)
 * and returns this server's public point plus the secret both sides now hold.
 */
export function agreeOnSecret(clientPublicKeyBase64: string): {
  serverPublicKey: string;
  sharedSecret: Buffer;
} {
  const ecdh = crypto.createECDH(CURVE);
  ecdh.generateKeys();

  const clientPublicKey = Buffer.from(clientPublicKeyBase64, 'base64');
  const sharedSecret = ecdh.computeSecret(clientPublicKey);

  return {
    serverPublicKey: ecdh.getPublicKey().toString('base64'),
    sharedSecret,
  };
}

/**
 * The key for one message: the session secret, salted with this message's
 * nonce and separated by direction so a request and its reply never share one.
 */
export function deriveMessageKey(
  sharedSecret: Buffer,
  nonceHash: string,
  direction: Direction
): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(nonceHash, 'hex'),
      Buffer.from(`${HKDF_INFO_PREFIX}|${direction}`),
      KEY_BYTES
    )
  );
}

/**
 * Encrypt one message.
 *
 * The IV is random rather than derived from the nonce: a query does not consume
 * its nonce, so several messages can legitimately share one, and an IV repeated
 * under a single AES-GCM key is the one mistake the mode cannot survive. `nid`
 * goes in as additional authenticated data, so a message cannot be moved onto a
 * different nonce without breaking the tag.
 */
export function seal(
  plaintext: string,
  key: Buffer,
  nonceHash: string
): { iv: string; ct: string } {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(nonceHash, 'utf8'));

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  return { iv: iv.toString('base64'), ct: ciphertext.toString('base64') };
}

/**
 * Decrypt one message. Returns null for anything that does not authenticate -
 * wrong key, tampered bytes, wrong nonce - with no detail about which.
 */
export function open(
  envelope: TransportEnvelope,
  key: Buffer
): string | null {
  try {
    const raw = Buffer.from(envelope.ct, 'base64');
    const tag = raw.subarray(raw.length - 16);
    const ciphertext = raw.subarray(0, raw.length - 16);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(envelope.iv, 'base64')
    );
    decipher.setAAD(Buffer.from(envelope.nid, 'utf8'));
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

/** sha256 of a nonce - the form the database keeps and the envelope quotes. */
export function hashNonce(nonce: string): string {
  return crypto.createHash('sha256').update(nonce).digest('hex');
}
