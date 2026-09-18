/**
 * The client half of the encrypted channel.
 *
 * Mirrors `server/src/crypto/transport-cipher.ts` byte for byte: ECDH on P-256
 * to agree a secret at login, HKDF over that secret salted with each message's
 * nonce hash, AES-256-GCM per message with a random IV and the nonce hash as
 * additional authenticated data.
 *
 * The raw nonce travels inside the ciphertext rather than in a header, so the
 * value the server's replay check needs is never visible on the wire - and
 * neither is the rotated nonce that comes back.
 */

const HKDF_INFO_PREFIX = 'nonce-transport-v1';
const IV_BYTES = 12;

export const TRANSPORT_VERSION = 1;

export type Direction = 'req' | 'res';

export interface TransportEnvelope {
  v: number;
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

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(value.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/** sha256 as lowercase hex - the form both the digest and the envelope use. */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toHex(new Uint8Array(digest));
}

export interface Handshake {
  /** Raw public point, base64, for the server to compute the same secret */
  publicKey: string;
  /** Finish the agreement once the server's public point comes back */
  complete: (serverPublicKeyBase64: string) => Promise<Uint8Array>;
}

/**
 * Start a key agreement.
 *
 * The private half never leaves this function's closure, and the secret it
 * produces is never sent: both sides compute it, nobody transmits it. That is
 * what keeps an eavesdropper out, and it is why the key cannot simply be the
 * nonce - the nonce has to travel.
 */
export async function startHandshake(): Promise<Handshake> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);

  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));

  return {
    publicKey: toBase64(publicKey),
    complete: async (serverPublicKeyBase64: string): Promise<Uint8Array> => {
      const serverKey = await crypto.subtle.importKey(
        'raw',
        fromBase64(serverPublicKeyBase64),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );

      const bits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: serverKey },
        pair.privateKey,
        256
      );

      return new Uint8Array(bits);
    },
  };
}

/**
 * The key for one message: the session secret, salted with this message's
 * nonce hash and separated by direction.
 */
async function deriveMessageKey(
  sharedSecret: Uint8Array,
  nonceHash: string,
  direction: Direction
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    sharedSecret as unknown as ArrayBuffer,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: fromHex(nonceHash),
      info: new TextEncoder().encode(`${HKDF_INFO_PREFIX}|${direction}`),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function seal(
  plaintext: string,
  sharedSecret: Uint8Array,
  nonceHash: string
): Promise<TransportEnvelope> {
  const key = await deriveMessageKey(sharedSecret, nonceHash, 'req');
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: new TextEncoder().encode(nonceHash),
    },
    key,
    new TextEncoder().encode(plaintext)
  );

  return {
    v: TRANSPORT_VERSION,
    nid: nonceHash,
    iv: toBase64(iv),
    ct: toBase64(new Uint8Array(ciphertext)),
  };
}

/** Returns null for anything that does not authenticate. */
export async function open(
  envelope: TransportEnvelope,
  sharedSecret: Uint8Array
): Promise<string | null> {
  try {
    const key = await deriveMessageKey(sharedSecret, envelope.nid, 'res');

    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromBase64(envelope.iv),
        additionalData: new TextEncoder().encode(envelope.nid),
      },
      key,
      fromBase64(envelope.ct)
    );

    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}
