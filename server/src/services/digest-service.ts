import crypto from 'crypto';

/**
 * Challenge-response authentication, the shape HTTP digest auth has used since
 * RFC 2617 and the one the article describes: the server issues a nonce, the
 * client answers with a hash over that nonce, its own cnonce, and the password.
 * The password itself never crosses the network.
 *
 * What the server stores is HA1 - a digest of the credentials, not the password.
 * The client can compute it from what the user typed; the server can compare
 * without ever seeing the password again.
 *
 *   HA1      = sha256(username : realm : password)
 *   response = sha256(HA1 : nonce : cnonce)
 *
 * The trade this makes, plainly: HA1 is password-equivalent. Steal the database
 * and you can authenticate as that user - you still cannot learn the password
 * or reuse it elsewhere, but bcrypt would not have let you in at all. That is
 * the price of a server that can verify a digest it did not choose the inputs
 * for, and it is why digest auth belongs behind TLS.
 */

export const DIGEST_REALM = 'nonce-todo';

export class DigestService {
  /**
   * The stored verifier. Computed once, when an account is created.
   */
  static computeHa1(username: string, password: string): string {
    return crypto
      .createHash('sha256')
      .update(`${username.toLowerCase().trim()}:${DIGEST_REALM}:${password}`)
      .digest('hex');
  }

  /**
   * The answer to one challenge. The client computes this from the password it
   * was just given; the server recomputes it from the HA1 it has stored.
   */
  static computeResponse(ha1: string, nonce: string, cnonce: string): string {
    return crypto.createHash('sha256').update(`${ha1}:${nonce}:${cnonce}`).digest('hex');
  }

  /**
   * Compare two digests without leaking, through timing, how much of the
   * candidate was right.
   */
  static matches(expected: string, candidate: string): boolean {
    if (typeof candidate !== 'string' || expected.length !== candidate.length) {
      return false;
    }

    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(candidate, 'hex'));
  }
}

export default DigestService;
