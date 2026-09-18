import crypto from 'crypto';
import { Nonce } from '../types/entities';
import { storage } from '../data/storage-layer';
import { getEnv } from '../utils/env';
 
export class RaceConditionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RaceConditionError';
  }
}
 
export enum NonceErrorCode {
  NONCE_INVALID = 'NONCE_INVALID', // Nonce doesn't exist
  NONCE_ALREADY_USED = 'NONCE_ALREADY_USED', // Nonce has been consumed
  NONCE_EXPIRED = 'NONCE_EXPIRED', // TTL exceeded
  NONCE_BINDING_MISMATCH = 'NONCE_BINDING_MISMATCH', // User, session or client mismatch
  NONCE_RACE_CONDITION = 'NONCE_RACE_CONDITION', // Concurrent consumption attempt
}
 
export interface NonceError {
  code: NonceErrorCode | string;
  message: string;
  statusCode: 401 | 403 | 409;
  timestamp: number;
}
 
export interface NonceValidationResult {
  valid: boolean;
  nonceId?: string;
  error?: NonceError;
}

 
/**
 * The session id a login challenge is filed under. There is no real session
 * yet, and a nonce bound to nothing could be used anywhere.
 */
export const LOGIN_CHALLENGE_SESSION = 'login-challenge';

export class NonceService {
  /** A login challenge is answered in seconds; it has no reason to outlive that */
  private static readonly CHALLENGE_TTL_MS = 120_000;

  /** Nonces are kept this long after expiry so a replay still gets a clear answer */
  private static readonly RETENTION_MS = 86_400_000; // 24 hours

  /** Above this many nonces, retention drops to zero and everything expired goes */
  private static readonly CLEANUP_THRESHOLD = 1_000_000;

  /**
   * TTL and entropy come from the environment (NONCE_TTL, NONCE_LENGTH), which
   * validates both before the server starts. An explicit `ttl` overrides it.
   */
  static async generateNonce(
    userId: string,
    sessionId: string,
    ipAddress: string = 'unknown',
    userAgent: string = '',
    ttl?: number,
    transportKey: string | null = null
  ): Promise<string> {
    const startTime = Date.now();
    const env = getEnv();
    const effectiveTtl = ttl ?? env.nonceTtl;
 
    const nonceBuffer = crypto.randomBytes(env.nonceLength);
    const nonce = nonceBuffer.toString('hex');
 
    const nonceHash = crypto
      .createHash('sha256')
      .update(nonce)
      .digest('hex');
 
    const userAgentHash = crypto
      .createHash('sha256')
      .update(userAgent)
      .digest('hex');
 
    const now = Date.now();
    const nonceRecord: Nonce = {
      id: `nonce_${crypto.randomUUID()}`,
      user_id: userId,
      session_id: sessionId,
      nonce_hash: nonceHash,
      created_at: now,
      expires_at: now + effectiveTtl,
      status: 'active',
      used: false,
      consumed_at: null,
      ip_address: ipAddress,
      user_agent_hash: userAgentHash,
      transport_key: transportKey,
    };
 
    await storage.nonces.create(nonceRecord);

    const endTime = Date.now();
    const duration = endTime - startTime;
 
    if (duration > 50) {
      console.warn(
        `⚠️  Nonce generation took ${duration}ms (target: <50ms) - Requirement 9.1`
      );
    }

    return nonce;
  }
 
  /**
   * A nonce is only accepted for the caller it was issued to: same user, same
   * session, same client. The user agent is compared as a hash, in constant
   * time, so the check cannot be probed byte by byte.
   */
  /**
   * A nonce for a client that has no session yet: the challenge half of
   * challenge-response login.
   *
   * It is a nonce in every sense the article gives - random, single-use,
   * time-limited - which is what stops a captured login from being replayed:
   * the digest answering it is only ever valid once.
   *
   * It carries the key agreed during the handshake, because there is no
   * session to keep it on until the login it authorises succeeds.
   */
  static async generateLoginChallenge(
    userId: string,
    ipAddress: string,
    userAgent: string,
    transportKey: string | null
  ): Promise<string> {
    const nonce = await this.generateNonce(
      userId,
      LOGIN_CHALLENGE_SESSION,
      ipAddress,
      userAgent,
      NonceService.CHALLENGE_TTL_MS,
      transportKey
    );

    return nonce;
  }

  /**
   * The newest challenge still open for this user.
   *
   * Newest wins so that a second attempt, after a mistyped password, is not
   * blocked by the challenge the first one left behind.
   */
  static async findOpenChallenge(userId: string): Promise<Nonce | null> {
    const open = await storage.nonces.findAll({
      user_id: userId,
      session_id: LOGIN_CHALLENGE_SESSION,
      used: false,
      status: 'active',
    });

    const usable = open
      .filter((record) => !this.isExpired(record))
      .sort((a, b) => b.created_at - a.created_at);

    return usable[0] ?? null;
  }

  static async validateNonce(
    nonce: string,
    userId: string,
    sessionId: string,
    userAgent: string = ''
  ): Promise<NonceValidationResult> {
    const result: NonceValidationResult = { valid: false };

    // The nonce is looked up by its hash: the plaintext is never stored, so it
    // is never something an attacker can read out of the database
    const nonceHash = crypto
      .createHash('sha256')
      .update(nonce)
      .digest('hex');

    // Step 1: The nonce must be one this server issued
    const nonceRecord = await storage.nonces.findByHash(nonceHash);

    if (!nonceRecord) {
      result.error = {
        code: NonceErrorCode.NONCE_INVALID,
        message: 'Invalid or expired nonce',
        statusCode: 401,
        timestamp: Date.now(),
      };
      return result;
    } 
    if (nonceRecord.status !== 'active') { 
      if (nonceRecord.status === 'revoked') {
        result.error = {
          code: NonceErrorCode.NONCE_INVALID,
          message: 'Invalid or expired nonce',
          statusCode: 401,
          timestamp: Date.now(),
        };
      } else { 
        result.error = {
          code: NonceErrorCode.NONCE_EXPIRED,
          message: 'Your session has expired. Please refresh and try again.',
          statusCode: 401,
          timestamp: Date.now(),
        };
      }
      return result;
    }
 
    if (nonceRecord.used) {
      result.error = {
        code: NonceErrorCode.NONCE_ALREADY_USED,
        message: 'This request has already been processed. Please try again with a new request.',
        statusCode: 403,
        timestamp: Date.now(),
      };
      return result;
    }
 
    if (this.isExpired(nonceRecord)) { 
      await this.updateStatus(nonceRecord.id, 'expired');

      result.error = {
        code: NonceErrorCode.NONCE_EXPIRED,
        message: 'Your session has expired. Please refresh and try again.',
        statusCode: 401,
        timestamp: Date.now(),
      };
      return result;
    }
 
    if (
      nonceRecord.user_id !== userId ||
      nonceRecord.session_id !== sessionId ||
      !this.matchesClient(nonceRecord, userAgent)
    ) {
      result.error = {
        code: NonceErrorCode.NONCE_BINDING_MISMATCH,
        message: 'Nonce user binding mismatch',
        statusCode: 403,
        timestamp: Date.now(),
      };
      return result;
    }
 
    result.valid = true;
    result.nonceId = nonceRecord.id;

    return result;
  }
  
  static isExpired(nonce: Nonce): boolean {
    return Date.now() > nonce.expires_at;
  }

  /**
   * Compare the caller's user agent against the one the nonce was issued to.
   *
   * Both sides are SHA-256 digests of the same length, so timingSafeEqual is
   * usable directly.
   */
  private static matchesClient(nonce: Nonce, userAgent: string): boolean {
    const expected = Buffer.from(nonce.user_agent_hash, 'hex');
    const actual = crypto.createHash('sha256').update(userAgent).digest();

    if (expected.length !== actual.length) {
      return false;
    }

    return crypto.timingSafeEqual(expected, actual);
  }

 
  static async consumeNonce(nonceId: string): Promise<void> {
    const now = Date.now();
 
    const updated = await storage.nonces.updateAtomic(
      nonceId,
      {
        used: true,
        consumed_at: now,
      },
      (record) => !record.used // Only update if not already used
    );

    if (!updated) {
      throw new RaceConditionError('Nonce was already consumed or does not exist');
    }
  }
 
  /**
   * Revoke every nonce issued to one session.
   *
   * Scoped to the session on purpose: a user signing out in one tab must not
   * invalidate the nonce another of their own sessions is holding.
   */
  static async revokeSessionNonces(sessionId: string): Promise<number> {
    return await storage.nonces.updateMany(
      { session_id: sessionId },
      { status: 'revoked' }
    );
  }

  /**
   * Revoke every nonce a user holds, in every session.
   *
   * For the account-wide events - a password change, a stolen device - not for
   * an ordinary logout.
   */
  static async revokeUserNonces(userId: string): Promise<number> {
    return await storage.nonces.updateMany(
      { user_id: userId },
      { status: 'revoked' }
    );
  }
 
  /**
   * Delete nonces that can no longer do anything: expired, revoked, or already
   * consumed. A consumed nonce keeps `status: 'active'` - nothing marks it
   * otherwise - so it has to be matched on `used`, or it would live forever.
   *
   * Records are kept for RETENTION_MS past expiry so a late replay still gets
   * NONCE_ALREADY_USED rather than the vaguer NONCE_INVALID. Past the
   * threshold, retention drops to zero: bounded memory wins over a nicer error.
   */
  static async cleanupExpiredNonces(): Promise<number> {
    const totalCount = await storage.nonces.count();
    const aggressive = totalCount > this.CLEANUP_THRESHOLD;

    if (aggressive) {
      console.warn(
        `⚠️  Nonce count (${totalCount}) exceeds threshold (${this.CLEANUP_THRESHOLD}). ` +
        `Dropping retention for this run.`
      );
    }

    const cutoff = Date.now() - (aggressive ? 0 : this.RETENTION_MS);

    const staleByStatus = await storage.nonces.deleteMany({
      expires_at: { $lt: cutoff },
      status: { $in: ['expired', 'revoked'] },
    });

    const staleConsumed = await storage.nonces.deleteMany({
      expires_at: { $lt: cutoff },
      used: true,
    });

    const deleted = staleByStatus + staleConsumed;

    console.log(
      `✓ Cleanup job completed: deleted ${deleted} nonces ` +
      `(${staleByStatus} expired/revoked, ${staleConsumed} consumed) ` +
      `past a ${aggressive ? 0 : this.RETENTION_MS}ms retention window`
    );

    return deleted;
  } 
  static async updateStatus(
    nonceId: string,
    status: 'active' | 'expired' | 'revoked'
  ): Promise<void> {
    await storage.nonces.update(nonceId, { status });
  }
 
  static async getNonceMetrics(): Promise<{
    total: number;
    active: number;
    expired: number;
    revoked: number;
    used: number;
  }> {
    const all = await storage.nonces.findAll();

    return {
      total: all.length,
      active: all.filter((n) => n.status === 'active' && !n.used).length,
      expired: all.filter((n) => n.status === 'expired').length,
      revoked: all.filter((n) => n.status === 'revoked').length,
      used: all.filter((n) => n.used).length,
    };
  }
}
