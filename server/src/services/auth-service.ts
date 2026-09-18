import * as jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User, Session } from '../types/entities';
import { storage } from '../data/storage-layer';
import { DigestService } from './digest-service';
import { logger } from '../utils/logger';
import { getEnv } from '../utils/env';
import {
  ApplicationError,
  ErrorCode,
  NotFoundError,
} from '../utils/errors';

/**
 * JWT Payload structure for session tokens
 */
export interface JWTPayload {
  userId: string;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export interface CreatedSession {
  session: Session;
  token: string;
}

export class AuthService {

  static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  static async findUserByEmail(email: string): Promise<User | null> {
    try {
      if (!email || typeof email !== 'string') {
        logger.warn('findUserByEmail called with invalid email');
        return null;
      }

      const user = await storage.users.findByEmail(email.toLowerCase().trim());

      if (user) {
        logger.debug('User found by email', { userId: user.id });
      }

      return user;
    } catch (error) {
      logger.error('Error finding user by email', error as Error);
      throw new ApplicationError(
        ErrorCode.DATABASE_ERROR,
        'Failed to look up user',
        500
      );
    }
  }

  static async getUserById(id: string): Promise<User | null> {
    try {
      if (!id || typeof id !== 'string') {
        logger.warn('getUserById called with invalid id', { id });
        return null;
      }

      const user = await storage.users.findById(id);

      if (user) {
        logger.debug('User found by ID', { userId: user.id });
      }

      return user;
    } catch (error) {
      logger.error('Error getting user by ID', error as Error, { id });
      throw new ApplicationError(
        ErrorCode.DATABASE_ERROR,
        'Failed to look up user',
        500
      );
    }
  }

  /**
   * Check a challenge-response answer.
   *
   * The password is not an argument here and never was one: the client sends a
   * digest over the server's nonce, its own cnonce and the password, and this
   * recomputes it from the stored verifier.
   */
  static verifyDigest(
    user: User,
    nonce: string,
    cnonce: string,
    response: string
  ): boolean {
    const expected = DigestService.computeResponse(user.digest_ha1, nonce, cnonce);
    const matched = DigestService.matches(expected, response);

    if (matched) {
      logger.info('Digest accepted', { userId: user.id });
    } else {
      logger.warn('Digest rejected', { userId: user.id });
    }

    return matched;
  }

  static async createSession(
    userId: string,
    transportKey: string | null = null
  ): Promise<CreatedSession> {
    try {
      if (!userId || typeof userId !== 'string') {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid user ID',
          400
        );
      }

      // Verify user exists
      const user = await this.getUserById(userId);
      if (!user) {
        throw new NotFoundError('User not found', ErrorCode.USER_NOT_FOUND);
      }

      const env = getEnv();
      const now = Date.now();

      // randomUUID, not Math.random: a nonce is bound to this id, and a
      // session identifier guessable from a PRNG would undercut that binding.
      const sessionId = `session_${crypto.randomUUID()}`;

      const token = this.generateToken(userId, sessionId);

      const session: Session = {
        id: sessionId,
        user_id: userId,
        created_at: now,
        expires_at: now + env.sessionTtl,
        last_activity: now,
        status: 'active',
        token: this.hashToken(token),
        transport_key: transportKey,
      };

      // Persist session
      const createdSession = await storage.sessions.create(session);

      // Update user's active sessions list
      const currentActiveSessions = user.active_sessions || [];
      await storage.users.update(userId, {
        active_sessions: [...currentActiveSessions, sessionId],
        last_login: now,
      });

      logger.info('Session created successfully', {
        userId,
        sessionId,
        expiresAt: session.expires_at,
      });

      return { session: createdSession, token };
    } catch (error) {
      logger.error('Error creating session', error as Error, { userId });
      throw error;
    }
  }

  static generateToken(userId: string, sessionId: string): string {
    try {
      if (!userId || typeof userId !== 'string') {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid user ID',
          400
        );
      }

      if (!sessionId || typeof sessionId !== 'string') {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid session ID',
          400
        );
      }

      const env = getEnv();

      if (!env.jwtSecret) {
        throw new ApplicationError(
          ErrorCode.INTERNAL_SERVER_ERROR,
          'JWT configuration missing',
          500
        );
      }

      const expiresIn = Math.floor(env.sessionTtl / 1000); // Convert to seconds

      const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
        userId,
        sessionId,
      };

      const token = jwt.sign(payload, env.jwtSecret, {
        algorithm: 'HS256',
        expiresIn,
      });

      logger.debug('JWT token generated', {
        userId,
        sessionId,
        expiresIn,
      });

      return token;
    } catch (error) {
      logger.error('Error generating token', error as Error, { userId, sessionId });

      if (error instanceof ApplicationError) {
        throw error;
      }

      throw new ApplicationError(
        ErrorCode.INTERNAL_SERVER_ERROR,
        'Failed to generate authentication token',
        500
      );
    }
  }

  static async revokeSession(sessionId: string): Promise<void> {
    try {
      if (!sessionId || typeof sessionId !== 'string') {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid session ID',
          400
        );
      }

      // Find session
      const session = await storage.sessions.findById(sessionId);
      if (!session) {
        logger.warn('Attempted to revoke non-existent session', { sessionId });
        return;
      }

      // Mark session as revoked
      await storage.sessions.update(sessionId, {
        status: 'revoked',
      });

      // Revoke all associated nonces
      await storage.nonces.updateMany(
        { session_id: sessionId },
        { status: 'revoked' }
      );

      // Remove session from user's active_sessions list
      const user = await this.getUserById(session.user_id);
      if (user) {
        const updatedActiveSessions = (user.active_sessions || []).filter(
          (id) => id !== sessionId
        );
        await storage.users.update(session.user_id, {
          active_sessions: updatedActiveSessions,
        });
      }

      logger.info('Session revoked successfully', {
        sessionId,
        userId: session.user_id,
      });
    } catch (error) {
      logger.error('Error revoking session', error as Error, { sessionId });
      throw error;
    }
  } 

  static async isSessionValid(sessionId: string): Promise<boolean> {
    try {
      if (!sessionId || typeof sessionId !== 'string') {
        return false;
      }

      const session = await storage.sessions.findById(sessionId);
      if (!session) {
        return false;
      }

      const now = Date.now();

      // Check session status
      if (session.status !== 'active') {
        return false;
      }

      // Check expiration
      if (session.expires_at <= now) {
        // Mark as expired
        await storage.sessions.update(sessionId, { status: 'expired' });
        return false;
      }

      return true;
    } catch (error) {
      logger.error('Error validating session', error as Error, { sessionId });
      return false;
    }
  }

  
}
