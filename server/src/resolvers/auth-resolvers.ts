import { AuthService } from '../services/auth-service';
import { NonceService } from '../services/nonce-service';
import { logger } from '../utils/logger';
import type { GraphQLContext } from '../utils/types';
import { ApplicationError, ErrorCode } from '../utils/errors';
import { getRequestInfo } from '../utils/request-info';
import { requireAuth } from '../middleware/auth-middleware';
import { agreeOnSecret, hashNonce } from '../crypto/transport-cipher';

/**
 * Stands in for the account a challenge was requested for when there is none.
 * The challenge is issued anyway; it simply cannot be answered.
 */
const UNKNOWN_USER = 'user_unknown';

export const authResolvers = {
  Mutation: {
    
    /**
     * The challenge half of challenge-response login, and the key exchange.
     *
     * Public on purpose: a client with no credentials yet cannot authenticate
     * to ask for the thing it needs in order to authenticate. It answers for
     * unknown accounts exactly as it does for real ones, so the challenge
     * cannot be used to find out who has an account here.
     *
     * When the caller sends an ECDH public key, this completes the handshake
     * and keeps the agreed secret on the challenge itself - there is no session
     * to keep it on until the login it authorises succeeds.
     */
    getNonce: async (
      _: unknown,
      { username, clientPublicKey }: { username: string; clientPublicKey?: string | null },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { ipAddress, userAgent } = getRequestInfo(context.request);

      if (!username || typeof username !== 'string') {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'A username is required to request a challenge',
          400
        );
      }

      let serverPublicKey: string | null = null;
      let transportKey: string | null = null;

      if (clientPublicKey) {
        try {
          const agreed = agreeOnSecret(clientPublicKey);
          serverPublicKey = agreed.serverPublicKey;
          transportKey = agreed.sharedSecret.toString('hex');
        } catch (error) {
          logger.warn('Rejected a malformed client public key', {
            reason: (error as Error).message,
          });
          throw new ApplicationError(
            ErrorCode.INVALID_CREDENTIALS,
            'The public key could not be read',
            400
          );
        }
      }

      const user = await AuthService.findUserByEmail(username);

      const nonce = await NonceService.generateLoginChallenge(
        user?.id ?? UNKNOWN_USER,
        ipAddress,
        userAgent,
        transportKey
      );

      logger.debug('Login challenge issued', { handshake: Boolean(clientPublicKey) });

      return { nonce, serverPublicKey };
    },

    /**
     * The response half. The password is not a parameter and never travels:
     * what arrives is a digest over the challenge, the client's own cnonce and
     * the password, which the server recomputes from its stored verifier.
     *
     * The challenge is consumed before the digest is checked, right or wrong.
     * A challenge that survived a failed answer would be a challenge an
     * attacker could keep guessing against.
     */
    login: async (
      _: unknown,
      {
        username,
        nonce,
        cnonce,
        response,
      }: { username: string; nonce: string; cnonce: string; response: string },
      context: GraphQLContext
    ): Promise<unknown> => {
      logger.debug('Resolving Mutation.login');

      if (!username || !nonce || !cnonce || !response) {
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid email or password',
          401
        );
      }

      const user = await AuthService.findUserByEmail(username);
      const challenge = user ? await NonceService.findOpenChallenge(user.id) : null;

      // One failure for every way this can go wrong: unknown account, no
      // challenge, the wrong challenge, a bad digest. Anything more specific
      // would be an oracle.
      const refuse = (): never => {
        logger.warn('Login failed');
        throw new ApplicationError(
          ErrorCode.INVALID_CREDENTIALS,
          'Invalid email or password',
          401
        );
      };

      if (!user || !challenge || challenge.nonce_hash !== hashNonce(nonce)) {
        return refuse();
      }

      try {
        await NonceService.consumeNonce(challenge.id);
      } catch {
        return refuse();
      }

      if (!AuthService.verifyDigest(user, nonce, cnonce, response)) {
        return refuse();
      }

      const { session, token } = await AuthService.createSession(
        user.id,
        challenge.transport_key ?? null
      );

      const { ipAddress, userAgent } = getRequestInfo(context.request);
      const sessionNonce = await NonceService.generateNonce(
        user.id,
        session.id,
        ipAddress,
        userAgent
      );

      logger.info('Login successful', { userId: user.id, sessionId: session.id });

      return {
        user: {
          id: user.id,
          email: user.email,
          createdAt: new Date(user.created_at).toISOString(),
        },
        session: {
          id: session.id,
          userId: session.user_id,
          expiresAt: new Date(session.expires_at).toISOString(),
          status: session.status.toUpperCase(),
        },
        nonce: sessionNonce,
        token,
      };
    },

    /**
     * Hand the caller a fresh nonce for the session it is already authenticated
     * for.
     *
     * Deliberately not nonce-protected: a client asking for a nonce is, by
     * definition, a client without a usable one. Requiring one here would make
     * every spent or expired nonce a dead end ending in a forced re-login.
     * It is safe because it changes nothing and issues only to the
     * authenticated caller's own session.
     */
    refreshNonce: async (
      _: unknown,
      __: unknown,
      context: GraphQLContext
    ): Promise<unknown> => {
      const { user_id, session_id } = requireAuth(context);
      const { ipAddress, userAgent } = getRequestInfo(context.request);

      const nonce = await NonceService.generateNonce(
        user_id,
        session_id,
        ipAddress,
        userAgent
      );

      logger.info('Fresh nonce issued on request', {
        userId: user_id,
        sessionId: session_id,
      });

      return { nonce };
    },

    logout: async (
      _: unknown,
      __: unknown,
      context: GraphQLContext
    ): Promise<unknown> => {
      const startTime = Date.now();
      logger.debug('Resolving Mutation.logout', {
        userId: context.user_id,
        sessionId: context.session_id,
      });

      if (!context.authenticated || !context.user_id || !context.session_id) {
        logger.warn('Logout attempt without authentication', {
          authenticated: context.authenticated,
        });
        throw new ApplicationError(
          ErrorCode.NOT_AUTHENTICATED,
          'Not authenticated',
          401
        );
      }

      try {
        const userId = context.user_id;
        const sessionId = context.session_id;

        logger.debug('Revoking session', { sessionId });
        await AuthService.revokeSession(sessionId);
        logger.debug('Session revoked successfully', { sessionId });

        // Only this session's nonces. revokeSession already revoked them;
        // this call reports how many and keeps the intent explicit. Revoking
        // by user here would sign the account's other sessions out of their
        // nonces without signing them out.
        logger.debug('Revoking nonces for this session', { sessionId });
        const nonceCount = await NonceService.revokeSessionNonces(sessionId);
        logger.debug('Session nonces revoked', { sessionId, nonceCount });

        const duration = Date.now() - startTime;
        logger.info('Logout successful', {
          userId,
          sessionId,
          nonceCount,
          duration: `${duration}ms`,
        });

        return {
          success: true,
          message: 'Logged out successfully',
        };
      } catch (error) {
        logger.error('Error during logout', error as Error, {
          userId: context.user_id,
          sessionId: context.session_id,
        });
        throw new ApplicationError(
          ErrorCode.INTERNAL_SERVER_ERROR,
          'Logout failed',
          500
        );
      }
    },
  },
};
