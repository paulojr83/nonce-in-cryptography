/**
 * Authentication Middleware for GraphQL
 * 
 * This middleware:
 * - Extracts JWT token from Authorization header (Bearer token)
 * - Verifies token signature using JWT_SECRET
 * - Checks token expiration
 * - Attaches user_id and session_id to GraphQL context
 * - Returns 401 errors for invalid/missing tokens
 * - Skips validation for public mutations (login)
 * 
 * Requirements: 5.0, 12.0
 */

import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';
import { AuthContext } from '../utils/types';
import { ErrorCode, AuthenticationError } from '../utils/errors';
import { getEnv } from '../utils/env';
import { AuthService } from '../services/auth-service';

interface JWTPayload {
  userId: string;
  sessionId: string;
  iat: number;
  exp: number;
}

export interface RequestLike {
  headers?: {
    get?: (name: string) => string | null | undefined;
  };
}

/**
 * Authentication middleware for GraphQL requests
 * Validates JWT token from Authorization header
 *
 * @param request - HTTP request object with headers
 * @returns AuthContext with authentication status and user information
 */
export async function authMiddleware(
  request: RequestLike | undefined
): Promise<AuthContext> {
  try {
    const authHeader = request?.headers?.get?.('Authorization');

    if (!authHeader) {
      logger.debug('No Authorization header provided');
      return {
        authenticated: false,
      };
    }

    if (!authHeader.startsWith('Bearer ')) {
      logger.warn('Invalid Authorization header format');
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.INVALID_TOKEN,
          message: 'Invalid token format. Expected "Bearer <token>"',
          statusCode: 401,
        },
      };
    }

    const token = authHeader.slice(7);

    if (!token) {
      logger.warn('Empty token in Authorization header');
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.INVALID_TOKEN,
          message: 'Token is empty',
          statusCode: 401,
        },
      };
    }

    const env = getEnv();
    if (!env.jwtSecret) {
      logger.error('JWT_SECRET not configured in environment');
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.INVALID_TOKEN,
          message: 'Server configuration error',
          statusCode: 500,
        },
      };
    }

    let decoded: JWTPayload;
    try {
      decoded = jwt.verify(token, env.jwtSecret) as JWTPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        logger.warn('JWT token expired', {
          expiredAt: error.expiredAt,
        });
        return {
          authenticated: false,
          auth_error: {
            code: ErrorCode.TOKEN_EXPIRED,
            message: 'Your session has expired. Please log in again',
            statusCode: 401,
          },
        };
      }

      if (error instanceof jwt.JsonWebTokenError) {
        logger.warn('JWT verification failed', {
          error: error.message,
        });
        return {
          authenticated: false,
          auth_error: {
            code: ErrorCode.INVALID_TOKEN,
            message: 'Invalid token signature',
            statusCode: 401,
          },
        };
      }

      // Generic JWT error
      logger.error('JWT verification error', error as Error);
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.INVALID_TOKEN,
          message: 'Token validation failed',
          statusCode: 401,
        },
      };
    }

    if (!decoded.userId || !decoded.sessionId) {
      logger.warn('JWT token missing required claims', {
        hasUserId: !!decoded.userId,
        hasSessionId: !!decoded.sessionId,
      });
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.INVALID_TOKEN,
          message: 'Invalid token claims',
          statusCode: 401,
        },
      };
    }

    if (decoded.exp && decoded.exp * 1000 < Date.now()) {
      logger.warn('JWT token timestamp validation failed', {
        expiresAt: new Date(decoded.exp * 1000),
        currentTime: new Date(),
      });
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.TOKEN_EXPIRED,
          message: 'Your session has expired. Please log in again',
          statusCode: 401,
        },
      };
    }

    const sessionValid = await AuthService.isSessionValid(decoded.sessionId);
    if (!sessionValid) {
      logger.warn('JWT token references an inactive session', {
        userId: decoded.userId,
        sessionId: decoded.sessionId,
      });
      return {
        authenticated: false,
        auth_error: {
          code: ErrorCode.TOKEN_EXPIRED,
          message: 'Your session is no longer active. Please log in again',
          statusCode: 401,
        },
      };
    }

    logger.debug('JWT token validated successfully', {
      userId: decoded.userId,
      sessionId: decoded.sessionId,
    });

    return {
      user_id: decoded.userId,
      session_id: decoded.sessionId,
      authenticated: true,
    };
  } catch (error) {
    logger.error('Unexpected error in auth middleware', error as Error);
    return {
      authenticated: false,
      auth_error: {
        code: ErrorCode.INVALID_TOKEN,
        message: 'Authentication failed',
        statusCode: 401,
      },
    };
  }
}

export function requireAuth(context: AuthContext): {
  user_id: string;
  session_id: string;
} {
  if (!context.authenticated || !context.user_id || !context.session_id) {
    const error = context.auth_error;

    throw new AuthenticationError(
      error?.code ?? ErrorCode.NOT_AUTHENTICATED,
      error?.message ?? 'Authentication required. Please log in to continue',
      error?.statusCode ?? 401
    );
  }

  return {
    user_id: context.user_id,
    session_id: context.session_id,
  };
}

