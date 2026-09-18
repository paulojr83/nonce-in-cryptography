import crypto from 'crypto';
import { logger } from './logger';
import {
  ApplicationError,
  ErrorCode,
  ErrorResponse,
  NonceErrorClass,
} from './errors';
 
export const NONCE_ERROR_CODES = [
  ErrorCode.NONCE_MISSING,
  ErrorCode.NONCE_INVALID,
  ErrorCode.NONCE_EXPIRED,
  ErrorCode.NONCE_ALREADY_USED,
  ErrorCode.NONCE_BINDING_MISMATCH,
  ErrorCode.NONCE_RACE_CONDITION,
  ErrorCode.NONCE_MULTIPLE_OPERATIONS,
] as const;

export type NonceErrorCode = (typeof NONCE_ERROR_CODES)[number];
 
export const NONCE_ERROR_STATUS: Record<NonceErrorCode, 401 | 403 | 409> = {
  [ErrorCode.NONCE_MISSING]: 403,
  [ErrorCode.NONCE_INVALID]: 401,
  [ErrorCode.NONCE_EXPIRED]: 401,
  [ErrorCode.NONCE_ALREADY_USED]: 403,
  [ErrorCode.NONCE_BINDING_MISMATCH]: 403,
  [ErrorCode.NONCE_RACE_CONDITION]: 409,
  [ErrorCode.NONCE_MULTIPLE_OPERATIONS]: 403,
};
 
export const NONCE_ERROR_MESSAGES: Record<NonceErrorCode, string> = {
  [ErrorCode.NONCE_MISSING]:
    'CSRF token missing. Please refresh the page and try again.',
  [ErrorCode.NONCE_INVALID]:
    'Invalid security token. Please refresh the page and try again.',
  [ErrorCode.NONCE_EXPIRED]:
    'Your session has expired. Please refresh and try again.',
  [ErrorCode.NONCE_ALREADY_USED]:
    'This request has already been processed. Please try again with a new request.',
  [ErrorCode.NONCE_BINDING_MISMATCH]:
    'Session verification failed. Please log in again.',
  [ErrorCode.NONCE_RACE_CONDITION]:
    'This request was already processed. Please try again.',
  [ErrorCode.NONCE_MULTIPLE_OPERATIONS]:
    'A nonce authorises a single operation. Send one protected mutation per request.',
};
 
export function isNonceErrorCode(code: unknown): code is NonceErrorCode {
  return NONCE_ERROR_CODES.includes(code as NonceErrorCode);
}
 
export function getStatusCode(code: string | ErrorCode): number {
  return isNonceErrorCode(code) ? NONCE_ERROR_STATUS[code] : 400;
}
 
export function buildNonceError(
  code: string | ErrorCode,
  details?: Record<string, unknown>
): NonceErrorClass {
  if (!isNonceErrorCode(code)) {
    return new NonceErrorClass(
      ErrorCode.NONCE_INVALID,
      'A security validation error occurred. Please try again.',
      400,
      details
    );
  }

  return new NonceErrorClass(
    code,
    NONCE_ERROR_MESSAGES[code],
    NONCE_ERROR_STATUS[code],
    details
  );
}
 
export function formatErrorResponse(
  error: unknown,
  details?: Record<string, unknown>
): ErrorResponse { 
  if (error instanceof ApplicationError) {
    const response = error.toResponse();
    return details ? { ...response, details: { ...response.details, ...details } } : response;
  }
 
  if (typeof error === 'string' && isNonceErrorCode(error)) {
    return buildNonceError(error, details).toResponse();
  }
 
  const internal = new ApplicationError(
    ErrorCode.INTERNAL_SERVER_ERROR,
    'An unexpected error occurred. Please try again later.',
    500,
    details
  );

  return internal.toResponse();
}
 
export function hashNonce(nonce: string): string {
  return crypto.createHash('sha256').update(nonce).digest('hex');
}
 
export function logNonceError(
  code: string | ErrorCode,
  context: {
    nonce?: string;
    nonceId?: string;
    userId?: string;
    sessionId?: string;
    operation?: string;
    ipAddress?: string;
  } = {}
): void {
  const { nonce, ...rest } = context;

  logger.warn('Nonce validation failed', {
    ...rest,
    errorCode: code,
    statusCode: getStatusCode(code), 
    ...(nonce ? { nonceHash: hashNonce(nonce) } : {}),
  });
}
