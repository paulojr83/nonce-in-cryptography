/**
 * Custom error classes for application error handling
 */

export enum ErrorCode {
  // Nonce-related errors
  NONCE_MISSING = 'NONCE_MISSING',
  NONCE_INVALID = 'NONCE_INVALID',
  NONCE_EXPIRED = 'NONCE_EXPIRED',
  NONCE_ALREADY_USED = 'NONCE_ALREADY_USED',
  NONCE_BINDING_MISMATCH = 'NONCE_BINDING_MISMATCH',
  NONCE_RACE_CONDITION = 'NONCE_RACE_CONDITION',
  NONCE_MULTIPLE_OPERATIONS = 'NONCE_MULTIPLE_OPERATIONS',

  // Authentication errors
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  NOT_AUTHENTICATED = 'NOT_AUTHENTICATED',
  NOT_AUTHORIZED = 'NOT_AUTHORIZED',

  // User errors
  USER_NOT_FOUND = 'USER_NOT_FOUND',

  // Todo errors
  TODO_NOT_FOUND = 'TODO_NOT_FOUND',

  // Server errors
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
}

export interface NonceError {
  code: ErrorCode;
  message: string;
  statusCode: number;
  details?: Record<string, unknown>;
}

export interface ErrorResponse {
  error_code: ErrorCode;
  error_message: string;
  suggested_action: string;
  details?: Record<string, unknown>;
}

export class ApplicationError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;
 
  public readonly extensions: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, statusCode: number = 400, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.name = 'ApplicationError';

    const response = this.toResponse();
    this.extensions = {
      error_code: response.error_code,
      suggested_action: response.suggested_action,
      http: { status: statusCode },
    };
  }

  /**
   * Add a field to the extensions GraphQL sends back with this error.
   *
   * Used to hand a replacement nonce to a client whose nonce was consumed by a
   * request that then failed for an unrelated reason.
   */
  withExtension(key: string, value: unknown): this {
    this.extensions[key] = value;
    return this;
  }

  toResponse(): ErrorResponse {
    const suggestedActionMap: Record<ErrorCode, string> = {
      [ErrorCode.NONCE_MISSING]: 'Include a valid CSRF token in your request',
      [ErrorCode.NONCE_INVALID]: 'Refresh the page and try again',
      [ErrorCode.NONCE_EXPIRED]: 'Your session has expired. Please refresh and try again',
      [ErrorCode.NONCE_ALREADY_USED]: 'Try again with a new request',
      [ErrorCode.NONCE_BINDING_MISMATCH]: 'Please log in again',
      [ErrorCode.NONCE_RACE_CONDITION]: 'Try your request again',
      [ErrorCode.NONCE_MULTIPLE_OPERATIONS]:
        'Send one protected mutation per request, each with its own nonce',
      [ErrorCode.INVALID_CREDENTIALS]: 'Check your email and password and try again',
      [ErrorCode.INVALID_TOKEN]: 'Please log in again',
      [ErrorCode.TOKEN_EXPIRED]: 'Your session has expired. Please log in again',
      [ErrorCode.NOT_AUTHENTICATED]: 'Please log in to continue',
      [ErrorCode.NOT_AUTHORIZED]: 'You do not have permission to perform this action',
      [ErrorCode.USER_NOT_FOUND]: 'User not found',
      [ErrorCode.TODO_NOT_FOUND]: 'Todo item not found',
      [ErrorCode.INTERNAL_SERVER_ERROR]: 'Please try again later',
      [ErrorCode.DATABASE_ERROR]: 'Database error. Please try again later',
    };

    return {
      error_code: this.code,
      error_message: this.message,
      suggested_action: suggestedActionMap[this.code] || 'Please try again',
      details: this.details,
    };
  }
}

export class NonceErrorClass extends ApplicationError {
  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 401,
    details?: Record<string, unknown>
  ) {
    super(code, message, statusCode, details);
    this.name = 'NonceError';
  }
}

export class AuthenticationError extends ApplicationError {
  constructor(
    code: ErrorCode = ErrorCode.NOT_AUTHENTICATED,
    message: string = 'Not authenticated',
    statusCode: number = 401,
    details?: Record<string, unknown>
  ) {
    super(code, message, statusCode, details);
    this.name = 'AuthenticationError';
  }
}

export class RaceConditionError extends ApplicationError {
  constructor(message: string = 'Race condition detected', details?: Record<string, unknown>) {
    super(ErrorCode.NONCE_RACE_CONDITION, message, 409, details);
    this.name = 'RaceConditionError';
  }
}

export class NotFoundError extends ApplicationError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.INTERNAL_SERVER_ERROR,
    details?: Record<string, unknown>
  ) {
    super(code, message, 404, details);
    this.name = 'NotFoundError';
  }
}

