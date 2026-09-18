import type { ErrorResponse, ErrorCode } from './errors';
import type { RequestLike } from './request-info';

export interface AuthError {
  code: ErrorCode;
  message: string;
  statusCode: number;
}

export interface AuthContext {
  user_id?: string;
  session_id?: string;
  authenticated: boolean;
  auth_error?: AuthError;
}


export interface NonceValidationContext {
  nonce_id?: string;
  nonce_valid: boolean;
  nonce_enforced: boolean;
  nonce_error?: ErrorResponse;
}

export interface GraphQLContext extends NonceValidationContext, AuthContext {
  request?: RequestLike;
}
