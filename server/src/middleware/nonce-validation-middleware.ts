import { parse, Kind } from 'graphql';
import type { FieldNode, OperationDefinitionNode } from 'graphql';
import { NonceService } from '../services/nonce-service';
import { logger } from '../utils/logger';
import { ApplicationError, ErrorCode, ErrorResponse } from '../utils/errors';
import {
  buildNonceError,
  formatErrorResponse,
  logNonceError,
} from '../utils/error-formatter';
import { getHeader, getIpAddress, getUserAgent } from '../utils/request-info';
import {
  isNonceEnforcedFor,
  PROTECTED_MUTATIONS,
  PROTECTED_QUERIES,
} from '../utils/nonce-flags';

const PUBLIC_MUTATIONS = [
  'getNonce',
  'login',
  'refreshNonce',
  'IntrospectionQuery',
];

const PUBLIC_QUERIES = [
  '__schema',
  '__type',
  '__typename',
  'IntrospectionQuery',
];

function isProtectedField(field: string): boolean {
  return !PUBLIC_MUTATIONS.includes(field);
}

function isProtectedQueryField(field: string): boolean {
  return !PUBLIC_QUERIES.includes(field);
}

export interface RequestLike {
  headers?: {
    get?: (name: string) => string | null | undefined;
  };
}

interface NonceValidationContext {
  nonce_valid: boolean;
  nonce_enforced: boolean;
  nonce_id?: string;
  nonce_error?: ErrorResponse;
}

function extractNonce(
  request: RequestLike | undefined,
  variables?: Record<string, unknown>
): string | null {
  const headerNonce =
    getHeader(request, 'X-NONCE') || getHeader(request, 'X-CSRF-TOKEN');
  if (headerNonce) {
    logger.debug('Nonce extracted from headers');
    return headerNonce;
  }

  if (typeof variables?.nonce === 'string' && variables.nonce) {
    logger.debug('Nonce extracted from the $nonce variable');
    return variables.nonce;
  }

  const input = variables?.input;
  if (input && typeof input === 'object') {
    const inputNonce = (input as { nonce?: unknown }).nonce;
    if (typeof inputNonce === 'string' && inputNonce) {
      logger.debug('Nonce extracted from the $input.nonce variable');
      return inputNonce;
    }
  }

  logger.debug('No nonce found in request');
  return null;
}

function protectedFieldsOf(operation: OperationInfo): string[] {
  if (operation.operationType === 'mutation') {
    const fields = operation.rootFields.filter(isProtectedField);

    for (const field of fields) {
      if (!PROTECTED_MUTATIONS.includes(field)) {
        logger.warn('Unknown mutation - treating as protected', { field });
      }
    }

    return fields;
  }

  if (operation.operationType === 'query') {
    const fields = operation.rootFields.filter(isProtectedQueryField);

    for (const field of fields) {
      if (!PROTECTED_QUERIES.includes(field)) {
        logger.warn('Unknown query - treating as protected', { field });
      }
    }

    return fields;
  }

  logger.debug('Neither a query nor a mutation - nonce validation skipped', {
    operationType: operation.operationType,
  });
  return [];
}

/**
 * GraphQL request parameters as delivered by Yoga's context factory
 */
export interface GraphQLParamsLike {
  query?: string;
  operationName?: string | null;
  variables?: Record<string, unknown> | null;
}

export interface OperationInfo {
  operationType: 'query' | 'mutation' | 'subscription' | undefined;
  operationName: string | undefined;
  rootFields: string[];
}

export function extractOperationInfo(params: GraphQLParamsLike | undefined): OperationInfo {
  const empty: OperationInfo = {
    operationType: undefined,
    operationName: undefined,
    rootFields: [],
  };

  if (!params?.query) {
    return empty;
  }

  try {
    const document = parse(params.query);

    const operations = document.definitions.filter(
      (definition): definition is OperationDefinitionNode =>
        definition.kind === Kind.OPERATION_DEFINITION
    );

    // Pick the operation the client asked to run, or the only one present
    const operation = params.operationName
      ? operations.find((op) => op.name?.value === params.operationName)
      : operations[0];

    if (!operation) {
      return empty;
    }

    const rootFields = operation.selectionSet.selections
      .filter((selection): selection is FieldNode => selection.kind === Kind.FIELD)
      .map((selection) => selection.name.value);

    // A protected root field takes precedence over any other
    const protectedField =
      operation.operation === 'mutation'
        ? rootFields.find(isProtectedField)
        : operation.operation === 'query'
          ? rootFields.find(isProtectedQueryField)
          : undefined;

    return {
      operationType: operation.operation,
      operationName: protectedField ?? rootFields[0],
      rootFields,
    };
  } catch (error) {
    logger.debug('Could not parse GraphQL operation for nonce validation', {
      reason: (error as Error).message,
    });
    return empty;
  }
}

export function assertNonceValid(
  context: { nonce_valid: boolean; nonce_error?: ErrorResponse },
  operation: string
): void {
  if (context.nonce_valid) {
    return;
  }

  const error = context.nonce_error;

  logger.warn('Protected operation rejected: nonce not valid', {
    operation,
    errorCode: error?.error_code,
  });

  throw new ApplicationError(
    (error?.error_code as ErrorCode) ?? ErrorCode.NONCE_INVALID,
    error?.error_message ?? 'CSRF token validation failed',
    403,
    error ? { suggested_action: error.suggested_action } : undefined
  );
}

/**
 * Authentication context consumed by this middleware
 */
interface AuthContextLike {
  user_id?: string;
  session_id?: string;
  authenticated?: boolean;
}

/**
 * Nonce Validation Middleware
 *
 * Execution flow:
 * 0. Skip entirely when the nonce switch for this operation is off
 * 1. Determine if operation requires nonce validation
 * 2. Extract nonce from request
 * 3. Validate nonce status (exists, not used, not expired, user binding)
 * 4. On validation failure: attach the error and its recovery action to context
 * 5. On validation success: consume the nonce for a mutation and attach
 *    nonce_id; a query leaves it unspent, so the same nonce serves the next
 *    read as well
 *
 * Error handling:
 * - NONCE_MISSING (403): User hasn't included a nonce
 * - NONCE_INVALID (401): Nonce doesn't exist or is malformed
 * - NONCE_EXPIRED (401): Nonce TTL has passed
 * - NONCE_ALREADY_USED (403): Nonce was already consumed
 * - NONCE_BINDING_MISMATCH (403): Nonce bound to a different user, session or client
 * - NONCE_RACE_CONDITION (409): Race condition - nonce consumed by concurrent request
 * - NONCE_MULTIPLE_OPERATIONS (403): One nonce offered for several mutations
 */
export async function nonceValidationMiddleware(
  request: RequestLike | undefined,
  operation: OperationInfo,
  variables?: Record<string, unknown>,
  authContext?: AuthContextLike
): Promise<NonceValidationContext> {
  const ipAddress = getIpAddress(request);
  const operationName = operation.operationName;
  const isMutation = operation.operationType === 'mutation';

  try {
    const protectedFields = protectedFieldsOf(operation);

    if (protectedFields.length === 0) {
      logger.debug('Non-protected operation - bypassing nonce validation');
      return { nonce_valid: true, nonce_enforced: false };
    }
    const enforcedFields = protectedFields.filter(isNonceEnforcedFor);

    if (enforcedFields.length === 0) {
      logger.debug('Nonce enforcement switched off - bypassing validation', {
        operation: operationName,
        fields: protectedFields,
      });
      return { nonce_valid: true, nonce_enforced: false };
    }

    if (isMutation && enforcedFields.length > 1) {
      logNonceError(ErrorCode.NONCE_MULTIPLE_OPERATIONS, {
        operation: operationName,
        ipAddress,
      });

      return {
        nonce_valid: false,
        nonce_enforced: true,
        nonce_error: buildNonceError(ErrorCode.NONCE_MULTIPLE_OPERATIONS, {
          operation: operationName,
          fields: enforcedFields,
        }).toResponse(),
      };
    }

    if (!authContext?.user_id || !authContext.session_id) {
      if (!isMutation) {
        logger.debug('Unauthenticated read - leaving the refusal to the resolver', {
          operation: operationName,
        });
        return { nonce_valid: true, nonce_enforced: false };
      }

      logNonceError(ErrorCode.NONCE_BINDING_MISMATCH, {
        operation: operationName,
        ipAddress,
      });


      return {
        nonce_valid: false,
        nonce_enforced: true,
        nonce_error: buildNonceError(ErrorCode.NONCE_BINDING_MISMATCH, {
          operation: operationName,
        }).toResponse(),
      };
    }

    const nonce = extractNonce(request, variables);

    if (!nonce) {
      logNonceError(ErrorCode.NONCE_MISSING, {
        userId: authContext.user_id,
        sessionId: authContext.session_id,
        operation: operationName,
        ipAddress,
      });


      return {
        nonce_valid: false,
        nonce_enforced: true,
        nonce_error: buildNonceError(ErrorCode.NONCE_MISSING, {
          operation: operationName,
        }).toResponse(),
      };
    }

    const validationResult = await NonceService.validateNonce(
      nonce,
      authContext.user_id,
      authContext.session_id,
      getUserAgent(request)
    );

    if (!validationResult.valid) {
      const errorCode = validationResult.error?.code || ErrorCode.NONCE_INVALID;
      logNonceError(errorCode, {
        nonce,
        userId: authContext.user_id,
        sessionId: authContext.session_id,
        operation: operationName,
        ipAddress,
      });


      return {
        nonce_valid: false,
        nonce_enforced: true,
        nonce_error: buildNonceError(errorCode, {
          operation: operationName,
        }).toResponse(),
      };
    }

    const nonceId = validationResult.nonceId;
    if (!nonceId) {
      throw new Error('Nonce ID is missing from validation result');
    }

    if (!isMutation) {
      logger.debug('Nonce accepted for a read, left unspent', {
        operationName,
        nonceId,
        userId: authContext.user_id,
      });

      return {
        nonce_valid: true,
        nonce_enforced: true,
      };
    }

    try {
      await NonceService.consumeNonce(nonceId);
    } catch (error) {
      // Race condition: nonce was consumed by a concurrent request between
      // validation and consumption. consumeNonce throws RaceConditionError.
      if (isRaceCondition(error)) {
        logNonceError(ErrorCode.NONCE_RACE_CONDITION, {
          nonce,
          nonceId,
          userId: authContext.user_id,
          sessionId: authContext.session_id,
          operation: operationName,
          ipAddress,
        });


        return {
          nonce_valid: false,
          nonce_enforced: true,
          nonce_error: buildNonceError(ErrorCode.NONCE_RACE_CONDITION, {
            operation: operationName,
          }).toResponse(),
        };
      }

      throw error;
    }

    logger.debug('Nonce consumed successfully', {
      operationName,
      nonceId,
      userId: authContext.user_id,
    });


    return {
      nonce_valid: true,
      nonce_enforced: true,
      nonce_id: nonceId,
    };
  } catch (error) {
    logger.error('Unexpected error in nonce validation middleware', error as Error);

    return {
      nonce_valid: false,
      nonce_enforced: true,
      nonce_error: formatErrorResponse(
        error instanceof ApplicationError
          ? error
          : new ApplicationError(
              ErrorCode.INTERNAL_SERVER_ERROR,
              'An unexpected error occurred. Please try again later.',
              500
            )
      ),
    };
  }
}


function isRaceCondition(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    error.name === 'RaceConditionError' ||
    /already consumed|does not exist/i.test(error.message)
  );
}
