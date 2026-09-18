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

/**
 * Protected mutations that require nonce validation
 * State-changing operations must include and validate nonce
 */
const PROTECTED_MUTATIONS = [
  'createTodo',
  'updateTodo',
  'deleteTodo',
  'logout',
];

/**
 * Mutations that carry no nonce.
 *
 * `getNonce` and `login` have none to carry yet - they are how a client gets
 * its first one - and `refreshNonce` is how a client that lost its nonce gets
 * another. Requiring a nonce on any of them would be a deadlock. None of them
 * changes anything a replay could exploit: the login challenge is itself a
 * single-use nonce, which is what protects that exchange.
 */
const PUBLIC_MUTATIONS = [
  'getNonce',
  'login',
  'refreshNonce',
  'IntrospectionQuery',
];

/**
 * Does this root field need a nonce?
 *
 * Anything not explicitly public is protected, including mutations added later
 * and forgotten here: a new mutation is protected until someone says otherwise.
 */
function isProtectedField(field: string): boolean {
  return !PUBLIC_MUTATIONS.includes(field);
}

/**
 * Minimal shape the middleware needs from an incoming request.
 * Satisfied by the fetch `Request` used by Yoga and by a plain header map.
 */
export interface RequestLike {
  headers?: {
    get?: (name: string) => string | null | undefined;
  };
}

interface NonceValidationContext {
  nonce_valid: boolean;
  nonce_id?: string;
  nonce_error?: ErrorResponse;
}

/**
 * Extract the nonce from a request.
 *
 * Priority: X-NONCE header > X-CSRF-TOKEN header > `$nonce` variable >
 * `$input.nonce` variable. The header is what the web client uses; the
 * variables are there so the schema's optional `nonce` argument is honoured
 * for callers that would rather send it in the body.
 */
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

/**
 * Which root fields of this operation need a nonce.
 *
 * Queries are read-only and never consume one. For mutations the decision is
 * made per root field, because a single request can select several.
 */
function protectedFieldsOf(operation: OperationInfo): string[] {
  if (operation.operationType !== 'mutation') {
    logger.debug('Not a mutation - nonce validation skipped', {
      operationType: operation.operationType,
    });
    return [];
  }

  const fields = operation.rootFields.filter(isProtectedField);

  for (const field of fields) {
    if (!PROTECTED_MUTATIONS.includes(field)) {
      logger.warn('Unknown mutation - treating as protected', { field });
    }
  }

  return fields;
}

/**
 * GraphQL request parameters as delivered by Yoga's context factory
 */
export interface GraphQLParamsLike {
  query?: string;
  operationName?: string | null;
  variables?: Record<string, unknown> | null;
}

/**
 * Operation details the middleware needs in order to decide on protection
 */
export interface OperationInfo {
  operationType: 'query' | 'mutation' | 'subscription' | undefined;
  /** Root field name used for the protection decision */
  operationName: string | undefined;
  /** Every root field selected by the operation */
  rootFields: string[];
}

/**
 * Determine the operation type and root field names of a GraphQL request
 *
 * The protection decision is made on the root *field* (createTodo), not on the
 * client-chosen operation name (CreateTodoMutation) - otherwise a client could
 * bypass validation simply by naming its operation something unrecognised.
 *
 * When several root fields are selected, a protected one wins so a protected
 * mutation cannot be smuggled in alongside an unprotected one.
 */
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
      operation.operation === 'mutation' ? rootFields.find(isProtectedField) : undefined;

    return {
      operationType: operation.operation,
      operationName: protectedField ?? rootFields[0],
      rootFields,
    };
  } catch (error) {
    // Malformed query: Yoga rejects it during parsing, so there is nothing to
    // protect. Report no operation rather than guessing.
    logger.debug('Could not parse GraphQL operation for nonce validation', {
      reason: (error as Error).message,
    });
    return empty;
  }
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
 * 1. Determine if operation requires nonce validation
 * 2. Extract nonce from request
 * 3. Validate nonce status (exists, not used, not expired, user binding)
 * 4. On validation failure: attach the error and its recovery action to context
 * 5. On validation success: consume nonce, attach nonce_id to context
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

  try {
    const protectedFields = protectedFieldsOf(operation);

    if (protectedFields.length === 0) {
      logger.debug('Non-protected operation - bypassing nonce validation');
      return { nonce_valid: true };
    }

    // One nonce authorises one state change. GraphQL happily executes every
    // root field in a request, so without this a single nonce would cover
    // `a: createTodo ... b: createTodo ...` and the "used once" guarantee
    // would hold per request rather than per operation.
    if (protectedFields.length > 1) {
      logNonceError(ErrorCode.NONCE_MULTIPLE_OPERATIONS, {
        operation: operationName,
        ipAddress,
      });

      return {
        nonce_valid: false,
        nonce_error: buildNonceError(ErrorCode.NONCE_MULTIPLE_OPERATIONS, {
          operation: operationName,
          fields: protectedFields,
        }).toResponse(),
      };
    }

    if (!authContext?.user_id || !authContext.session_id) {
      logNonceError(ErrorCode.NONCE_BINDING_MISMATCH, {
        operation: operationName,
        ipAddress,
      });


      return {
        nonce_valid: false,
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
        nonce_error: buildNonceError(errorCode, {
          operation: operationName,
        }).toResponse(),
      };
    }

    const nonceId = validationResult.nonceId;
    if (!nonceId) {
      throw new Error('Nonce ID is missing from validation result');
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
      nonce_id: nonceId,
    };
  } catch (error) {
    logger.error('Unexpected error in nonce validation middleware', error as Error);

    return {
      nonce_valid: false,
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
