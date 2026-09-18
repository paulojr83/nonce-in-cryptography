import { useCallback, useRef, useState } from 'react';
import { useRelayEnvironment } from 'react-relay';
import {
  commitMutation,
  type GraphQLTaggedNode,
  type MutationParameters,
  type Variables,
} from 'relay-runtime';

import { useNonce } from './useNonce';
import {
  RETRYABLE_NONCE_ERRORS,
  NONCE_ERROR_CODES,
  type NonceErrorCode,
} from '../relay/nonce-middleware';

type AnyMutation = MutationParameters & {
  variables: Variables;
  response: Record<string, unknown>;
};

export const MAX_MUTATION_RETRIES = 2;

export interface NonceMutationError extends Error {
  code?: NonceErrorCode;
}

export function toNonceErrorCode(message: string): NonceErrorCode | null {
  return NONCE_ERROR_CODES.find((code) => message.includes(code)) ?? null;
}

export function unwrapServerError(error: unknown): {
  message: string;
  code: NonceErrorCode | null;
} {
  const relayError = error as {
    message?: string;
    source?: { errors?: Array<{ message?: string; extensions?: { error_code?: string } }> };
  };

  const serverError = relayError?.source?.errors?.[0];

  if (serverError) {
    const extensionCode = serverError.extensions?.error_code;
    const code =
      extensionCode && (NONCE_ERROR_CODES as readonly string[]).includes(extensionCode)
        ? (extensionCode as NonceErrorCode)
        : toNonceErrorCode(serverError.message ?? '');

    return { message: serverError.message ?? 'Request failed', code };
  }

  const message = relayError?.message ?? 'Request failed';
  return { message, code: toNonceErrorCode(message) };
}

export type CommitFn<TResponse> = (
  variables: Variables
) => Promise<TResponse>;

export function useNonceMutation<TResponse = Record<string, unknown>>(
  mutation: GraphQLTaggedNode
): [CommitFn<TResponse>, boolean] {
  const environment = useRelayEnvironment();
  const { setNonce, refreshNonce } = useNonce();
  const [isInFlight, setIsInFlight] = useState(false);
  const retryCount = useRef(0);

  const runOnce = useCallback(
    (variables: Variables): Promise<TResponse> =>
      new Promise<TResponse>((resolve, reject) => {
        commitMutation<AnyMutation>(environment, {
          mutation,
          variables,
          onCompleted: (response: unknown, errors) => {
            const firstError = errors?.[0] as
              | { message: string; extensions?: { error_code?: string } }
              | undefined;

            if (firstError) {
              const { message, code } = unwrapServerError({
                source: { errors: [firstError] },
              });
              const error = new Error(message) as NonceMutationError;
              if (code) error.code = code;
              reject(error);
              return;
            }

            const payload = Object.values(
              (response as Record<string, unknown>) ?? {}
            )[0] as { nonce?: string } | undefined;

            if (payload?.nonce) {
              setNonce(payload.nonce);
            }

            resolve(response as TResponse);
          },
          onError: (error) => {
            const { message, code } = unwrapServerError(error);
            const wrapped = new Error(message) as NonceMutationError;
            if (code) wrapped.code = code;
            reject(wrapped);
          },
        });
      }),
    [environment, mutation, setNonce]
  );

  const commit = useCallback(
    async (variables: Variables): Promise<TResponse> => {
      setIsInFlight(true);
      retryCount.current = 0;

      try {
        for (;;) {
          try {
            return await runOnce(variables);
          } catch (error) {
            const { code } = error as NonceMutationError;

            const recoverable =
              code !== undefined && RETRYABLE_NONCE_ERRORS.includes(code);
            if (!recoverable || retryCount.current >= MAX_MUTATION_RETRIES) {
              throw error;
            }

            retryCount.current += 1;

            const fresh = await refreshNonce();
            if (!fresh) {
              throw error;
            }
          }
        }
      } finally {
        setIsInFlight(false);
        retryCount.current = 0;
      }
    },
    [runOnce, refreshNonce]
  );

  return [commit, isInFlight];
}

export default useNonceMutation;
