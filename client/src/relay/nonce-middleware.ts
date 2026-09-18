import type {
  CacheConfig,
  RequestParameters,
  UploadableMap,
  Variables,
} from 'relay-runtime';
import { postGraphQL, readSecret } from '../crypto/channel';

export const NONCE_ERROR_CODES = [
  'NONCE_MISSING',
  'NONCE_INVALID',
  'NONCE_EXPIRED',
  'NONCE_ALREADY_USED',
  'NONCE_BINDING_MISMATCH',
  'NONCE_RACE_CONDITION',
  'NONCE_MULTIPLE_OPERATIONS',
] as const;

export type NonceErrorCode = (typeof NONCE_ERROR_CODES)[number];

export const RETRYABLE_NONCE_ERRORS: readonly NonceErrorCode[] = [
  'NONCE_EXPIRED',
  'NONCE_RACE_CONDITION',
];

export interface GraphQLErrorLike {
  message?: string;
  extensions?: {
    code?: string;
    error_code?: string;
    /** Replacement nonce for a request whose nonce was consumed then failed */
    nonce?: string;
  } | null;
}

export interface GraphQLResponseLike {
  data?: Record<string, unknown> | null;
  errors?: GraphQLErrorLike[] | null;
  extensions?: Record<string, unknown> | null;
}

export interface NonceMiddlewareOptions {
  endpoint: string;
  getToken: () => string | null;
  getNonce: () => string | null;
  /** The secret agreed at sign-in. Without one, requests go in the clear. */
  getSecret?: () => Uint8Array | null;
  setNonce: (nonce: string | null) => void;
  onNonceError?: (code: NonceErrorCode, message: string) => void;
  refreshNonce?: () => Promise<string | null>;
  maxRetries?: number;
  debug?: boolean;
  fetchFn?: typeof fetch;
}

export function findNonceError(
  response: GraphQLResponseLike
): { code: NonceErrorCode; message: string } | null {
  for (const error of response.errors ?? []) {
    const code = error.extensions?.error_code ?? error.extensions?.code;

    if (code && (NONCE_ERROR_CODES as readonly string[]).includes(code)) {
      return { code: code as NonceErrorCode, message: error.message ?? 'Nonce error' };
    }

    // Yoga masks extensions in production, so the message is the only signal
    const message = error.message ?? '';
    const matched = NONCE_ERROR_CODES.find((known) => message.includes(known));
    if (matched) {
      return { code: matched, message };
    }
  }

  return null;
}

/**
 * Find the nonce the server rotated into this response.
 *
 * It arrives in one of three places: the response extensions, the mutation
 * payload on success, or - when the nonce was consumed by a request that then
 * failed on a business rule - the extensions of the error itself. Missing that
 * last one is what used to leave the client holding a spent nonce.
 */
export function extractNonce(response: GraphQLResponseLike): string | null {
  const fromExtensions = response.extensions?.nonce;
  if (typeof fromExtensions === 'string' && fromExtensions) {
    return fromExtensions;
  }

  for (const payload of Object.values(response.data ?? {})) {
    if (payload && typeof payload === 'object' && 'nonce' in payload) {
      const nonce = (payload as { nonce?: unknown }).nonce;
      if (typeof nonce === 'string' && nonce) {
        return nonce;
      }
    }
  }

  for (const error of response.errors ?? []) {
    const nonce = error.extensions?.nonce;
    if (typeof nonce === 'string' && nonce) {
      return nonce;
    }
  }

  return null;
}

export function createNonceFetch(options: NonceMiddlewareOptions) {
  const {
    endpoint,
    getToken,
    getNonce,
    getSecret = readSecret,
    setNonce,
    onNonceError,
    refreshNonce,
    maxRetries = 1,
    debug = false,
    fetchFn = fetch,
  } = options;

  const log = (message: string, detail?: unknown): void => {
    if (debug) {
      console.info(`[nonce] ${message}`, detail ?? '');
    }
  };

  async function send(
    params: RequestParameters,
    variables: Variables,
    attempt: number
  ): Promise<GraphQLResponseLike> {
    const isMutation = params.operationKind === 'mutation';
    const nonce = getNonce();
    const secret = getSecret();

    // The nonce keys the envelope, so it goes out with reads too - but only a
    // mutation ever consumes it, and that decision stays on the server.
    if (!nonce) {
      log(`sending ${params.name} without a nonce`, { attempt, isMutation });
    }

    const { json: body, wasSealed } = await postGraphQL({
      endpoint,
      payload: {
        query: params.text,
        variables,
        operationName: params.name,
      },
      token: getToken(),
      nonce,
      secret,
      fetchFn,
    });

    log(`sent ${params.name}`, { attempt, sealed: wasSealed });

    const json = body as GraphQLResponseLike;
    const rotated = extractNonce(json);
    if (rotated) {
      setNonce(rotated);
      log(`received a rotated nonce from ${params.name}`);
    }

    const nonceError = findNonceError(json);
    if (nonceError) {
      log(`${params.name} failed: ${nonceError.code}`);
      onNonceError?.(nonceError.code, nonceError.message);

      const canRetry =
        attempt < maxRetries &&
        RETRYABLE_NONCE_ERRORS.includes(nonceError.code) &&
        Boolean(refreshNonce);

      if (canRetry) {
        const fresh = await refreshNonce!();
        if (fresh) {
          setNonce(fresh);
          log(`retrying ${params.name} with a fresh nonce`, { attempt: attempt + 1 });
          return send(params, variables, attempt + 1);
        }
        log(`could not refresh the nonce; giving up on ${params.name}`);
      }
    }

    return json;
  }

  return function nonceFetch(
    params: RequestParameters,
    variables: Variables,
    _cacheConfig: CacheConfig,
    _uploadables?: UploadableMap | null
  ): Promise<GraphQLResponseLike> {
    return send(params, variables, 0);
  };
}
