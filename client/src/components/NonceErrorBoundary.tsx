import React from 'react';
import { MAX_NONCE_RETRIES } from '../contexts/NonceContext';
import { useNonce } from '../hooks/useNonce';
import { NONCE_ERROR_CODES, type NonceErrorCode } from '../relay/nonce-middleware';

interface Recovery {
  title: string;
  message: string;
  canRetry: boolean;
}

export const RECOVERY_BY_CODE: Record<NonceErrorCode, Recovery> = {
  NONCE_MISSING: {
    title: 'Security token missing',
    message: 'Refresh the page to get a new security token, then try again.',
    canRetry: true,
  },
  NONCE_INVALID: {
    title: 'Security token not recognised',
    message: 'Refresh the page to get a new security token, then try again.',
    canRetry: true,
  },
  NONCE_EXPIRED: {
    title: 'Security token expired',
    message: 'Your security token timed out. Get a fresh one and try again.',
    canRetry: true,
  },
  NONCE_ALREADY_USED: {
    title: 'Already processed',
    message: 'This request was already completed. Reload to see the current state.',
    canRetry: false,
  },
  NONCE_BINDING_MISMATCH: {
    title: 'Session mismatch',
    message: 'This token belongs to a different session. Please log in again.',
    canRetry: false,
  },
  NONCE_RACE_CONDITION: {
    title: 'Request already in progress',
    message: 'Another copy of this request got there first. Try again.',
    canRetry: true,
  },
  NONCE_MULTIPLE_OPERATIONS: {
    title: 'Too many operations in one request',
    message:
      'Each protected operation needs its own security token. Send them one at a time.',
    canRetry: false,
  },
};

export function classifyNonceError(message: string): NonceErrorCode | null {
  return NONCE_ERROR_CODES.find((code) => message.includes(code)) ?? null;
}

export interface NonceErrorNoticeProps {
  onRequireLogin?: () => void;
}

export const NonceErrorNotice: React.FC<NonceErrorNoticeProps> = ({ onRequireLogin }) => {
  const { error, errorCount, hasExhaustedRetries, isLoading, refreshNonce } = useNonce();

  if (!error) {
    return null;
  }

  if (hasExhaustedRetries) {
    return (
      <div className="nonce-error nonce-error--fatal" role="alert">
        <h3>Please log in again</h3>
        <p>
          We could not refresh your security token after {MAX_NONCE_RETRIES} attempts.
        </p>
        <button type="button" onClick={onRequireLogin}>
          Go to sign in
        </button>
      </div>
    );
  }

  const code = classifyNonceError(error);
  const recovery = code ? RECOVERY_BY_CODE[code] : null;

  return (
    <div className="nonce-error" role="alert">
      <h3>{recovery?.title ?? 'Something went wrong'}</h3>
      <p>{recovery?.message ?? error}</p>

      {(recovery?.canRetry ?? true) && (
        <button type="button" onClick={() => void refreshNonce()} disabled={isLoading}>
          {isLoading ? 'Refreshing...' : 'Get a new token'}
        </button>
      )}

      {errorCount > 1 && (
        <p className="nonce-error__count">
          Attempt {errorCount} of {MAX_NONCE_RETRIES}.
        </p>
      )}
    </div>
  );
};

interface BoundaryProps {
  children: React.ReactNode;
  fallback?: (error: Error, reset: () => void) => React.ReactNode;
}

interface BoundaryState {
  error: Error | null;
}

export class NonceErrorBoundary extends React.Component<BoundaryProps, BoundaryState> {
  constructor(props: BoundaryProps) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error };
  }

  componentDidCatch(error: Error): void {
    console.error('[nonce] render error caught by boundary', error.message);
  }

  reset = (): void => {
    this.setState({ error: null });
  };

  render(): React.ReactNode {
    const { error } = this.state;
    const { children, fallback } = this.props;

    if (!error) {
      return children;
    }

    if (fallback) {
      return fallback(error, this.reset);
    }

    const code = classifyNonceError(error.message);
    const recovery = code ? RECOVERY_BY_CODE[code] : null;

    return (
      <div className="nonce-error" role="alert">
        <h3>{recovery?.title ?? 'Something went wrong'}</h3>
        <p>{recovery?.message ?? 'Please reload the page and try again.'}</p>
        <button type="button" onClick={this.reset}>
          Try again
        </button>
      </div>
    );
  }
}

export default NonceErrorBoundary;
