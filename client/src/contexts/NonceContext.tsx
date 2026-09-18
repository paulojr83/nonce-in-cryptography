import React, {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export const NONCE_STORAGE_KEY = 'nonce.current';

export const MAX_NONCE_RETRIES = 3;

export interface NonceContextType {
  currentNonce: string | null;
  isLoading: boolean;
  error: string | null;
  errorCount: number;
  hasExhaustedRetries: boolean;
  setNonce: (nonce: string | null) => void;
  refreshNonce: () => Promise<string | null>;
  reportError: (message: string) => void;
  clearNonce: () => void;
}

export const NonceContext = createContext<NonceContextType | undefined>(undefined);

function readStoredNonce(): string | null {
  try {
    return window.sessionStorage.getItem(NONCE_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredNonce(nonce: string | null): void {
  try {
    if (nonce) {
      window.sessionStorage.setItem(NONCE_STORAGE_KEY, nonce);
    } else {
      window.sessionStorage.removeItem(NONCE_STORAGE_KEY);
    }
  } catch {
    // A page that cannot persist still works for the life of the tab
  }
}

export interface NonceProviderProps {
  children: React.ReactNode;
  onRefresh?: () => Promise<string | null>;
  initialNonce?: string | null;
}

export const NonceProvider: React.FC<NonceProviderProps> = ({
  children,
  onRefresh,
  initialNonce,
}) => {
  const [currentNonce, setCurrentNonce] = useState<string | null>(
    () => initialNonce ?? readStoredNonce()
  );
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCount, setErrorCount] = useState(0);

  const nonceRef = useRef(currentNonce);

  useEffect(() => {
    nonceRef.current = currentNonce;
    writeStoredNonce(currentNonce);
  }, [currentNonce]);

  const setNonce = useCallback((nonce: string | null) => {
    nonceRef.current = nonce;
    writeStoredNonce(nonce);

    setCurrentNonce(nonce);
    if (nonce) {
      setError(null);
      setErrorCount(0);
    }
  }, []);

  const reportError = useCallback((message: string) => {
    setError(message);
    setErrorCount((count) => count + 1);
  }, []);

  const clearNonce = useCallback(() => {
    nonceRef.current = null;
    writeStoredNonce(null);

    setCurrentNonce(null);
    setError(null);
    setErrorCount(0);
  }, []);

  const refreshNonce = useCallback(async (): Promise<string | null> => {
    if (!onRefresh) {
      setError('No nonce available. Please log in again.');
      return null;
    }

    setIsLoading(true);
    try {
      const fresh = await onRefresh();
      if (fresh) {
        nonceRef.current = fresh;
        writeStoredNonce(fresh);
        setCurrentNonce(fresh);
        setError(null);
        setErrorCount(0);
      }
      return fresh;
    } catch (refreshError) {
      const message =
        refreshError instanceof Error ? refreshError.message : 'Failed to refresh token';
      setError(message);
      setErrorCount((count) => count + 1);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, [onRefresh]);

  const value = useMemo<NonceContextType>(
    () => ({
      currentNonce,
      isLoading,
      error,
      errorCount,
      hasExhaustedRetries: errorCount >= MAX_NONCE_RETRIES,
      setNonce,
      refreshNonce,
      reportError,
      clearNonce,
    }),
    [
      currentNonce,
      isLoading,
      error,
      errorCount,
      setNonce,
      refreshNonce,
      reportError,
      clearNonce,
    ]
  );

  return <NonceContext.Provider value={value}>{children}</NonceContext.Provider>;
};
