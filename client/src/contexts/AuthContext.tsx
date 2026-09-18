/**
 * AuthContext - session token and current user
 *
 * The JWT is kept in sessionStorage alongside the nonce so both are discarded
 * when the tab closes. It is deliberately not in localStorage: a token that
 * outlives the tab is a token that outlives the user's intent to stay signed in.
 *
 * Requirements: 5.0
 */

import React, {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

export const TOKEN_STORAGE_KEY = 'auth.token';
export const USER_STORAGE_KEY = 'auth.user';

export interface AuthUser {
  id: string;
  email: string;
  createdAt?: string;
}

export interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  /** Record a successful authentication */
  setSession: (user: AuthUser, token: string) => void;
  /** Forget the session locally */
  clearSession: () => void;
  setLoading: (loading: boolean) => void;
  setError: (message: string | null) => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

function readStored<T>(key: string, parse: boolean): T | null {
  try {
    const raw = window.sessionStorage.getItem(key);
    if (raw === null) return null;
    return (parse ? JSON.parse(raw) : raw) as T;
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string | null): void {
  try {
    if (value === null) {
      window.sessionStorage.removeItem(key);
    } else {
      window.sessionStorage.setItem(key, value);
    }
  } catch {
    // Storage is a convenience here; the session still works in memory
  }
}

export interface AuthProviderProps {
  children: React.ReactNode;
  initialToken?: string | null;
  initialUser?: AuthUser | null;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({
  children,
  initialToken,
  initialUser,
}) => {
  const [token, setToken] = useState<string | null>(
    () => initialToken ?? readStored<string>(TOKEN_STORAGE_KEY, false)
  );
  const [user, setUser] = useState<AuthUser | null>(
    () => initialUser ?? readStored<AuthUser>(USER_STORAGE_KEY, true)
  );
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    writeStored(TOKEN_STORAGE_KEY, token);
  }, [token]);

  useEffect(() => {
    writeStored(USER_STORAGE_KEY, user ? JSON.stringify(user) : null);
  }, [user]);

  const setSession = useCallback((nextUser: AuthUser, nextToken: string) => {
    // Written synchronously, not only in the effect above: the Relay network
    // layer reads the token straight from storage, and the first query after
    // sign-in renders before effects run. Deferring the write means that query
    // goes out unauthenticated.
    writeStored(TOKEN_STORAGE_KEY, nextToken);
    writeStored(USER_STORAGE_KEY, JSON.stringify(nextUser));

    setUser(nextUser);
    setToken(nextToken);
    setError(null);
  }, []);

  const clearSession = useCallback(() => {
    writeStored(TOKEN_STORAGE_KEY, null);
    writeStored(USER_STORAGE_KEY, null);

    setUser(null);
    setToken(null);
    setError(null);
  }, []);

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      token,
      isAuthenticated: Boolean(token && user),
      isLoading,
      error,
      setSession,
      clearSession,
      setLoading: setIsLoading,
      setError,
    }),
    [user, token, isLoading, error, setSession, clearSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
