import React, { useCallback, useMemo, useRef, useState } from 'react';
import { RelayEnvironmentProvider } from 'react-relay';
import { NonceProvider } from './contexts/NonceContext';
import { AuthProvider } from './contexts/AuthContext';
import { useAuth } from './hooks/useAuth';
import { useNonce } from './hooks/useNonce';
import { createRelayEnvironment } from './relay/environment';
import { requestFreshNonce } from './relay/refresh-nonce';
import { getEnv } from './utils/env';
import LoginForm from './components/LoginForm';
import TodoList from './components/TodoList';
import CreateTodoForm from './components/CreateTodoForm';
import {
  NonceErrorBoundary,
  NonceErrorNotice,
} from './components/NonceErrorBoundary';
import { TOKEN_STORAGE_KEY } from './contexts/AuthContext';
import { NONCE_STORAGE_KEY } from './contexts/NonceContext';

function readStorage(key: string): string | null {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

/**
 * How the app gets a nonce back when it has none.
 *
 * Without this the provider's refreshNonce() could only ever return null, and
 * every recoverable nonce failure - an expired token, a lost race - would end
 * in a forced sign-in instead of a retry.
 */
const refreshNonceFromServer = (): Promise<string | null> =>
  requestFreshNonce({
    endpoint: getEnv().graphqlEndpoint,
    getToken: () => readStorage(TOKEN_STORAGE_KEY),
    getNonce: () => readStorage(NONCE_STORAGE_KEY),
  });

const TodoPage: React.FC = () => {
  const { user, logout } = useAuth();
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = useCallback(() => setRefreshKey((key) => key + 1), []);

  return (
    <div className="todo-page">
      <header className="todo-page__header">
        <div>
          <h1>Your todos</h1>
          <p>Signed in as {user?.email}</p>
        </div>
        <button type="button" onClick={() => void logout()}>
          Sign out
        </button>
      </header>

      <NonceErrorNotice onRequireLogin={() => void logout()} />

      <CreateTodoForm onCreated={refresh} />

      <NonceErrorBoundary>
        <TodoList refreshKey={refreshKey} onChanged={refresh} />
      </NonceErrorBoundary>
    </div>
  );
};

const AppRoutes: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const { error } = useNonce();

  if (!isAuthenticated) {
    return (
      <div className="app-shell app-shell--centered">
        <header>
          <h1>Nonce-Based Todo Application</h1>
          <p>Secure authentication with cryptographic nonces</p>
        </header>
        {error && <NonceErrorNotice />}
        <LoginForm />
      </div>
    );
  }

  return (
    <div className="app-shell">
      <TodoPage />
    </div>
  );
};

const RelayRoot: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const nonce = useNonce();
  const setNonceRef = useRef(nonce.setNonce);
  setNonceRef.current = nonce.setNonce;

  const reportErrorRef = useRef(nonce.reportError);
  reportErrorRef.current = nonce.reportError;

  const refreshNonceRef = useRef(nonce.refreshNonce);
  refreshNonceRef.current = nonce.refreshNonce;

  const environment = useMemo(
    () =>
      createRelayEnvironment({
        getToken: () => readStorage(TOKEN_STORAGE_KEY),
        getNonce: () => readStorage(NONCE_STORAGE_KEY),
        setNonce: (value) => setNonceRef.current(value),
        onNonceError: (code, message) => reportErrorRef.current(`${code}: ${message}`),
        refreshNonce: () => refreshNonceRef.current(),
        debug: import.meta.env.DEV,
      }),
    []
  );

  return (
    <RelayEnvironmentProvider environment={environment}>
      {children}
    </RelayEnvironmentProvider>
  );
};

const App: React.FC = () => (
  <NonceProvider onRefresh={refreshNonceFromServer}>
    <RelayRoot>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </RelayRoot>
  </NonceProvider>
);

export default App;
