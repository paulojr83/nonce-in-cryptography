import { useCallback, useContext } from 'react';
import { useRelayEnvironment } from 'react-relay';
import { commitMutation } from 'relay-runtime';
import type { MutationParameters, Variables } from 'relay-runtime';
import { AuthContext, type AuthContextType, type AuthUser } from '../contexts/AuthContext';
import { useNonce } from './useNonce';
import { signIn } from '../crypto/login-handshake';
import { clearSecret } from '../crypto/channel';
import { getEnv } from '../utils/env';
import LogoutMutation from '../graphql/mutations/LogoutMutation';

export interface UseAuthResult extends AuthContextType {
  login: (email: string, password: string) => Promise<AuthUser>;
  logout: () => Promise<void>;
}

type AnyMutation = MutationParameters & {
  variables: Variables;
  response: Record<string, unknown>;
};

export function useAuth(): UseAuthResult {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error(
      'useAuth must be used inside an <AuthProvider>. Wrap your app in AuthProvider.'
    );
  }

  const environment = useRelayEnvironment();
  const { setNonce, clearNonce } = useNonce();
  const { setSession, clearSession, setLoading, setError } = context;

  /**
   * Sign in is the one exchange that does not go through Relay.
   *
   * It is two round trips - challenge, then digest - that establish the token,
   * the first nonce and the secret the Relay network layer reads on every later
   * request. It cannot run through the layer it is setting up.
   */
  const login = useCallback(
    async (email: string, password: string): Promise<AuthUser> => {
      setLoading(true);
      setError(null);

      try {
        const result = await signIn(getEnv().graphqlEndpoint, email, password);

        setNonce(result.nonce);
        setSession(result.user, result.token);

        return result.user;
      } catch (loginError) {
        const message =
          loginError instanceof Error ? loginError.message : 'Sign in failed';
        setError(message);
        throw loginError instanceof Error ? loginError : new Error(message);
      } finally {
        setLoading(false);
      }
    },
    [setError, setLoading, setNonce, setSession]
  );

  const logout = useCallback((): Promise<void> => {
    setLoading(true);

    return new Promise<void>((resolve) => {
      const finish = (): void => {
        clearNonce();
        clearSession();
        clearSecret();
        setLoading(false);
        resolve();
      };

      commitMutation<AnyMutation>(environment, {
        mutation: LogoutMutation,
        variables: {},
        onCompleted: finish,
        onError: finish,
      });
    });
  }, [environment, clearNonce, clearSession, setLoading]);

  return { ...context, login, logout };
}

export default useAuth;
