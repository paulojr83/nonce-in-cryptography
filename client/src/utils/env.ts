/**
 * Client configuration
 *
 * Vite exposes variables prefixed with VITE_ on import.meta.env.
 */

interface EnvConfig {
  /** GraphQL endpoint the Relay network layer posts to */
  graphqlEndpoint: string;
}

const read = (key: string, fallback: string): string =>
  (import.meta.env as Record<string, string>)[`VITE_${key}`] || fallback;

let envConfig: EnvConfig | null = null;

export const getEnv = (): EnvConfig => {
  if (!envConfig) {
    envConfig = {
      graphqlEndpoint: read('GRAPHQL_ENDPOINT', 'http://localhost:4000/graphql'),
    };
  }
  return envConfig;
};

export default getEnv;
