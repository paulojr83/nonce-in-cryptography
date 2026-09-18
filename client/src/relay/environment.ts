import { Environment, Network, RecordSource, Store } from 'relay-runtime';
import type { FetchFunction } from 'relay-runtime';
import { createNonceFetch, type NonceMiddlewareOptions } from './nonce-middleware';
import { getEnv } from '../utils/env';

export type RelayEnvironmentOptions = Omit<NonceMiddlewareOptions, 'endpoint'> & {
  endpoint?: string;
};

export function createRelayEnvironment(options: RelayEnvironmentOptions): Environment {
  const endpoint = options.endpoint ?? getEnv().graphqlEndpoint;

  const fetchFn = createNonceFetch({ ...options, endpoint }) as unknown as FetchFunction;

  return new Environment({
    network: Network.create(fetchFn),
    store: new Store(new RecordSource()),
    isServer: false,
  });
}

export default createRelayEnvironment;
