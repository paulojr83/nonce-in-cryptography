import { createYoga, createSchema } from 'graphql-yoga';
import { createServer } from 'http';
import type { IncomingMessage } from 'http';
import { typeDefs } from './typedefs';
import { logger, LogLevel } from './utils/logger';
import type { GraphQLContext } from './utils/types';
import { authMiddleware } from './middleware/auth-middleware';
import {
  nonceValidationMiddleware,
  extractOperationInfo,
} from './middleware/nonce-validation-middleware';
import type {
  RequestLike,
  GraphQLParamsLike,
} from './middleware/nonce-validation-middleware';
import {
  decodeRequest,
  encodeResponse,
  TransportError,
} from './middleware/transport-middleware';
import { NonceCleanupJob } from './jobs/nonce-cleanup-job';
import { ALL_OPERATIONS, disabledOperations } from './utils/nonce-flags';
import { authResolvers } from './resolvers/auth-resolvers';
import { queryResolvers } from './resolvers/query-resolvers';
import { todoResolvers } from './resolvers/todo-resolvers';
import { bootstrapStorage, shutdownStorage } from './data/bootstrap';
import { getEnv } from './utils/env';

const env = getEnv();

logger.setLevel(env.logLevel.toUpperCase() as LogLevel);

const PORT = env.port;
const NODE_ENV = env.nodeEnv;

const resolvers = {
  Query: {
    ...queryResolvers.Query,
  },
  User: {
    ...queryResolvers.User,
  },
  Mutation: {
    ...authResolvers.Mutation,
    ...todoResolvers.Mutation,
  },
};

const schema = createSchema({
  typeDefs,
  resolvers,
});

const yoga = createYoga({
  schema,
  context: async ({
    request,
    params,
  }: {
    request: RequestLike;
    params: GraphQLParamsLike;
  }): Promise<GraphQLContext> => {
    const authContext = await authMiddleware(request);

    const operation = extractOperationInfo(params);

    const nonceContext = await nonceValidationMiddleware(
      request,
      operation,
      params?.variables ?? undefined,
      authContext
    );

    // Combine contexts
    const context: GraphQLContext = {
      ...authContext,
      ...nonceContext,
      request,
    };

    logger.debug('GraphQL context created', {
      authenticated: context.authenticated,
      userId: context.user_id,
      operation: operation.operationName,
      operationType: operation.operationType,
      nonceValid: context.nonce_valid,
    });

    return context;
  },
  maskedErrors: NODE_ENV === 'production',
});

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

function copyHeaders(source: IncomingMessage): Headers {
  const headers = new Headers();

  for (const [name, value] of Object.entries(source.headers)) {
    if (typeof value === 'string') {
      headers.set(name, value);
    } else if (Array.isArray(value)) {
      headers.set(name, value.join(', '));
    }
  }

  headers.delete('content-length');

  return headers;
}

const server = createServer((request, response) => {
  if (request.method !== 'POST') {
    void yoga(request, response);
    return;
  }

  void (async () => {
    try {
      const rawBody = await readBody(request);

      let decoded;
      try {
        decoded = await decodeRequest(rawBody);
      } catch (error) {
        if (error instanceof TransportError) {
          response.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
          response.end(
            JSON.stringify({
              errors: [
                {
                  message: error.message,
                  extensions: { error_code: 'TRANSPORT_UNREADABLE' },
                },
              ],
            })
          );
          return;
        }
        throw error;
      }

      const headers = copyHeaders(request);
      if (decoded.nonce) {
        // Lifted out of the envelope: the nonce middleware reads it from here
        headers.set('x-nonce', decoded.nonce);
      }

      const url = new URL(request.url ?? '/graphql', `http://localhost:${PORT}`);
      const inner = new Request(url, {
        method: 'POST',
        headers,
        body: decoded.body,
      });

      const result = await yoga.fetch(inner);
      const text = await result.text();
      const payload = decoded.sealWith ? encodeResponse(text, decoded.sealWith) : text;

      const outgoing: Record<string, string> = {};
      result.headers.forEach((value, name) => {
        if (name.toLowerCase() !== 'content-length') {
          outgoing[name] = value;
        }
      });

      response.writeHead(result.status, outgoing);
      response.end(payload);
    } catch (error) {
      logger.error('Request failed before reaching GraphQL', error as Error);
      response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ errors: [{ message: 'Internal server error' }] }));
    }
  })();
});

server.on('error', (error) => {
  logger.error('Server error', error);
});

server.on('clientError', (error) => {
  logger.warn('Client error', { message: error.message });
});

server.listen(PORT, async () => {
  try {
    await bootstrapStorage();
  } catch (error) {
    logger.error('Storage bootstrap failed', error as Error);
  }

  logger.info('Yoga GraphQL server started', {
    port: PORT,
    environment: NODE_ENV,
    graphqlEndpoint: `http://localhost:${PORT}/graphql`,
  });

  const exempt = disabledOperations();
  if (exempt.length > 0) {
    logger.warn(
      'Nonce enforcement is switched off - replay and CSRF protection are not active there',
      exempt.includes(ALL_OPERATIONS)
        ? { operations: 'every operation' }
        : { operations: exempt }
    );
  }

  // Expired nonces are deleted periodically so the table cannot grow forever
  NonceCleanupJob.initialize({
    environment: NODE_ENV === 'production' ? 'production' : 'development',
    runOnStartup: NODE_ENV === 'development',
  });
});

/**
 * Graceful shutdown
 */
process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  NonceCleanupJob.stop();
  server.close(() => {
    // Drain queued writes so the last operations reach db.json
    void shutdownStorage().finally(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
  });
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  NonceCleanupJob.stop();
  server.close(() => {
    // Drain queued writes so the last operations reach db.json
    void shutdownStorage().finally(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
  });
});


process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection at:', new Error(String(reason)));
  process.exit(1);
});

export { server };
