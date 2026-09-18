/**
 * Yoga GraphQL Server Entry Point
 * 
 * Initializes and starts the GraphQL server with:
 * - Nonce validation middleware for CSRF protection
 * - Authentication middleware for JWT validation
 * - Error handling for graceful error responses
 * - Logger utility for structured logging
 * - Background cleanup job for nonce lifecycle management
 */

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
import { authResolvers } from './resolvers/auth-resolvers';
import { queryResolvers } from './resolvers/query-resolvers';
import { todoResolvers } from './resolvers/todo-resolvers';
import { bootstrapStorage, shutdownStorage } from './data/bootstrap';

// Set log level based on environment
const logLevel = (process.env.LOG_LEVEL as LogLevel) || LogLevel.INFO;
logger.setLevel(logLevel);

// Configuration
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000;
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * GraphQL Resolvers
 * Combines resolvers from different modules
 */
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

/**
 * Create GraphQL schema
 */
const schema = createSchema({
  typeDefs,
  resolvers,
});

/**
 * Create Yoga GraphQL server instance
 */
const yoga = createYoga({
  schema,
  context: async ({
    request,
    params,
  }: {
    request: RequestLike;
    params: GraphQLParamsLike;
  }): Promise<GraphQLContext> => {
    // Run authentication middleware
    const authContext = await authMiddleware(request);

    // Identify which GraphQL operation is being executed so the nonce
    // middleware can tell a protected mutation from a read-only query
    const operation = extractOperationInfo(params);

    // Run nonce validation middleware
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

/**
 * Read a request body in full. Yoga is handed a new request built from it, so
 * the original stream is consumed here and nowhere else.
 */
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

  // The body about to be sent is not the body that arrived
  headers.delete('content-length');

  return headers;
}

/**
 * HTTP server.
 *
 * Everything that is not a POST - GraphiQL, CORS preflight - goes straight to
 * Yoga. A POST passes through the transport layer first: a sealed body is
 * opened before GraphQL parses it, and the answer is sealed again on the way
 * out. A plain body is untouched.
 */
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

/**
 * Server lifecycle handlers
 */
server.on('error', (error) => {
  logger.error('Server error', error);
});

server.on('clientError', (error) => {
  logger.warn('Client error', { message: error.message });
});

/**
 * Start server
 */
server.listen(PORT, async () => {
  // Connect to json-server when it is available, hydrate the repositories and
  // seed a demo account if the database is empty
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

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection at:', new Error(String(reason)));
  process.exit(1);
});

export { server };
