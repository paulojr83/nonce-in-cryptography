import crypto from 'crypto';
import { NonceService } from '../services/nonce-service';
import { storage } from '../data/storage-layer';
import { logger } from '../utils/logger';
import type { GraphQLContext } from '../utils/types';
import { requireAuth } from '../middleware/auth-middleware';
import { ApplicationError, ErrorCode } from '../utils/errors';
import { getRequestInfo } from '../utils/request-info';
import { toGraphQLTodo } from './query-resolvers';
import { Todo } from '../types/entities';
 
interface MutationContext {
  userId: string;
  sessionId: string;
  nonceId: string;
}
 
function requireValidNonce(context: GraphQLContext, operation: string): MutationContext {
  const { user_id, session_id } = requireAuth(context);

  if (!context.nonce_valid) {
    const error = context.nonce_error;

    logger.warn('Protected mutation rejected: nonce not valid', {
      operation,
      userId: user_id,
      errorCode: error?.error_code,
    });

    throw new ApplicationError(
      (error?.error_code as ErrorCode) ?? ErrorCode.NONCE_INVALID,
      error?.error_message ?? 'CSRF token validation failed',
      403,
      error ? { suggested_action: error.suggested_action } : undefined
    );
  }
 
  if (!context.nonce_id) {
    logger.error(
      'Protected mutation reached resolver without a consumed nonce',
      undefined,
      { operation, userId: user_id }
    );

    throw new ApplicationError(
      ErrorCode.NONCE_MISSING,
      'CSRF token missing. Please refresh the page and try again.',
      403
    );
  }

  return { userId: user_id, sessionId: session_id, nonceId: context.nonce_id };
}
 
async function requireOwnedTodo(todoId: string, userId: string): Promise<Todo> {
  const todo = await storage.todos.findById(todoId);

  if (!todo || todo.user_id !== userId) {
    logger.warn('Todo not accessible for mutation', {
      todoId,
      userId,
      found: Boolean(todo),
    });
    throw new ApplicationError(ErrorCode.TODO_NOT_FOUND, 'Todo not found', 404);
  }

  return todo;
}
 
async function issueFreshNonce(
  context: GraphQLContext,
  userId: string,
  sessionId: string
): Promise<string> {
  const { ipAddress, userAgent } = getRequestInfo(context.request);
  return NonceService.generateNonce(userId, sessionId, ipAddress, userAgent);
}

/**
 * Run a protected mutation, making sure the caller ends up with a usable nonce
 * whichever way it goes.
 *
 * The nonce is consumed before this resolver runs - consuming it up front is
 * what makes the consumption atomic - so a failure here would otherwise leave
 * the client holding a spent token and no replacement, with nothing to do but
 * log in again. On success the fresh nonce travels in the payload; on failure
 * it travels in the error's extensions.
 */
async function rotateOnFailure<T>(
  context: GraphQLContext,
  userId: string,
  sessionId: string,
  run: () => Promise<T>
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof ApplicationError) {
      try {
        error.withExtension('nonce', await issueFreshNonce(context, userId, sessionId));
      } catch (issueError) {
        logger.error(
          'Could not issue a replacement nonce after a failed mutation',
          issueError as Error,
          { userId }
        );
      }
    }

    throw error;
  }
}
 
export const todoResolvers = {
  Mutation: {

    createTodo: async (
      _: unknown,
      {
        input,
      }: { input: { title: string; description?: string | null; nonce?: string | null } },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { userId, sessionId, nonceId } = requireValidNonce(context, 'createTodo');

      return rotateOnFailure(context, userId, sessionId, async () => {
        logger.debug('Resolving Mutation.createTodo', { userId, title: input?.title });

        const title = input?.title?.trim();
        if (!title) {
          throw new ApplicationError(
            ErrorCode.INVALID_CREDENTIALS,
            'Todo title is required',
            400
          );
        }

        const now = Date.now();
        const todo: Todo = {
          id: `todo_${crypto.randomUUID()}`,
          user_id: userId,
          title,
          description: input.description ?? null,
          completed: false,
          created_at: now,
          updated_at: now,
          created_by_nonce_id: nonceId,
        };

        const created = await storage.todos.create(todo);

        logger.info('Todo created', { userId, todoId: created.id });

        return {
          todo: toGraphQLTodo(created),
          nonce: await issueFreshNonce(context, userId, sessionId),
        };
      });
    },

    updateTodo: async (
      _: unknown,
      {
        id,
        input,
      }: {
        id: string;
        input: {
          title?: string | null;
          description?: string | null;
          completed?: boolean | null;
          nonce?: string | null;
        };
      },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { userId, sessionId } = requireValidNonce(context, 'updateTodo');

      return rotateOnFailure(context, userId, sessionId, async () => {
        logger.debug('Resolving Mutation.updateTodo', { userId, todoId: id });

        await requireOwnedTodo(id, userId);

        const updates: Partial<Todo> = {};

        if (typeof input?.title === 'string') {
          const title = input.title.trim();
          if (!title) {
            throw new ApplicationError(
              ErrorCode.INVALID_CREDENTIALS,
              'Todo title cannot be empty',
              400
            );
          }
          updates.title = title;
        }

        if (input?.description !== undefined && input.description !== null) {
          updates.description = input.description;
        }

        if (typeof input?.completed === 'boolean') {
          updates.completed = input.completed;
        }

        const updated = await storage.todos.update(id, updates);
        if (!updated) {
          throw new ApplicationError(ErrorCode.TODO_NOT_FOUND, 'Todo not found', 404);
        }

        logger.info('Todo updated', { userId, todoId: updated.id });

        return {
          todo: toGraphQLTodo(updated),
          nonce: await issueFreshNonce(context, userId, sessionId),
        };
      });
    },

    deleteTodo: async (
      _: unknown,
      { id }: { id: string; nonce?: string | null },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { userId, sessionId } = requireValidNonce(context, 'deleteTodo');

      return rotateOnFailure(context, userId, sessionId, async () => {
        logger.debug('Resolving Mutation.deleteTodo', { userId, todoId: id });

        const todo = await requireOwnedTodo(id, userId);

        const deleted = await storage.todos.delete(id);
        if (!deleted) {
          throw new ApplicationError(ErrorCode.TODO_NOT_FOUND, 'Todo not found', 404);
        }

        logger.info('Todo deleted', { userId, todoId: id });

        return {
          todo: toGraphQLTodo(todo),
          nonce: await issueFreshNonce(context, userId, sessionId),
        };
      });
    },
  },
};
