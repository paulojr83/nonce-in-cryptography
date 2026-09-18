import { AuthService } from '../services/auth-service';
import { storage } from '../data/storage-layer';
import { logger } from '../utils/logger';
import type { GraphQLContext } from '../utils/types';
import { requireAuth } from '../middleware/auth-middleware';
import { ApplicationError, ErrorCode } from '../utils/errors';
import { Todo } from '../types/entities';

const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 100;
export function toGraphQLTodo(todo: Todo): Record<string, unknown> {
  return {
    id: todo.id,
    userId: todo.user_id,
    title: todo.title,
    description: todo.description,
    completed: todo.completed,
    createdAt: new Date(todo.created_at).toISOString(),
    updatedAt: new Date(todo.updated_at).toISOString(),
  };
}

export function encodeCursor(todoId: string): string {
  return Buffer.from(`todo:${todoId}`, 'utf8').toString('base64');
}

export function decodeCursor(cursor: string): string | null {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf8');
    return decoded.startsWith('todo:') ? decoded.slice('todo:'.length) : null;
  } catch {
    return null;
  }
}

export async function buildTodoConnection(
  userId: string,
  first?: number | null,
  after?: string | null
): Promise<Record<string, unknown>> {
  const all = (await storage.todos.findByUserId(userId)).sort(
    (a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id)
  );

  const pageSize = Math.min(
    Math.max(typeof first === 'number' && first > 0 ? first : DEFAULT_PAGE_SIZE, 1),
    MAX_PAGE_SIZE
  );

  let startIndex = 0;
  if (after) {
    const afterId = decodeCursor(after);
    const afterIndex = afterId ? all.findIndex((todo) => todo.id === afterId) : -1;

    if (afterIndex === -1) {
      throw new ApplicationError(
        ErrorCode.NOT_AUTHORIZED,
        'Invalid pagination cursor',
        400
      );
    }

    startIndex = afterIndex + 1;
  }

  const page = all.slice(startIndex, startIndex + pageSize);

  const edges = page.map((todo) => ({
    node: toGraphQLTodo(todo),
    cursor: encodeCursor(todo.id),
  }));

  return {
    edges,
    pageInfo: {
      hasNextPage: startIndex + page.length < all.length,
      hasPreviousPage: startIndex > 0,
      startCursor: edges[0]?.cursor ?? null,
      endCursor: edges[edges.length - 1]?.cursor ?? null,
    },
    totalCount: all.length,
  };
}

export const queryResolvers = {
  Query: {
    me: async (_: unknown, __: unknown, context: GraphQLContext): Promise<unknown> => {
      const { user_id } = requireAuth(context);
      logger.debug('Resolving Query.me', { userId: user_id });

      const user = await AuthService.getUserById(user_id);
      if (!user) {
        throw new ApplicationError(ErrorCode.USER_NOT_FOUND, 'User not found', 404);
      }

      return {
        id: user.id,
        email: user.email,
        createdAt: new Date(user.created_at).toISOString(),
      };
    },

    todos: async (
      _: unknown,
      { first, after }: { first?: number | null; after?: string | null },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { user_id } = requireAuth(context);
      logger.debug('Resolving Query.todos', { userId: user_id, first, after });

      return buildTodoConnection(user_id, first, after);
    },

    getTodo: async (
      _: unknown,
      { id }: { id: string },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { user_id } = requireAuth(context);
      logger.debug('Resolving Query.getTodo', { userId: user_id, todoId: id });

      const todo = await storage.todos.findById(id);

      if (!todo || todo.user_id !== user_id) {
        logger.warn('Todo not accessible', {
          userId: user_id,
          todoId: id,
          found: Boolean(todo),
        });
        throw new ApplicationError(ErrorCode.TODO_NOT_FOUND, 'Todo not found', 404);
      }

      return toGraphQLTodo(todo);
    },
  },

  User: {
    todos: async (
      parent: { id: string },
      { first, after }: { first?: number | null; after?: string | null },
      context: GraphQLContext
    ): Promise<unknown> => {
      const { user_id } = requireAuth(context); 
      if (parent.id !== user_id) {
        throw new ApplicationError(
          ErrorCode.NOT_AUTHORIZED,
          'You do not have permission to view these todos',
          403
        );
      }

      return buildTodoConnection(user_id, first, after);
    },
  },
};
