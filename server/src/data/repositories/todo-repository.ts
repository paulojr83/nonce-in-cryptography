import { Todo, QueryFilter, UpdateOptions } from '../../types/entities';
import { persistCreate, persistRemove, persistUpdate } from '../persistence';

export interface ITodoRepository {
  create(todo: Todo): Promise<Todo>;
  findById(id: string): Promise<Todo | null>;
  findByUserId(userId: string): Promise<Todo[]>;
  findAll(filter?: QueryFilter, limit?: number, offset?: number): Promise<Todo[]>;
  update(id: string, updates: UpdateOptions): Promise<Todo | null>;
  delete(id: string): Promise<boolean>;
  count(filter?: QueryFilter): Promise<number>;
}

export class TodoRepository implements ITodoRepository {
  private data: Map<string, Todo> = new Map();

  private userIdIndex: Map<string, Set<string>> = new Map();

  async create(todo: Todo): Promise<Todo> {
    this.data.set(todo.id, todo);

    if (!this.userIdIndex.has(todo.user_id)) {
      this.userIdIndex.set(todo.user_id, new Set());
    }
    this.userIdIndex.get(todo.user_id)!.add(todo.id);

    persistCreate('todos', todo);

    return todo;
  }

  async findById(id: string): Promise<Todo | null> {
    return this.data.get(id) || null;
  }

  async findByUserId(userId: string): Promise<Todo[]> {
    const ids = this.userIdIndex.get(userId);
    if (!ids) return [];

    return Array.from(ids)
      .map((id) => this.data.get(id))
      .filter((todo): todo is Todo => todo !== undefined);
  }

  async findAll(
    filter?: QueryFilter,
    limit?: number,
    offset: number = 0
  ): Promise<Todo[]> {
    let results = Array.from(this.data.values());

    if (filter) {
      results = results.filter((todo) => this.matches(todo, filter));
    }

    return limit ? results.slice(offset, offset + limit) : results.slice(offset);
  }

  async update(id: string, updates: UpdateOptions): Promise<Todo | null> {
    const todo = this.data.get(id);
    if (!todo) return null;

    const updated = { ...todo, ...updates, updated_at: Date.now() };
    this.data.set(id, updated);

    persistUpdate('todos', id, { ...updates, updated_at: updated.updated_at });

    return updated;
  }

  async delete(id: string): Promise<boolean> {
    const todo = this.data.get(id);
    if (!todo) return false;

    this.data.delete(id);

    const ids = this.userIdIndex.get(todo.user_id);
    if (ids) {
      ids.delete(id);
      if (ids.size === 0) this.userIdIndex.delete(todo.user_id);
    }

    persistRemove('todos', id);

    return true;
  }

  async count(filter?: QueryFilter): Promise<number> {
    if (!filter) return this.data.size;

    return Array.from(this.data.values()).filter((todo) => this.matches(todo, filter))
      .length;
  }

  private matches(todo: Todo, filter: QueryFilter): boolean {
    return Object.entries(filter).every(([key, value]) => {
      if (key === 'user_id') return todo.user_id === value;
      if (key === 'completed') return todo.completed === value;
      return true;
    });
  }
}
