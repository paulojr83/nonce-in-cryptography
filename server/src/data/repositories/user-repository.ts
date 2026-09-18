import { User, UpdateOptions } from '../../types/entities';
import { persistCreate, persistUpdate } from '../persistence';

export interface IUserRepository {
  create(user: User): Promise<User>;
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  update(id: string, updates: UpdateOptions): Promise<User | null>;
  count(): Promise<number>;
}

export class UserRepository implements IUserRepository {
  private data: Map<string, User> = new Map();

  private emailIndex: Map<string, string> = new Map();

  async create(user: User): Promise<User> {
    this.data.set(user.id, user);
    this.emailIndex.set(user.email, user.id);

    persistCreate('users', user);

    return user;
  }

  async findById(id: string): Promise<User | null> {
    return this.data.get(id) || null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const id = this.emailIndex.get(email);
    return id ? this.data.get(id) || null : null;
  }

  async update(id: string, updates: UpdateOptions): Promise<User | null> {
    const user = this.data.get(id);
    if (!user) return null;

    const updated = { ...user, ...updates };
    this.data.set(id, updated);

    if (updates.email && updates.email !== user.email) {
      this.emailIndex.delete(user.email);
      this.emailIndex.set(updates.email, id);
    }

    persistUpdate('users', id, updates);

    return updated;
  }

  async count(): Promise<number> {
    return this.data.size;
  }
}
