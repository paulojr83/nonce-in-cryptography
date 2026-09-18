import { Session, UpdateOptions } from '../../types/entities';
import { persistCreate, persistUpdate } from '../persistence';

export interface ISessionRepository {
  create(session: Session): Promise<Session>;
  findById(id: string): Promise<Session | null>;
  update(id: string, updates: UpdateOptions): Promise<Session | null>;
  count(): Promise<number>;
}

export class SessionRepository implements ISessionRepository {
  private data: Map<string, Session> = new Map();

  async create(session: Session): Promise<Session> {
    this.data.set(session.id, session);

    persistCreate('sessions', session);

    return session;
  }

  async findById(id: string): Promise<Session | null> {
    return this.data.get(id) || null;
  }

  async update(id: string, updates: UpdateOptions): Promise<Session | null> {
    const session = this.data.get(id);
    if (!session) return null;

    const updated = { ...session, ...updates };
    this.data.set(id, updated);

    persistUpdate('sessions', id, updates);

    return updated;
  }

  async count(): Promise<number> {
    return this.data.size;
  }
}
