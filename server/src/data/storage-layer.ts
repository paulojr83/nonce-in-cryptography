import { NonceRepository, INonceRepository } from './repositories/nonce-repository';
import { UserRepository, IUserRepository } from './repositories/user-repository';
import { SessionRepository, ISessionRepository } from './repositories/session-repository';
import { TodoRepository, ITodoRepository } from './repositories/todo-repository';

export class StorageLayer {
  private static instance: StorageLayer | null = null;

  public nonces: INonceRepository;
  public users: IUserRepository;
  public sessions: ISessionRepository;
  public todos: ITodoRepository;

  private constructor() {
    this.nonces = new NonceRepository();
    this.users = new UserRepository();
    this.sessions = new SessionRepository();
    this.todos = new TodoRepository();
  }

  static getInstance(): StorageLayer {
    if (!StorageLayer.instance) {
      StorageLayer.instance = new StorageLayer();
    }
    return StorageLayer.instance;
  }

  static reset(): void {
    const instance = StorageLayer.getInstance();
    instance.nonces = new NonceRepository();
    instance.users = new UserRepository();
    instance.sessions = new SessionRepository();
    instance.todos = new TodoRepository();
  }

}

export const storage = StorageLayer.getInstance();
export type { INonceRepository, IUserRepository, ISessionRepository, ITodoRepository };
