import { logger } from '../utils/logger';

/** Collections mirrored into db.json */
export type CollectionName = 'users' | 'todos' | 'nonces' | 'sessions';

export interface JsonServerClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

export class JsonServerClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: JsonServerClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.fetchFn = options.fetchFn ?? fetch;
  }

  private async request(
    path: string,
    init: RequestInit = {}
  ): Promise<Response | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await this.fetchFn(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
      });
    } catch (error) {
      logger.debug('json-server request failed', {
        path,
        method: init.method ?? 'GET',
        reason: (error as Error).message,
      });
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async isReachable(): Promise<boolean> {
    const response = await this.request('/users', { method: 'GET' });
    return response !== null && response.ok;
  }

  async list<T>(collection: CollectionName): Promise<T[]> {
    const response = await this.request(`/${collection}`, { method: 'GET' });

    if (!response || !response.ok) {
      return [];
    }

    try {
      const body = (await response.json()) as T[];
      return Array.isArray(body) ? body : [];
    } catch {
      return [];
    }
  }

  async create<T extends { id: string }>(
    collection: CollectionName,
    record: T
  ): Promise<boolean> {
    const response = await this.request(`/${collection}`, {
      method: 'POST',
      body: JSON.stringify(record),
    });

    return response !== null && response.ok;
  }

  
  async update(
    collection: CollectionName,
    id: string,
    updates: Record<string, unknown>
  ): Promise<boolean> {
    const response = await this.request(`/${collection}/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });

    if (!response) {
      return false;
    }

    if (response.status === 404) {
      logger.debug('Skipped an update for a record that no longer exists', {
        collection,
        id,
      });
      return true;
    }

    return response.ok;
  }

  async remove(collection: CollectionName, id: string): Promise<boolean> {
    const response = await this.request(`/${collection}/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });

    if (!response) {
      return false;
    }

    return response.ok || response.status === 404;
  }
}
