import { logger } from '../utils/logger';
import {
  JsonServerClient,
  type CollectionName,
} from './json-server-client';

type Operation =
  | { kind: 'create'; collection: CollectionName; id: string; record: { id: string } }
  | { kind: 'update'; collection: CollectionName; id: string; updates: Record<string, unknown> }
  | { kind: 'remove'; collection: CollectionName; id: string };


export class PersistenceSink {
  private static readonly MAX_RETRIES = 3;

  private static readonly RETRY_DELAY_MS = 120;

  private queue: Operation[] = [];
  private draining = false;

  private idleWaiters: Array<() => void> = [];

  constructor(private readonly client: JsonServerClient) {}

  private enqueue(operation: Operation): void {
    this.queue.push(operation);
    void this.drain();
  }

  recordCreate<T extends { id: string }>(collection: CollectionName, record: T): void {
    this.enqueue({ kind: 'create', collection, id: record.id, record });
  }

  recordUpdate(
    collection: CollectionName,
    id: string,
    updates: Record<string, unknown>
  ): void {
    this.enqueue({ kind: 'update', collection, id, updates });
  }

  recordRemove(collection: CollectionName, id: string): void {
    this.enqueue({ kind: 'remove', collection, id });
  }


  private async drain(): Promise<void> {
    if (this.draining) {
      return;
    }
    this.draining = true;

    try {
      while (this.queue.length > 0) {
        const operation = this.queue.shift() as Operation;

        try {
          const ok = await this.applyWithRetry(operation);
          if (!ok) {
            logger.warn('Could not mirror a change to json-server', {
              collection: operation.collection,
              operation: operation.kind,
            });
          }
        } catch (error) {
            logger.error('Error mirroring a change to json-server', error as Error, {
            collection: operation.collection,
            operation: operation.kind,
          });
        }
      }
    } finally {
      this.draining = false;

      const waiters = this.idleWaiters;
      this.idleWaiters = [];
      for (const resolve of waiters) {
        resolve();
      }
    }
  }

  private async applyWithRetry(operation: Operation): Promise<boolean> {
    for (let attempt = 0; attempt <= PersistenceSink.MAX_RETRIES; attempt++) {
      if (await this.apply(operation)) {
        return true;
      }

      if (attempt < PersistenceSink.MAX_RETRIES) {
        await new Promise((resolve) =>
          setTimeout(resolve, PersistenceSink.RETRY_DELAY_MS * (attempt + 1))
        );
      }
    }

    return false;
  }

  private apply(operation: Operation): Promise<boolean> {
    switch (operation.kind) {
      case 'create':
        return this.client.create(operation.collection, operation.record);
      case 'update':
        return this.client.update(operation.collection, operation.id, operation.updates);
      case 'remove':
        return this.client.remove(operation.collection, operation.id);
    }
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0 && !this.draining) {
      return;
    }

    await new Promise<void>((resolve) => {
      this.idleWaiters.push(resolve);
      void this.drain();
    });
  }
}

let sink: PersistenceSink | null = null;

export function setPersistenceSink(next: PersistenceSink | null): void {
  sink = next;
}

export function persistCreate<T extends { id: string }>(
  collection: CollectionName,
  record: T
): void {
  sink?.recordCreate(collection, record);
}

export function persistUpdate(
  collection: CollectionName,
  id: string,
  updates: Record<string, unknown>
): void {
  sink?.recordUpdate(collection, id, updates);
}

export function persistRemove(collection: CollectionName, id: string): void {
  sink?.recordRemove(collection, id);
}

export async function flushPersistence(): Promise<void> {
  await sink?.flush();
}
