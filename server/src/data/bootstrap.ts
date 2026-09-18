import { storage } from './storage-layer';
import { JsonServerClient } from './json-server-client';
import { PersistenceSink, setPersistenceSink, flushPersistence } from './persistence';
import { buildSeedData, seedDatabase, type DatabaseFile } from './seed';
import { logger } from '../utils/logger';
import { getEnv } from '../utils/env';
import { Nonce, Session, Todo, User } from '../types/entities';

export interface BootstrapResult {
  persisted: boolean;
  users: number;
  todos: number;
  nonces: number;
  sessions: number;
}

async function readFromJsonServer(client: JsonServerClient): Promise<DatabaseFile> {
  const [users, todos, nonces, sessions] = await Promise.all([
    client.list<User>('users'),
    client.list<Todo>('todos'),
    client.list<Nonce>('nonces'),
    client.list<Session>('sessions'),
  ]);

  return { users, todos, nonces, sessions };
}

async function writeToJsonServer(
  client: JsonServerClient,
  data: DatabaseFile
): Promise<void> {
  for (const user of data.users ?? []) {
    await client.create('users', user);
  }
  for (const todo of data.todos ?? []) {
    await client.create('todos', todo);
  }
}


function pruneExpired(data: DatabaseFile): DatabaseFile {
  const now = Date.now();

  return {
    ...data,
    nonces: (data.nonces ?? []).filter((nonce) => nonce.expires_at > now),
    sessions: (data.sessions ?? []).filter((session) => session.expires_at > now),
  };
}


async function hydrate(data: DatabaseFile, sink: PersistenceSink | null): Promise<void> {
  setPersistenceSink(null);

  try {
    for (const user of data.users ?? []) {
      if (!(await storage.users.findById(user.id))) await storage.users.create(user);
    }
    for (const todo of data.todos ?? []) {
      if (!(await storage.todos.findById(todo.id))) await storage.todos.create(todo);
    }
    for (const session of data.sessions ?? []) {
      if (!(await storage.sessions.findById(session.id))) {
        await storage.sessions.create(session);
      }
    }
    for (const nonce of data.nonces ?? []) {
      if (!(await storage.nonces.findById(nonce.id))) await storage.nonces.create(nonce);
    }
  } finally {
    setPersistenceSink(sink);
  }
}


export async function bootstrapStorage(databaseUrl?: string): Promise<BootstrapResult> {
  const baseUrl = databaseUrl ?? getEnv().databaseUrl;
  const client = new JsonServerClient({ baseUrl });

  if (!(await client.isReachable())) {
    logger.warn(
      `json-server is not reachable at ${baseUrl} - running in memory only. ` +
        'Nonces and sessions will not be written to db.json. ' +
        'Start it with: npm run db --workspace=server'
    );

    const users = await seedDatabase();
    return {
      persisted: false,
      users,
      todos: await storage.todos.count(),
      nonces: 0,
      sessions: 0,
    };
  }

  logger.info(`json-server reachable at ${baseUrl} - persisting to db.json`);

  let data = await readFromJsonServer(client);
  if (data.users.length === 0) {
    logger.info('Database has no users - seeding through json-server');
    const seed = await buildSeedData();
    await writeToJsonServer(client, seed);
    data = await readFromJsonServer(client);
  }

  const dropped =
    (data.nonces?.length ?? 0) + (data.sessions?.length ?? 0);
  const usable = pruneExpired(data);
  const keptShortLived = (usable.nonces?.length ?? 0) + (usable.sessions?.length ?? 0);

  if (dropped > keptShortLived) {
    logger.info('Skipped expired nonces/sessions found in the database', {
      skipped: dropped - keptShortLived,
    });
  }

  const sink = new PersistenceSink(client);
  await hydrate(usable, sink);
  setPersistenceSink(sink);

  const result: BootstrapResult = {
    persisted: true,
    users: await storage.users.count(),
    todos: await storage.todos.count(),
    nonces: await storage.nonces.count(),
    sessions: usable.sessions?.length ?? 0,
  };

  logger.info('Storage bootstrapped from json-server', { ...result });

  return result;
}

export async function shutdownStorage(): Promise<void> {
  await flushPersistence();
}

