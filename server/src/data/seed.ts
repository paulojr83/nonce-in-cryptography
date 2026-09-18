import { readFile, writeFile } from 'fs/promises';
import path from 'path';
import { storage } from './storage-layer';
import { DigestService } from '../services/digest-service';
import { logger } from '../utils/logger';
import { Nonce, Session, Todo, User } from '../types/entities';
 
export const DEMO_EMAIL = 'user@example.com';
export const DEMO_PASSWORD = 'DemoPassword123!';

 
export interface DatabaseFile {
  users: User[];
  todos: Todo[];
  nonces: Nonce[];
  sessions: Session[];
}

 
export function getDatabasePath(): string {
  return (
    process.env.DATABASE_FILE ?? path.resolve(process.cwd(), 'data', 'db.json')
  );
}
 
export async function buildSeedData(): Promise<DatabaseFile> {
  const now = Date.now();
  const userId = 'user_demo';

  const user: User = {
    id: userId,
    email: DEMO_EMAIL,
    digest_ha1: DigestService.computeHa1(DEMO_EMAIL, DEMO_PASSWORD),
    created_at: now,
    last_login: null,
    active_sessions: [],
    security_metadata: {
      failed_login_attempts: 0,
      last_failed_attempt: null,
      account_locked: false,
    },
  };

  const todos: Todo[] = [
    {
      id: 'todo_seed_1',
      user_id: userId,
      title: 'Read the nonce design document',
      description: 'Understand how single-use tokens prevent replay attacks',
      completed: true,
      created_at: now - 7_200_000,
      updated_at: now - 3_600_000,
      created_by_nonce_id: 'seed',
    },
    {
      id: 'todo_seed_2',
      user_id: userId,
      title: 'Try creating a todo from the UI',
      description: 'Watch the nonce rotate in the network tab',
      completed: false,
      created_at: now - 3_600_000,
      updated_at: now - 3_600_000,
      created_by_nonce_id: 'seed',
    },
    {
      id: 'todo_seed_3',
      user_id: userId,
      title: 'Replay a consumed nonce and watch it fail',
      description: 'Expect NONCE_ALREADY_USED with HTTP 403',
      completed: false,
      created_at: now - 1_800_000,
      updated_at: now - 1_800_000,
      created_by_nonce_id: 'seed',
    },
  ];

  return { users: [user], todos, nonces: [], sessions: [] };
}

/**
 * Write a fresh db.json, replacing whatever is there
 */
export async function writeSeedFile(targetPath = getDatabasePath()): Promise<DatabaseFile> {
  const data = await buildSeedData();
  await writeFile(targetPath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');

  logger.info('Seed database written', {
    path: targetPath,
    users: data.users.length,
    todos: data.todos.length,
  });

  return data;
}

/**
 * Read db.json, returning null when it is missing or unreadable
 */
export async function readDatabaseFile(
  targetPath = getDatabasePath()
): Promise<DatabaseFile | null> {
  try {
    const raw = await readFile(targetPath, 'utf8');
    return JSON.parse(raw) as DatabaseFile;
  } catch (error) {
    logger.warn('Could not read the database file', {
      path: targetPath,
      reason: (error as Error).message,
    });
    return null;
  }
}

 
export async function loadIntoStorage(data: DatabaseFile): Promise<void> {
  for (const user of data.users ?? []) {
    if (!(await storage.users.findById(user.id))) {
      await storage.users.create(user);
    }
  }

  for (const todo of data.todos ?? []) {
    if (!(await storage.todos.findById(todo.id))) {
      await storage.todos.create(todo);
    }
  }

  for (const session of data.sessions ?? []) {
    if (!(await storage.sessions.findById(session.id))) {
      await storage.sessions.create(session);
    }
  }

  for (const nonce of data.nonces ?? []) {
    if (!(await storage.nonces.findById(nonce.id))) {
      await storage.nonces.create(nonce);
    }
  }
}
 
export async function seedDatabase(targetPath = getDatabasePath()): Promise<number> {
  let data = await readDatabaseFile(targetPath);

  if (!data || !Array.isArray(data.users) || data.users.length === 0) {
    logger.info('No users found in the database file - writing seed data');
    data = await writeSeedFile(targetPath);
  }

  await loadIntoStorage(data);

  const count = await storage.users.count();
  logger.info('Database seeded', { users: count, todos: (data.todos ?? []).length });

  return count;
}
