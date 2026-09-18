import { getEnv } from './env';
import { logger } from './logger';

export const ALL_OPERATIONS = '*';

export const NONCE_DISABLED_ID = 'nonce-disabled';

export const PROTECTED_MUTATIONS = [
  'createTodo',
  'updateTodo',
  'deleteTodo',
  'logout',
];

export const PROTECTED_QUERIES = ['me', 'todos', 'getTodo'];

export const PROTECTED_OPERATIONS = [...PROTECTED_MUTATIONS, ...PROTECTED_QUERIES];

let exempt: Set<string> | null = null;

function parseDisabled(raw: string | undefined): Set<string> {
  if (!raw) {
    return new Set();
  }

  return new Set(
    raw
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
  );
}

function state(): Set<string> {
  if (exempt === null) {
    exempt = parseDisabled(getEnv().nonceDisabledOperations);
  }

  return exempt;
}

export function isNonceEnforcedFor(field: string): boolean {
  const disabled = state();

  return !disabled.has(ALL_OPERATIONS) && !disabled.has(field);
}

export function setNonceEnforcement(field: string, enforced: boolean): void {
  const next = new Set(state());

  if (enforced) {
    next.delete(field);
    next.delete(ALL_OPERATIONS);
  } else {
    next.add(field);
  }

  exempt = next;

  logger.warn('Nonce enforcement changed', { field, enforced });
}

export function disabledOperations(): string[] {
  return [...state()];
}

export function resetNonceEnforcement(): void {
  exempt = null;
}
