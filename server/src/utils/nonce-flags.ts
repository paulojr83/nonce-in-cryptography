/**
 * Per-operation nonce switch.
 *
 * Nonce validation is on for every protected operation by default, reads and
 * writes alike. This module is the one place that can turn it off again, one
 * field at a time, so an operation can be exercised without a nonce -
 * measuring what the check costs, reproducing a client bug, demonstrating the
 * replay the nonce prevents - without touching the middleware that enforces
 * it.
 *
 * `NONCE_ENABLED_OPERATIONS` says which operations validate their nonce:
 *
 *   no such variable            every protected operation - the default
 *   `*`                         the same, said out loud
 *   `todos,createTodo`          those two; the rest run without a nonce
 *   empty, or `none`            nothing validates anything
 *
 * Only an absent variable falls back to "all", so a machine with no .env is
 * protected; a list that is present is read literally. Turning an operation
 * off removes its replay and CSRF protection: this is a development switch,
 * not a production one.
 */

import { getEnv } from './env';
import { logger } from './logger';

export const PROTECTED_MUTATIONS = [
  'createTodo',
  'updateTodo',
  'deleteTodo',
  'logout',
];

/**
 * Queries that require nonce validation.
 *
 * A read presents its nonce but does not spend it: consuming one per read
 * would burn a single-use token on an operation that changes nothing, and the
 * page would need a fresh nonce for every list it draws. So the same nonce
 * proves the same live session across many reads, and only a mutation retires
 * it.

 */
export const PROTECTED_QUERIES = ['me', 'todos', 'getTodo'];

/** Everything the switch can turn on or off, reads and writes alike */
export const PROTECTED_OPERATIONS = [...PROTECTED_MUTATIONS, ...PROTECTED_QUERIES];

export const ALL_OPERATIONS = '*';
export const NO_OPERATIONS = 'none';

export const NONCE_DISABLED_ID = 'nonce-disabled';

let enabled: Set<string> | null | undefined;

function parseEnabled(raw: string | undefined): Set<string> | null {
  if (raw === undefined) {
    return null;
  }

  const operations = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (operations.includes(ALL_OPERATIONS)) {
    return null;
  }

  if (operations.includes(NO_OPERATIONS)) {
    return new Set();
  }

  // Including the empty list, which is every mutation switched off
  return new Set(operations);
}

function state(): Set<string> | null {
  if (enabled === undefined) {
    enabled = parseEnabled(getEnv().nonceEnabledOperations);
  }

  return enabled;
}

export function isNonceEnforcedFor(field: string): boolean {
  const current = state();

  return current === null ? true : current.has(field);
}

export function setNonceEnforcement(field: string, enforced: boolean): void {
  const current = state();
  const next = current === null ? new Set(PROTECTED_OPERATIONS) : new Set(current);

  if (enforced) {
    next.add(field);
  } else {
    next.delete(field);
  }

  enabled = next;

  logger.warn('Nonce enforcement changed', { field, enforced });
}

export function getNoncePolicy(): {
  enabledOperations: string[];
  disabledOperations: string[];
} {
  return {
    enabledOperations: PROTECTED_OPERATIONS.filter(isNonceEnforcedFor),
    disabledOperations: PROTECTED_OPERATIONS.filter((field) => !isNonceEnforcedFor(field)),
  };
}

export function resetNonceEnforcement(): void {
  enabled = undefined;
}
