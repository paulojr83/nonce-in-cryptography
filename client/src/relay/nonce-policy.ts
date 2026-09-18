/**
 * Which operations validate a nonce, as far as the client is concerned.
 *
 * The client needs this before it sends anything: an operation the server is
 * not checking should go out as a plain GraphQL request rather than an
 * envelope sealed with a nonce that will be ignored.
 *
 * It is read from the build, not from the server. Asking at runtime would
 * mean publishing a list of unprotected operations to anyone with the network
 * panel open - a request that tells a passer-by exactly where to push. The
 * value comes from `NONCE_ENABLED_OPERATIONS` in `server/.env`, injected by
 * `vite.config.ts`, so there is still one place to change it; restarting the
 * dev server picks up an edit, the same restart the API needs anyway.
 *
 * The server decides regardless. This only decides how to send.
 */

import { Kind, parse } from 'graphql';
import type {
  DocumentNode,
  FragmentDefinitionNode,
  OperationDefinitionNode,
  SelectionSetNode,
} from 'graphql';

/** Every operation validates a nonce */
const ALL_OPERATIONS = '*';

/** None of them does */
const NO_OPERATIONS = 'none';

/**
 * Named only to report what is switched off. The decision itself never
 * consults this list - it asks about the field in hand - so a field missing
 * here costs nothing but a line in a log.
 */
const KNOWN_OPERATIONS = [
  'createTodo',
  'updateTodo',
  'deleteTodo',
  'logout',
  'me',
  'todos',
  'getTodo',
];

const RAW = (import.meta.env as Record<string, string | undefined>)
  .VITE_NONCE_ENABLED_OPERATIONS;

/**
 * Read the list the way the server reads it, so the two cannot disagree:
 * absent means every operation, present means exactly what it says, and an
 * empty value means none. `null` here stands for "all of them".
 */
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

  return new Set(operations);
}

const enabled = parseEnabled(RAW);

/** Does this root field travel with a nonce? */
export function isNonceEnforcedFor(field: string): boolean {
  return enabled === null ? true : enabled.has(field);
}

/** The operations running without one */
export function disabledOperations(): string[] {
  return enabled === null ? [] : KNOWN_OPERATIONS.filter((field) => !enabled.has(field));
}

/**
 * The root fields a document selects: `todos` in the request Relay builds for
 * `GetTodosQuery`, even though that query's only root selection is a fragment
 * spread and the field is one level down, inside the fragment.
 *
 * Parsed rather than pattern-matched. A wrong answer in the "no nonce needed"
 * direction makes the server refuse a read the client could have sent
 * correctly, which is too high a price for a regular expression. This mirrors
 * `extractOperationInfo` on the server, which decides the same thing about
 * the same document - and remains the one that decides.
 */
export function rootFieldsOf(text: string | null | undefined): string[] {
  if (!text) {
    return [];
  }

  let document: DocumentNode;
  try {
    document = parse(text);
  } catch {
    return [];
  }

  const fragments = new Map<string, FragmentDefinitionNode>();
  for (const definition of document.definitions) {
    if (definition.kind === Kind.FRAGMENT_DEFINITION) {
      fragments.set(definition.name.value, definition);
    }
  }

  const operation = document.definitions.find(
    (definition): definition is OperationDefinitionNode =>
      definition.kind === Kind.OPERATION_DEFINITION
  );

  if (!operation) {
    return [];
  }

  const fields: string[] = [];
  const visited = new Set<string>();

  const collect = (selectionSet: SelectionSetNode): void => {
    for (const selection of selectionSet.selections) {
      if (selection.kind === Kind.FIELD) {
        fields.push(selection.name.value);
        continue;
      }

      if (selection.kind === Kind.INLINE_FRAGMENT) {
        collect(selection.selectionSet);
        continue;
      }

      // A spread at the root: the fields it selects are this operation's
      const name = selection.name.value;
      const fragment = fragments.get(name);
      if (fragment && !visited.has(name)) {
        visited.add(name);
        collect(fragment.selectionSet);
      }
    }
  };

  collect(operation.selectionSet);

  return fields;
}
