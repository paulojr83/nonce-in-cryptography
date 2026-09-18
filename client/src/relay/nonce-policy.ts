import { Kind, parse } from 'graphql';
import type {
  DocumentNode,
  FragmentDefinitionNode,
  OperationDefinitionNode,
  SelectionSetNode,
} from 'graphql';

const ALL_OPERATIONS = '*';

const RAW = (import.meta.env as Record<string, string | undefined>)
  .VITE_NONCE_DISABLED_OPERATIONS;

const exempt = new Set(
  (RAW ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
);

/** Does this root field travel with a nonce? */
export function isNonceEnforcedFor(field: string): boolean {
  return !exempt.has(ALL_OPERATIONS) && !exempt.has(field);
}

/** The exemptions in force, for the start-up log */
export function disabledOperations(): string[] {
  return [...exempt];
}

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
