/**
 * Copy the server's GraphQL SDL into client/schema.graphql.
 *
 * The Relay compiler type-checks every query against this file, so a stale copy
 * silently produces artifacts that do not match the running server. Run this
 * whenever the server schema changes (it runs automatically before `npm run relay`).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = resolve(here, '../../server/src/typedefs.ts');
const target = resolve(here, '../schema.graphql');

const file = readFileSync(source, 'utf8');

// typedefs.ts exports the SDL as a single backtick template literal
const match = file.match(/export const typeDefs = `([\s\S]*?)`;/);
if (!match) {
  console.error('Could not find the typeDefs template literal in', source);
  process.exit(1);
}

const header = `# GENERATED FILE - do not edit by hand.
# Synced from server/src/typedefs.ts by scripts/sync-schema.mjs.
`;

writeFileSync(target, `${header}${match[1].trim()}\n`, 'utf8');
console.log(`schema.graphql synced from ${source}`);
