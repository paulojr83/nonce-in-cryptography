import { writeSeedFile, getDatabasePath, DEMO_EMAIL, DEMO_PASSWORD } from '../data/seed';

async function main(): Promise<void> {
  const target = getDatabasePath();
  const data = await writeSeedFile(target);

  console.info(`Seeded ${target}`);
  console.info(`  users: ${data.users.length}`);
  console.info(`  todos: ${data.todos.length}`);
  console.info('');
  console.info('Sign in with:');
  console.info(`  email:    ${DEMO_EMAIL}`);
  console.info(`  password: ${DEMO_PASSWORD}`);
}

main().catch((error) => {
  console.error('Seeding failed:', error);
  process.exit(1);
});
