import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [18104],
    name: 'ORM-RAW-01 Drizzle sql.raw / Prisma $queryRawUnsafe with request value vs table names, validated ID lists, and migrations',
    detects: f('src/users/repo.ts', `import { sql } from 'drizzle-orm';
export async function findByEmail(db: any, req: any) {
  const email = req.query.email;
  return db.execute(sql.raw(\`SELECT * FROM users WHERE email = '\${email}'\`));
}
`),
    ignores: [
      ...f('src/db/stats.ts', `import { sql } from 'drizzle-orm';
export async function countRows(db: any, table: string, localesTable: string) {
  await db.execute(sql.raw(\`CREATE TABLE "\${localesTable}" (id serial primary key)\`));
  return db.execute(sql.raw(\`SELECT COUNT(*) FROM \${table}\`));
}
`),
      ...f('src/library/query.ts', `import { sql } from 'drizzle-orm';
export async function filterByLibraries(rawIds: string[]) {
  const libraryIds = rawIds.map((id) => Number(id)).filter((n) => Number.isFinite(n));
  return sql.raw(\`(\${libraryIds.join(',')})\`);
}
`),
      ...f('src/db/migrations/20260912_init.ts', `import { sql } from 'drizzle-orm';
export async function up(db: any, schemaName: string) {
  await db.execute(sql.raw(\`ALTER TABLE \${schemaName}.users ADD COLUMN active boolean DEFAULT true\`));
}
`),
      ...f('server/predefinedMigrations/seed.ts', `import { sql } from 'drizzle-orm';
export async function seed(db: any, val: string) {
  await db.execute(sql.raw(\`INSERT INTO config VALUES ('\${val}')\`));
}
`)
    ]
  },
  {
    ruleIds: [18101],
    name: 'MYSQL-SEC-01 Python cursor.execute f-string vs TypeScript pool.query and table-name interpolation',
    detects: f('app/db/users.py', `def find_user(cursor, name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
`),
    ignores: [
      ...f('server/conversations.ts', `export async function archiveConversations(pool: any, status: string) {
  return pool.query(\`update conversations set status = '\${status}'\`);
}
`),
      ...f('app/db/stats.py', `def count_rows(cursor, table_name: str):
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    return cursor.fetchone()
`)
    ]
  }
];
