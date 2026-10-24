import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3021, 6043],
    name: 'Rules 3021 & 6043 raw SQL vs quoteIdentifier, quote and constant interpolation',
    detects: f('src/routes/users.ts', `import { db } from '../db';
export async function deleteUser(req: any) {
  const userId = req.body.userId;
  await db.query(\`DELETE FROM users WHERE id = \${userId}\`);
}
`),
    ignores: f('src/datasets/wipe.ts', `import { db, client } from '../db';
export async function wipeTable(t: string, companyId: string) {
  const quote = (name: string) => '"' + name.replace(/"/g, '""') + '"';
  await db.query(\`DELETE FROM \${quote(t)} WHERE "companyId" = $1\`, [companyId]);
}
export async function getCount(schema: string, table: string) {
  const quoteIdentifier = (i: string) => '"' + i + '"';
  return client.query(\`SELECT COUNT(*) FROM \${quoteIdentifier(schema)}.\${quoteIdentifier(table)}\`);
}
export async function getMetrics(orgId: string) {
  const WALL_METRIC = 'wall_clock_time';
  return db.query(\`SELECT * FROM metrics WHERE type = '\${WALL_METRIC}' AND org_id = $1\`, [orgId]);
}
`),
  },
  {
    ruleIds: [18101],
    name: 'Rule 18101 Python MySQL injection vs introspection ops.quote_name',
    detects: f('app/db/users.py', `def find_user(cursor, name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
`),
    ignores: f('django/db/backends/postgresql/introspection.py', `class DatabaseIntrospection:
    def get_table_description(self, cursor, table_name):
        cursor.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s
            """
            % self.connection.ops.quote_name(table_name)
        )
        return cursor.fetchall()
`),
  },
];
