import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolyglotCoreRules } from '@/lib/rules/polyglot-core-rules';
import { stripComments } from '@/lib/scanner/text';

const core01 = (path: string, content: string) =>
  evaluatePolyglotCoreRules({ path, content }, content.split('\n'), stripComments(content), { count: 0 }).findings.find((f) => f.ruleId === 24101);

test('CORE-01 blocks (CRITICAL) when a value is spliced into the SQL', () => {
  assert.equal(core01('app/db.py', `def find(cur, name):\n    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")\n`)?.severity, 'CRITICAL');
  assert.equal(core01('Repo.java', `class Repo {\n  int count(String tenant) {\n    String sql = "SELECT COUNT(ID) FROM config_info where tenant_id like '" + tenant + "'";\n    return jdbc.queryForObject(sql, Integer.class);\n  }\n}\n`)?.severity, 'CRITICAL');
});

test('CORE-01 is advice (MEDIUM) when the code only assembles structure', () => {
  const f = core01('app/store.py', `def update(conn, assignments, values, row_id, guard):\n    conn.execute(f"UPDATE items SET {assignments} WHERE id = ?", (*values, row_id))\n    conn.execute(f"SELECT * FROM items {guard} ORDER BY id")\n`);
  assert.equal(f?.severity, 'MEDIUM');
});
