import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolyglotCoreRules } from '../../lib/rules/polyglot-core-rules';

// From a user's report: the finding pointed at a safe one-line query earlier in the file, not the statement it judged
test('CORE-01 points at the statement it reports, not the first SQL line in the file', () => {
  const content = [
    'def ids(conn, table):',
    '    return conn.execute("SELECT id FROM %s" % _sqlite.quote_ident(table)).fetchall()',
    '',
    'def build(conn, cols, where):',
    '    sql = ("SELECT p.id, %s FROM "',
    '           "part p WHERE %s" % (cols, where))',
    '    return conn.execute(sql).fetchall()',
    '',
  ].join('\n');
  const r = evaluatePolyglotCoreRules({ path: 'app/store.py', content }, content.split('\n'), content, { count: 0 });
  const core01 = r.findings.find((f) => f.ruleId === 24101);
  assert.ok(core01, 'CORE-01 fires on the dynamic statement');
  assert.equal(core01.lineRange, 'L5');
});
