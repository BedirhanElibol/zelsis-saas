import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';

test('SEC-45 points at the USING (true) line of a multi-line policy, not line 1', async () => {
  const sql = [
    '-- links',
    'ALTER TABLE links ENABLE ROW LEVEL SECURITY;',
    'CREATE POLICY "Links are viewable by everyone" ON links',
    '  FOR SELECT',
    '  USING (true);',
  ].join('\n');
  const { findings } = await runStaticCodeScan([{ path: 'supabase/migrations/1_links.sql', content: sql }], 'rls');
  const f = findings.find((x) => x.ruleId === 45);
  assert.ok(f, 'rule 45 fires');
  assert.equal(f.lineRange, 'L5');
});
