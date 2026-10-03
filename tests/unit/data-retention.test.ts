import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CODE_RETENTION_STATEMENT, CODE_SNIPPET_RETENTION_DAYS } from '../../lib/data-retention';

const root = join(__dirname, '../..');
const read = (rel: string) => readFileSync(join(root, rel), 'utf8');

test('the purge job enforces the advertised snippet retention window', () => {
  const sql = read('supabase/migrations/20261003120000_code_snippet_retention.sql');
  assert.match(sql, new RegExp(`interval '${CODE_SNIPPET_RETENTION_DAYS} days'`));
  assert.match(sql, /cron\.schedule\(\s*'purge-expired-code-snippets'/);
  assert.match(CODE_RETENTION_STATEMENT, new RegExp(`after ${CODE_SNIPPET_RETENTION_DAYS} days`));
});

test('retention copy comes from the shared statement, never a placeholder or old claim', () => {
  const files = [
    'components/saas/SaasHero.tsx',
    'components/saas/FinalCta.tsx',
    'components/saas/WorkflowSteps.tsx',
    'app/privacy/page.tsx',
  ];
  for (const file of files) {
    const src = read(file);
    assert.ok(src.includes('CODE_RETENTION_STATEMENT'), `${file} should render CODE_RETENTION_STATEMENT`);
    assert.ok(!src.includes('<N>'), `${file} still has a placeholder`);
    assert.ok(!/Repo never stored/i.test(src), `${file} still has the old storage claim`);
  }
});
