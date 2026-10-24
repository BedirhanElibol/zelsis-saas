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

test('SAAS-03 points at the CREATE FUNCTION line, not an earlier line that mentions the name', async () => {
  const sql = [
    'create table wall_visits (',
    '  id uuid primary key,',
    '  visitor_id text -- set by upsert_wall_visit',
    ');',
    'create or replace function upsert_wall_visit(p_wall uuid)',
    'returns void language plpgsql security definer as $$',
    'begin',
    '  insert into wall_visits (id) values (p_wall);',
    'end;',
    '$$;',
  ].join('\n');
  const { findings } = await runStaticCodeScan([{ path: 'supabase/migrations/1_visits.sql', content: sql }], 'fn');
  const f = findings.find((x) => x.ruleId === 23003);
  assert.ok(f, 'rule 23003 fires');
  assert.equal(f.lineRange, 'L5');
});

test('SEC-40 points at the cookie call when its options are on the next lines', async () => {
  const js = [
    "import express from 'express';",
    'const app = express();',
    "app.post('/login', (req, res) => {",
    "  res.cookie('session', token, {",
    '    httpOnly: false,',
    '  });',
    '});',
  ].join('\n');
  const { findings } = await runStaticCodeScan([{ path: 'server/app.js', content: js }], 'cookie');
  const f = findings.find((x) => x.ruleId === 40);
  assert.ok(f, 'rule 40 fires');
  assert.equal(f.lineRange, 'L4');
});
