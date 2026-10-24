import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { RULE_CASES } from '../rules/cases';

const toCrlf = (s: string) => s.replace(/\r?\n/g, '\r\n');

test('every rule fixture is still caught when the files use CRLF line endings', async () => {
  const missed: string[] = [];
  for (const c of RULE_CASES) {
    const files = c.detects.map((f) => ({ path: f.path, content: toCrlf(f.content) }));
    const fired = new Set((await runStaticCodeScan(files, 'crlf', { keepDuplicateRules: true })).findings.map((f) => f.ruleId));
    for (const id of c.ruleIds) if (!fired.has(id)) missed.push(`${id} (${c.name})`);
  }
  assert.deepEqual(missed, [], 'rules that miss Windows line endings');
});

test('findings point at the same lines with CRLF and LF', async () => {
  const content = "const a = 1;\nexport const key = \"sk-proj-abcdefghijklmnopqrstuvwxyz123456\";\n";
  const lf = (await runStaticCodeScan([{ path: 'src/a.ts', content }], 'lf')).findings.map((f) => `${f.ruleId}:${f.lineRange}`).sort();
  const crlf = (await runStaticCodeScan([{ path: 'src/a.ts', content: toCrlf(content) }], 'crlf')).findings.map((f) => `${f.ruleId}:${f.lineRange}`).sort();
  assert.deepEqual(crlf, lf);
});
