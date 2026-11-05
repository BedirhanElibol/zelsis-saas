import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findingKey, scanBaseVersions, splitByBaseline, MAX_BASELINE_FILES } from '@/lib/github/pr-baseline';
import { runStaticCodeScan } from '@/lib/scanner-engine';

const F = (ruleId: number, filePath: string, snippet: string) => ({ ruleId, filePath, snippet, title: 't' });

test('without a baseline every finding in a changed file is new (old behaviour)', () => {
  const { newFindings, existingFindings } = splitByBaseline([F(1, 'a.ts', 'x'), F(1, 'b.ts', 'x')], ['a.ts'], null);
  assert.deepEqual(newFindings.map((f) => f.filePath), ['a.ts']);
  assert.deepEqual(existingFindings.map((f) => f.filePath), ['b.ts']);
});

test('a finding whose rule and code were already in the base file is pre-existing', () => {
  const head = [F(1, 'a.ts', 'eval(input)'), F(2, 'a.ts', 'db.query(sql)')];
  const base = [F(1, 'a.ts', '  eval(input)  ')];
  const { newFindings, existingFindings } = splitByBaseline(head, ['a.ts'], base);
  assert.deepEqual(newFindings.map((f) => f.ruleId), [2]);
  assert.deepEqual(existingFindings.map((f) => f.ruleId), [1]);
});

test('a vulnerable line copied a second time is still new', () => {
  const head = [F(1, 'a.ts', 'eval(input)'), F(1, 'a.ts', 'eval(input)')];
  const { newFindings } = splitByBaseline(head, ['a.ts'], [F(1, 'a.ts', 'eval(input)')]);
  assert.equal(newFindings.length, 1);
});

test('findingKey ignores line numbers and whitespace', () => {
  assert.equal(findingKey({ ruleId: 5, filePath: 'x.py', snippet: 'a  =\tb' }), findingKey({ ruleId: 5, filePath: 'x.py', snippet: ' a = b ' }));
});

test('scanBaseVersions skips files missing at the base and large PRs', async () => {
  assert.equal(await scanBaseVersions(Array.from({ length: MAX_BASELINE_FILES + 1 }, (_, i) => `f${i}.ts`), async () => 'x', 'r'), null);
  assert.deepEqual(await scanBaseVersions(['new.ts'], async () => null, 'r'), []);
});

test('touching one line of a file with an old issue does not report that issue as new', async () => {
  const before = 'import https from "https";\nexport const agent = new https.Agent({ rejectUnauthorized: false });\n';
  const after = '// small comment change\nimport https from "https";\nexport const agent = new https.Agent({ rejectUnauthorized: false });\n';
  const head = await runStaticCodeScan([{ path: 'src/agent.ts', content: after }], 'demo/repo');
  const base = await scanBaseVersions(['src/agent.ts'], async () => before, 'demo/repo');
  assert.ok(head.findings.some((f) => f.ruleId === 12304), 'TLS-04 fires at head');
  const { newFindings } = splitByBaseline(head.findings, ['src/agent.ts'], base);
  assert.equal(newFindings.filter((f) => f.ruleId === 12304).length, 0);
});
