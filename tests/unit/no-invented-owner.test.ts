import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '@/lib/scanner-engine';

test('findings carry no owner the rule made up', async () => {
  const code = 'export function show(el: HTMLElement, q: URLSearchParams) {\n  el.innerHTML = q.get("name") ?? "";\n}\n';
  const { findings } = await runStaticCodeScan([{ path: 'src/show.ts', content: code }], 'solo/repo');
  assert.ok(findings.length > 0, 'the innerHTML rule should fire');
  for (const f of findings) assert.equal(f.owner, undefined, `${f.ruleId} still has owner "${f.owner}"`);
});
