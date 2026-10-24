import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hasUntrustedInput } from '../../lib/scanner/text';
import { runStaticCodeScan } from '../../lib/scanner-engine';

test('a variable whose name ends in r is not request input', () => {
  assert.equal(hasUntrustedInput('const h = user.header;\nconst b = parser.body;\nbuffer.form = 1;'), false);
  assert.equal(hasUntrustedInput('func h(w http.ResponseWriter, r *http.Request) { r.FormValue("q") }'), true);
});

test('eval is CRITICAL with request input in the file and HIGH without it', async () => {
  const withInput = "export function run(req: any) {\n  return eval(req.query.code);\n}\n";
  const noInput = "export function run(expr: string) {\n  return eval(expr);\n}\n";
  const a = await runStaticCodeScan([{ path: 'src/api/run.ts', content: withInput }], 't', { dependencyAudit: false });
  const b = await runStaticCodeScan([{ path: 'src/lib/run.ts', content: noInput }], 't', { dependencyAudit: false });
  assert.ok(a.findings.some((f) => f.ruleId === 32 && f.severity === 'CRITICAL'));
  const evalNoInput = b.findings.filter((f) => f.ruleId === 32);
  assert.ok(evalNoInput.length > 0 && evalNoInput.every((f) => f.severity === 'HIGH'));
});
