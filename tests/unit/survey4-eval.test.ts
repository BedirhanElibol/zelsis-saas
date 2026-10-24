import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';

describe('SEC-32 reviewed eval and trusted dynamic MDX compilation', () => {
  it('lowers eval with oxlint-disable-next-line to MEDIUM', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'editor/grida-canvas-react/devtools/__unsafe-console.tsx',
        content: '// oxlint-disable-next-line no-eval -- intentional: devtools debug console\nconst output = eval(value);',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'MEDIUM');
  });

  it('lowers eval with biome-ignore lint/security/noGlobalEval to MEDIUM', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'src/runtime/calc.ts',
        content: '// biome-ignore lint/security/noGlobalEval: safe dynamic math\nconst res = eval(expr);',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'MEDIUM');
  });

  it('lowers new Function in design-system MDX component to MEDIUM when no request input', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'apps/design-system/lib/use-mdx-component.tsx',
        content: 'export function getMDXComponent(code: string) {\n  const fn = new Function(code);\n  return fn();\n}',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'MEDIUM');
  });

  it('keeps new Function CRITICAL when request input reaches it', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'apps/design-system/lib/use-mdx-component.tsx',
        content: 'export function getMDXComponent(req: Request) {\n  const fn = new Function(req.query.code);\n  return fn();\n}',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'CRITICAL');
  });

  it('keeps eval(req.body.x) CRITICAL', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'src/api/run.ts',
        content: 'export function run(req: any) {\n  return eval(req.body.x);\n}',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'CRITICAL');
  });

  it('keeps Ruby eval(@subdomain.analytics_report_frequency) CRITICAL', async () => {
    const res = await runStaticCodeScan([
      {
        path: 'app/services/analytics_report_service.rb',
        content: 'def run\n  @report_since = eval(@subdomain.analytics_report_frequency).ago\nend',
      },
    ], 'test');
    const f32 = res.findings.filter((f) => f.ruleId === 32);
    assert.equal(f32.length, 1);
    assert.equal(f32[0].severity, 'CRITICAL');
  });
});
