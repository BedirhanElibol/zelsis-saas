import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan, type CodeFile } from '../../lib/scanner-engine';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { KNOWN_GAPS, RULE_CASES } from './cases';
import { VULNERABLE_VARIANTS } from './variants';

const ruleIdsFor = async (files: CodeFile[]) =>
  new Set((await runStaticCodeScan(files, 'fixture')).findings.map((f) => f.ruleId));

describe('rule fixtures', () => {
  for (const c of RULE_CASES) {
    describe(`${c.name} (#${c.ruleIds.join(', #')})`, () => {
      it('detects the vulnerable fixture', async () => {
        const found = await ruleIdsFor(c.detects);
        const missing = c.ruleIds.filter((id) => !found.has(id));
        assert.deepEqual(missing, [], `rules did not fire: ${missing.join(', ')}`);
      });

      it('ignores the fixed fixture (no false positive)', async () => {
        const found = await ruleIdsFor(c.ignores);
        const fired = c.ruleIds.filter((id) => found.has(id));
        assert.deepEqual(fired, [], `rules fired on safe code: ${fired.join(', ')}`);
      });
    });
  }
});

describe('known scanner gaps', () => {
  for (const gap of KNOWN_GAPS) {
    it(`[${gap.kind}] ${gap.name}`, { todo: 'move to RULE_CASES once fixed' }, async () => {
      const found = await ruleIdsFor(gap.files);
      if (gap.kind === 'false-positive') {
        assert.ok(gap.ruleId !== null && !found.has(gap.ruleId), `rule ${gap.ruleId} still fires`);
      } else {
        const securityFindings = (await runStaticCodeScan(gap.files, 'gap')).findings.filter((f) => f.type === 'SECURITY');
        assert.ok(securityFindings.length > 0, 'no security finding reported');
      }
    });
  }
});

describe('vulnerable variants (breadth guard)', () => {
  for (const [ruleId, name, files] of VULNERABLE_VARIANTS) {
    it(`#${ruleId} catches: ${name}`, async () => {
      assert.ok((await ruleIdsFor(files)).has(ruleId), `rule ${ruleId} missed this variant`);
    });
  }
});

describe('scanner self-reference', () => {
  it('rule definitions and scanner modules produce no findings when Zelsis scans itself', async () => {
    const root = join(__dirname, '../..');
    const dirs = ['lib/scanner', 'lib/rules'];
    const files: CodeFile[] = dirs.flatMap((dir) =>
      readdirSync(join(root, dir)).filter((n) => n.endsWith('.ts')).map((n) => ({ path: `${dir}/${n}`, content: readFileSync(join(root, dir, n), 'utf8') }))
    );
    files.push({ path: 'lib/scanner-engine.ts', content: readFileSync(join(root, 'lib/scanner-engine.ts'), 'utf8') });
    const { findings } = await runStaticCodeScan(files, 'self');
    assert.deepEqual(findings.map((f) => `${f.ruleId} ${f.filePath}`), []);
  });
});

describe('test fixture files', () => {
  it('skips non-secret findings in test files but still reports leaked secrets', async () => {
    const key = ['sk', 'proj', 'abcdefghijklmnopqrstuvwxyz123456'].join('-');
    const found = await ruleIdsFor([
      { path: 'tests/unit/calc.test.ts', content: 'export const run = (input: string) => eval(input);\n' },
      { path: 'src/__tests__/client.spec.ts', content: `const key = "${key}";\n` }
    ]);
    assert.ok(!found.has(32), 'eval in a test file must not count');
    assert.ok(found.has(1), 'secret committed in a test file must still be reported');
  });

  it('still scans production code with the same content', async () => {
    assert.ok((await ruleIdsFor([{ path: 'lib/calc.ts', content: 'export const run = (input: string) => eval(input);\n' }])).has(32));
  });
});

describe('SAAS rule suppression', () => {
  it('.zelsisignore accepts SAAS-xx codes', async () => {
    const { parseZelsisIgnore } = await import('../../lib/scanner-engine');
    assert.ok(parseZelsisIgnore('SAAS-04').ignoredRuleIds.has(23004));
    const found = await ruleIdsFor([
      { path: '.zelsisignore', content: 'SAAS-06\n' },
      { path: 'app/api/cron/sync/route.ts', content: 'export async function GET() {\n  await syncAll();\n  return Response.json({ ok: true });\n}\n' }
    ]);
    assert.ok(!found.has(23006));
  });
});
