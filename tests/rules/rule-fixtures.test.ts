import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan, type CodeFile } from '../../lib/scanner-engine';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { KNOWN_GAPS, RULE_CASES, type RuleCase } from './cases';
import { VULNERABLE_VARIANTS } from './variants';
import { STACK_MATRIX } from './stack-matrix';

// The scanner clears each file's content after scanning (memory), so scan copies and keep fixtures reusable
const ruleIdsFor = async (files: CodeFile[]) =>
  new Set((await runStaticCodeScan(files.map((f) => ({ ...f })), 'fixture', { keepDuplicateRules: true })).findings.map((f) => f.ruleId));

/** Per-area fixture tables in tests/rules/fixtures/*.ts, each exporting `CASES`. */
const AREA_CASES: RuleCase[] = readdirSync(join(__dirname, 'fixtures'))
  .filter((n) => n.endsWith('.ts'))
  .sort()
  .flatMap((n) => (require(join(__dirname, 'fixtures', n)) as { CASES: RuleCase[] }).CASES);

describe('rule fixtures', () => {
  for (const c of [...RULE_CASES, ...AREA_CASES]) {
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

describe('same-issue dedupe', () => {
  it('reports one finding per issue in a normal scan', async () => {
    const source = AREA_CASES.find((c) => c.ruleIds.includes(8321) && c.ruleIds.includes(12204))!.detects;
    const copy = () => source.map((f) => ({ ...f }));
    const all = await ruleIdsFor(copy());
    const deduped = new Set((await runStaticCodeScan(copy(), 'fixture')).findings.map((f) => f.ruleId));
    assert.ok(all.has(8321) && all.has(12204), 'both host-network rules fire on their own');
    assert.ok(deduped.has(8321) && !deduped.has(12204), 'the duplicate is dropped in the report');
  });
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
  const root = join(__dirname, '../..');
  const readDir = (dir: string): CodeFile[] =>
    readdirSync(join(root, dir)).filter((n) => n.endsWith('.ts')).map((n) => ({ path: `${dir}/${n}`, content: readFileSync(join(root, dir, n), 'utf8') }));
  const scannerSources = (): CodeFile[] => [
    ...readDir('lib/scanner'),
    ...readDir('lib/rules'),
    { path: 'lib/scanner-engine.ts', content: readFileSync(join(root, 'lib/scanner-engine.ts'), 'utf8') }
  ];

  it("Zelsis's own .zelsisignore keeps its rule definitions out of its scan", async () => {
    const files = [...scannerSources(), { path: '.zelsisignore', content: readFileSync(join(root, '.zelsisignore'), 'utf8') }];
    const { findings } = await runStaticCodeScan(files, 'self');
    assert.deepEqual(findings.map((f) => `${f.ruleId} ${f.filePath}`), []);
  });

  it('the engine has no hardcoded knowledge of Zelsis paths (same files are scanned like any repo)', async () => {
    const { findings } = await runStaticCodeScan(scannerSources(), 'any-repo');
    assert.ok(findings.length > 0, 'rule sources full of vulnerable patterns must be scanned when not ignored');
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

describe('new rule packs accept their codes in .zelsisignore', () => {
  it('maps each code prefix to its id range', async () => {
    const { parseZelsisIgnore } = await import('../../lib/scanner-engine');
    const cases: [string, number][] = [['NEXT-SB-01', 28001], ['NODE-WEB-25', 28125], ['AI-APP-07', 28207], ['GHA-01', 28251], ['LLM-V2-16', 28316], ['PRIV-14', 28414], ['CLOUD-V2-25', 28525], ['A11Y-23', 28623]];
    for (const [code, id] of cases) assert.ok(parseZelsisIgnore(code).ignoredRuleIds.has(id), `${code} -> ${id}`);
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

describe('cross-stack matrix (vendor-neutral rules)', () => {
  for (const c of STACK_MATRIX) {
    it(`${c.expect === 'detect' ? 'detects' : 'stays clean on'} ${c.id}`, async () => {
      const found = await ruleIdsFor([{ path: c.path, content: c.content }]);
      const hit = c.rules.filter((r) => found.has(r));
      if (c.expect === 'detect') assert.ok(hit.length > 0, `none of ${c.rules.join(', ')} fired`);
      else assert.deepEqual(hit, [], `fired on safe code: ${hit.join(', ')}`);
    });
  }
});
