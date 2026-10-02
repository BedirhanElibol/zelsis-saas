/**
 * Rule inventory: what each rule ID actually is, measured from source instead of claimed.
 * Writes data/rule-inventory.generated.json, which the UI and docs use for rule counts.
 *
 *   npx tsx scripts/rule-audit.ts          # regenerate
 *   npx tsx scripts/rule-audit.ts --check  # fail if the committed file is stale
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { REVIEWED_TRUE_POSITIVES } from './benchmark/reviewed';

const root = join(__dirname, '..');
const OUT = join(root, 'data/rule-inventory.generated.json');
/** Compact form for the UI bundle: counts plus the implemented rule IDs / codes. */
const SUMMARY_OUT = join(root, 'data/rule-summary.generated.json');
/** Rules with evidence (fixture-tested, caught a documented flaw, or reviewed true positive): only these can block a release. */
const EVIDENCE_OUT = join(root, 'data/rule-evidence.generated.json');

export interface RuleRecord {
  ruleId: number;
  code: string;
  title: string;
  severity: string;
  source: string;
  /** Finding points at a matched line (false = first line of the file / any line). */
  preciseLocation: boolean;
  /** Has at least one vulnerable/safe fixture in tests/. */
  tested: boolean;
  inCatalog: boolean;
}

const read = (p: string) => readFileSync(join(root, p), 'utf8');
const ruleSources = [
  ...readdirSync(join(root, 'lib/rules')).filter((f) => f.endsWith('.ts')).map((f) => `lib/rules/${f}`),
  'lib/scanner/builtin-rules.ts',
  'lib/scanner/osv.ts',
  'lib/scanner/live-checks.ts'
];

/** Rule IDs exercised by fixtures (new harness + legacy suite). */
function testedRuleIds(): Set<number> {
  const ids = new Set<number>();
  const add = (text: string, re: RegExp) => {
    for (const m of text.matchAll(re)) for (const n of m[1].match(/\d+/g) ?? []) ids.add(Number(n));
  };
  const areaFixtures = readdirSync(join(root, 'tests/rules/fixtures')).filter((f) => f.endsWith('.ts')).sort().map((f) => `tests/rules/fixtures/${f}`);
  for (const p of ['tests/rules/cases.ts', ...areaFixtures, 'tests/rules/variants.ts', 'tests/rules/stack-matrix.ts', 'tests/unit/osv.test.ts', 'tests/unit/live-checks.test.ts', 'tests/rules/secret-samples.generated.ts']) {
    const t = read(p);
    add(t, /ruleIds:\s*\[([^\]]*)\]/g);
    add(t, /rules:\s*\[([^\]]*)\]/g);
    add(t, /^\s*\[(\d+),\s*['"]/gm);
    add(t, /\[\s*'[^'\n]+',\s*(\d+),\s*'(?:detect|clean)'/g);
  }
  const legacy = read('tests/test_suite.ts');
  add(legacy, /ruleId\s*===\s*(\d+)/g);
  add(legacy, /\.has\((\d+)\)/g);
  return ids;
}

function catalogIds(): { ids: Set<number>; placeholder: Set<number> } {
  const ids = new Set<number>();
  const placeholder = new Set<number>();
  for (const f of readdirSync(join(root, 'data/catalogs')).filter((n) => n.endsWith('.ts'))) {
    const text = read(`data/catalogs/${f}`);
    for (const entry of text.split(/\n\s*\{\s*\n/)) {
      const id = entry.match(/^\s*id:\s*(\d+),/m);
      if (!id) continue;
      ids.add(Number(id[1]));
      if (/positiveExample:\s*"Safe implementation"|cweId:\s*"CWE-1234"/.test(entry)) placeholder.add(Number(id[1]));
    }
  }
  return { ids, placeholder };
}

export function auditRules() {
  const tested = testedRuleIds();
  const catalog = catalogIds();
  const rules = new Map<number, RuleRecord>();

  for (const source of ruleSources) {
    const text = read(source);
    for (const m of text.matchAll(/ruleId:\s*(\d+),/g)) {
      const ruleId = Number(m[1]);
      if (rules.has(ruleId)) continue;
      const before = text.slice(Math.max(0, m.index! - 2500), m.index);
      const after = text.slice(m.index, m.index! + 600);
      const lineSearch = before.slice(before.lastIndexOf('matchLineIdx ='));
      const onlySkipsComments = /findIndex\(\s*l\s*=>\s*(?:!l\.trim\(\)\.startsWith\([^)]*\)\s*(?:&&\s*)?)+\)/.test(lineSearch);
      const firstLineFallback = /lines\.indexOf\(l\)\s*===\s*0/.test(lineSearch);
      const title = after.match(/title:\s*[`"']([^`"'\n]+)[`"']/)?.[1] ?? '';
      rules.set(ruleId, {
        ruleId,
        code: title.match(/^([A-Z0-9][A-Z0-9-]*-\d+):/)?.[1] ?? `RULE-${ruleId}`,
        title: title.replace(/^[A-Z0-9][A-Z0-9-]*-\d+:\s*/, ''),
        severity: after.match(/severity:\s*['"]([A-Z]+)['"]/)?.[1] ?? 'UNKNOWN',
        source,
        preciseLocation: !(onlySkipsComments || firstLineFallback),
        tested: tested.has(ruleId),
        inCatalog: catalog.ids.has(ruleId)
      });
    }
  }

  const list = [...rules.values()].sort((a, b) => a.ruleId - b.ruleId);
  const catalogOnly = [...catalog.ids].filter((id) => !rules.has(id)).sort((a, b) => a - b);
  return {
    summary: {
      implementedRules: list.length,
      testedRules: list.filter((r) => r.tested).length,
      preciseLocationRules: list.filter((r) => r.preciseLocation).length,
      catalogEntries: catalog.ids.size,
      catalogOnlyNotImplemented: catalogOnly.length,
      catalogPlaceholderMetadata: catalog.placeholder.size
    },
    catalogOnly,
    rules: list
  };
}

export function evidenceJson(audit: ReturnType<typeof auditRules>): string {
  const maturity = JSON.parse(readFileSync(join(root, 'data/rule-maturity.generated.json'), 'utf8')) as { benchmarkProven?: number[] };
  const implemented = new Set(audit.rules.map((r) => r.ruleId));
  const ids = new Set<number>([
    ...audit.rules.filter((r) => r.tested).map((r) => r.ruleId),
    ...(maturity.benchmarkProven ?? []),
    ...Object.keys(REVIEWED_TRUE_POSITIVES).map(Number)
  ]);
  return JSON.stringify({ canBlockRelease: [...ids].filter((id) => implemented.has(id)).sort((a, b) => a - b) }) + '\n';
}

export function summaryJson(audit: ReturnType<typeof auditRules>): string {
  const maturity = JSON.parse(readFileSync(join(root, 'data/rule-maturity.generated.json'), 'utf8')) as { experimental: { ruleId: number }[] };
  const experimental = new Set(maturity.experimental.map((r) => r.ruleId));
  const implemented = audit.rules.length;
  const experimentalCount = audit.rules.filter((r) => experimental.has(r.ruleId)).length;
  return JSON.stringify({
    counts: {
      implemented,
      gating: implemented - experimentalCount,
      experimental: experimentalCount,
      fixtureTested: audit.summary.testedRules,
      canBlockRelease: (JSON.parse(evidenceJson(audit)).canBlockRelease as number[]).filter((id) => !experimental.has(id)).length,
      catalogPlanned: audit.summary.catalogOnlyNotImplemented
    },
    ids: audit.rules.map((r) => r.ruleId),
    codes: audit.rules.map((r) => r.code).filter((c) => !c.startsWith('RULE-'))
  }) + '\n';
}

if (require.main === module) {
  const json = JSON.stringify(auditRules(), null, 1) + '\n';
  if (process.argv.includes('--check')) {
    const current = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
    const currentSummary = existsSync(SUMMARY_OUT) ? readFileSync(SUMMARY_OUT, 'utf8') : '';
    const currentEvidence = existsSync(EVIDENCE_OUT) ? readFileSync(EVIDENCE_OUT, 'utf8') : '';
    if (current !== json || currentSummary !== summaryJson(JSON.parse(json)) || currentEvidence !== evidenceJson(JSON.parse(json))) {
      console.error('data/rule-inventory.generated.json is stale: run `npx tsx scripts/rule-audit.ts`');
      process.exit(1);
    }
    console.log('rule inventory up to date');
  } else {
    writeFileSync(OUT, json);
    writeFileSync(EVIDENCE_OUT, evidenceJson(JSON.parse(json)));
    writeFileSync(SUMMARY_OUT, summaryJson(JSON.parse(json)));
    console.log(JSON.parse(json).summary);
  }
}
