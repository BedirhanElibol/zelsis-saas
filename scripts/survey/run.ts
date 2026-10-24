/**
 * Bulk survey of public repositories for anonymous statistics and responsible disclosure.
 *
 *   npx tsx scripts/survey/run.ts select <out.txt>     pick repositories with gh search (needs gh auth)
 *   npx tsx scripts/survey/run.ts scan <list.txt>      clone each at HEAD (shallow), scan, write results
 *
 * Output goes to .cache/survey/<date>/ only (git-ignored): results.json holds per-repository findings for the
 * disclosure drafts and must never be committed or published while issues are unfixed; stats.json is anonymous.
 * Counts use the gate's own view (gating findings, gate severity), so unproven or experimental rules cannot
 * inflate the published numbers.
 */
import { execSync, spawnSync } from 'child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'fs';
import { join } from 'path';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { isScannableTreePath } from '../../lib/scanner/scan-paths';
import { gatingFindings, gateSeverity } from '../../lib/scanner/scoring';
import { riskKind } from '../../lib/scanner/risk-kind';

const root = join(__dirname, '../..');
const day = new Date().toISOString().slice(0, 10);
const outDir = join(root, '.cache/survey', day);
const cloneDir = join(root, '.cache/survey/repos');

/** Search queries: apps and SaaS products across stacks, not libraries or tutorials. */
const QUERIES = [
  'topic:saas', 'topic:saas-boilerplate', 'topic:saas-starter', 'topic:supabase topic:nextjs', 'topic:stripe topic:nextjs',
  'topic:ai-saas', 'topic:fastapi topic:saas', 'topic:django topic:saas', 'topic:laravel topic:saas', 'topic:rails topic:saas',
  'topic:express topic:stripe', 'topic:nestjs topic:saas', 'topic:supabase topic:react',
];

function select(outFile: string) {
  const seen = new Set<string>();
  for (const q of QUERIES) {
    const json = execSync(`gh search repos "${q}" --stars ">=20" --updated ">=2025-10-01" --archived=false --limit 40 --json fullName,isFork`, { cwd: root }).toString();
    for (const r of JSON.parse(json) as { fullName: string; isFork: boolean }[]) if (!r.isFork) seen.add(r.fullName);
  }
  writeFileSync(outFile, [...seen].sort().join('\n') + '\n');
  console.log(`${seen.size} repositories -> ${outFile}`);
}

interface RepoResult {
  repo: string; sha: string; files: number; framework: string | null; gate: string;
  gatingCritical: number; gatingHigh: number;
  findings: { ruleId: number; title: string; severity: string; risk: string | null; file: string; line: string; snippet: string }[];
}

/** Scan one repository (run in a child process so a slow repository can be timed out). */
async function scanOne(name: string): Promise<RepoResult | string> {
  const dir = join(cloneDir, name.replace('/', '_'));
  try {
    if (!existsSync(dir)) execSync(`git clone -q --depth 1 https://github.com/${name}.git "${dir}"`, { stdio: 'ignore', timeout: 120_000 });
  } catch { return 'clone failed'; }
  const files = execSync('git ls-files', { cwd: dir, maxBuffer: 1 << 26 }).toString().trim().split('\n')
    .filter((p) => isScannableTreePath(p) && !/package-lock\.json|yarn\.lock|pnpm-lock/.test(p))
    .filter((p) => { try { return statSync(join(dir, p)).size < 512_000; } catch { return false; } })
    .map((p) => ({ path: p, content: readFileSync(join(dir, p), 'utf8') }));
  if (files.length === 0) return 'no scannable files';
  const r = await runStaticCodeScan(files, name, { dependencyAudit: false });
  const gating = gatingFindings(r.findings).filter((f) => f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE');
  const serious = gating.filter((f) => gateSeverity(f) === 'CRITICAL' || gateSeverity(f) === 'HIGH');
  const sha = execSync('git rev-parse HEAD', { cwd: dir }).toString().trim();
  return {
    repo: name, sha, files: files.length, framework: r.detectedFramework ?? null, gate: r.gateStatus,
    gatingCritical: serious.filter((f) => gateSeverity(f) === 'CRITICAL').length,
    gatingHigh: serious.filter((f) => gateSeverity(f) === 'HIGH').length,
    findings: serious.map((f) => ({
      ruleId: f.ruleId, title: f.title, severity: gateSeverity(f), risk: f.risk ?? riskKind({ ruleId: f.ruleId, category: f.category, type: f.type }) ?? null,
      file: f.filePath, line: f.lineRange, snippet: String(f.snippet ?? '').replace(/\s+/g, ' ').slice(0, 160),
    })),
  };
}

/** Each repository runs in its own process with a time limit; finished ones go to results.jsonl so a rerun resumes. */
async function scan(listFile: string) {
  mkdirSync(outDir, { recursive: true });
  mkdirSync(cloneDir, { recursive: true });
  const repos = readFileSync(listFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  const progress = join(outDir, 'results.jsonl');
  const results: RepoResult[] = existsSync(progress)
    ? readFileSync(progress, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as RepoResult) : [];
  const done = new Set(results.map((r) => r.repo));
  for (const name of repos) {
    if (done.has(name)) continue;
    const child = spawnSync(process.execPath, [...process.execArgv, __filename, 'one', name], {
      cwd: root, timeout: 10 * 60_000, maxBuffer: 1 << 28, encoding: 'utf8',
    });
    if (child.error || child.status !== 0) { console.log(`skip ${name}: ${child.error ? 'timed out' : 'scan failed'}`); continue; }
    const out = JSON.parse(child.stdout.trim().split('\n').at(-1) ?? '""') as RepoResult | string;
    if (typeof out === 'string') { console.log(`skip ${name}: ${out}`); continue; }
    results.push(out);
    appendFileSync(progress, JSON.stringify(out) + '\n');
    console.log(`${name.padEnd(50)} files=${String(out.files).padEnd(5)} gate=${out.gate.padEnd(7)} crit=${out.gatingCritical} high=${out.gatingHigh}`);
  }
  writeFileSync(join(outDir, 'results.json'), JSON.stringify(results, null, 1));
  writeFileSync(join(outDir, 'stats.json'), JSON.stringify(stats(results), null, 1));
  console.log(`\n${results.length} scanned -> ${outDir} (results.json is private; stats.json is anonymous)`);
}

/** Anonymous aggregate: share of repositories with each kind of issue. No names, files or snippets. */
function stats(results: RepoResult[]) {
  const n = results.length;
  const pct = (k: number) => Math.round((1000 * k) / Math.max(n, 1)) / 10;
  const byRule = new Map<number, { title: string; repos: number }>();
  const byRisk = new Map<string, number>();
  for (const r of results) {
    for (const ruleId of new Set(r.findings.map((f) => f.ruleId))) {
      const f = r.findings.find((x) => x.ruleId === ruleId)!;
      const e = byRule.get(ruleId) ?? { title: f.title, repos: 0 };
      e.repos++;
      byRule.set(ruleId, e);
    }
    for (const risk of new Set(r.findings.map((f) => f.risk).filter(Boolean) as string[])) byRisk.set(risk, (byRisk.get(risk) ?? 0) + 1);
  }
  return {
    date: day,
    repositories: n,
    withBlockingCritical: { repos: results.filter((r) => r.gatingCritical > 0).length, pct: pct(results.filter((r) => r.gatingCritical > 0).length) },
    withHighOrCritical: { repos: results.filter((r) => r.gatingCritical + r.gatingHigh > 0).length, pct: pct(results.filter((r) => r.gatingCritical + r.gatingHigh > 0).length) },
    byRisk: Object.fromEntries([...byRisk].sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, { repos: v, pct: pct(v) }])),
    topRules: [...byRule].sort((a, b) => b[1].repos - a[1].repos).slice(0, 15).map(([ruleId, e]) => ({ ruleId, title: e.title, repos: e.repos, pct: pct(e.repos) })),
    note: 'Automated findings before manual review. Counts only rules that can fail the gate, at gate severity.',
  };
}

const [cmd, arg] = process.argv.slice(2);
if (cmd === 'select' && arg) select(arg);
else if (cmd === 'scan' && arg) scan(arg).catch((e) => { console.error(e); process.exit(1); });
else if (cmd === 'one' && arg) scanOne(arg).then((r) => console.log(JSON.stringify(r))).catch((e) => { console.error(e); process.exit(1); });
else { console.error('usage: run.ts select <out.txt> | scan <list.txt>'); process.exit(2); }
