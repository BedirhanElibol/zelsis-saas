/**
 * Measures Zelsis rules against pinned real-world repositories (scripts/benchmark/corpus.json).
 *
 *   npx tsx scripts/benchmark/run.ts
 *
 * Clones each repo at its pinned SHA into .cache/benchmark, scans it like a customer repo and
 * writes docs/benchmark/results.json: per-rule firing on clean repos (false-positive signal)
 * and recall against documented flaws in intentionally vulnerable apps.
 */
import { execSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'fs';
import { join } from 'path';
import { runStaticCodeScan, type CodeFile } from '../../lib/scanner-engine';
import { EXPECTED_FLAWS } from './expected';
import { REVIEWED_TRUE_POSITIVES } from './reviewed';

const root = join(__dirname, '../..');
const cacheDir = join(root, '.cache/benchmark');
const corpus = JSON.parse(readFileSync(join(__dirname, 'corpus.json'), 'utf8')) as {
  repos: { name: string; sha: string; kind: 'clean' | 'vulnerable'; stack: string }[];
};

const TEXT_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|py|rb|erb|go|php|twig|java|jsp|kt|cs|cshtml|razor|rs|sql|prisma|ya?ml|toml|json|tf|html|xml|gradle|env\.example|sh)$|(?:^|\/)(?:Dockerfile|Gemfile|\.zelsisignore)$/i;

function checkout(name: string, sha: string): string {
  const dir = join(cacheDir, name.replace('/', '_'));
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    execSync(`git init -q && git remote add origin https://github.com/${name}.git`, { cwd: dir });
  }
  const head = execSync('git rev-parse HEAD 2>/dev/null || true', { cwd: dir }).toString().trim();
  if (head !== sha) execSync(`git fetch -q --depth 1 origin ${sha} && git checkout -q ${sha}`, { cwd: dir, stdio: 'inherit' });
  return dir;
}

function loadFiles(dir: string): CodeFile[] {
  return execSync('git ls-files', { cwd: dir, maxBuffer: 1 << 26 }).toString().trim().split('\n')
    .filter((p) => TEXT_EXT.test(p) && !/package-lock\.json|yarn\.lock|pnpm-lock/.test(p))
    .filter((p) => { try { return statSync(join(dir, p)).size < 512_000; } catch { return false; } })
    .map((p) => ({ path: p, content: readFileSync(join(dir, p), 'utf8') }));
}

interface RuleStats { ruleId: number; title: string; severity: string; cleanRepos: string[]; cleanFindings: number; vulnerableRepos: string[] }

(async () => {
  mkdirSync(cacheDir, { recursive: true });
  const rules = new Map<number, RuleStats>();
  const repoResults: Record<string, unknown>[] = [];
  const recall: { repo: string; flaw: string; file: string; found: boolean; blocksGate: boolean; matchedBy: string[] }[] = [];

  for (const repo of corpus.repos) {
    const dir = checkout(repo.name, repo.sha);
    const files = loadFiles(dir);
    const started = Date.now();
    const result = await runStaticCodeScan(files.map((f) => ({ ...f })), repo.name);
    const ms = Date.now() - started;

    for (const f of result.findings) {
      const s = rules.get(f.ruleId) ?? { ruleId: f.ruleId, title: f.title, severity: f.severity, cleanRepos: [], cleanFindings: 0, vulnerableRepos: [] };
      if (repo.kind === 'clean') {
        s.cleanFindings++;
        if (!s.cleanRepos.includes(repo.name)) s.cleanRepos.push(repo.name);
      } else if (!s.vulnerableRepos.includes(repo.name)) {
        s.vulnerableRepos.push(repo.name);
      }
      rules.set(f.ruleId, s);
    }

    for (const flaw of EXPECTED_FLAWS.filter((e) => e.repo === repo.name)) {
      const hits = result.findings.filter((f) => f.filePath === flaw.file && flaw.match.test(f.title));
      const gatingHits = hits.filter((h) => h.maturity !== 'experimental' && (h.severity === 'CRITICAL' || h.severity === 'HIGH'));
      recall.push({ repo: repo.name, flaw: flaw.flaw, file: flaw.file, found: hits.length > 0, blocksGate: gatingHits.length > 0, matchedBy: [...new Set(hits.map((h) => `${h.title}${h.maturity === 'experimental' ? ' [experimental]' : ''}`))] });
    }

    repoResults.push({
      repo: repo.name, sha: repo.sha, kind: repo.kind, stack: repo.stack, files: files.length, scanMs: ms,
      gate: result.gateStatus, score: result.score,
      critical: result.criticalCount, high: result.highCount, medium: result.mediumCount, low: result.lowCount,
      experimental: result.experimentalCount ?? 0,
      allHighCritical: result.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length,
      detectedFramework: result.detectedFramework ?? null
    });
    console.log(`${repo.kind.padEnd(10)} ${repo.name.padEnd(48)} files=${String(files.length).padEnd(5)} gate=${result.gateStatus.padEnd(7)} crit=${result.criticalCount} high=${result.highCount}`);
  }

  const cleanCount = corpus.repos.filter((r) => r.kind === 'clean').length;
  const ruleList = [...rules.values()].sort((a, b) => b.cleanRepos.length - a.cleanRepos.length || b.cleanFindings - a.cleanFindings);
  const found = recall.filter((r) => r.found).length;
  const out = {
    generatedAt: new Date().toISOString().slice(0, 10),
    corpus: corpus.repos.map(({ name, sha, kind, stack }) => ({ name, sha, kind, stack })),
    summary: {
      cleanRepos: cleanCount,
      cleanReposGateFailed: repoResults.filter((r) => r.kind === 'clean' && r.gate === 'FAILED').length,
      cleanHighCriticalFindings: repoResults.filter((r) => r.kind === 'clean').reduce((n, r) => n + (r.allHighCritical as number), 0),
      cleanGatingHighCriticalFindings: repoResults.filter((r) => r.kind === 'clean').reduce((n, r) => n + (r.critical as number) + (r.high as number), 0),
      documentedFlaws: recall.length,
      documentedFlawsDetected: found,
      recall: recall.length ? Math.round((found / recall.length) * 100) / 100 : null,
      documentedFlawsBlockingGate: recall.filter((r) => r.blocksGate).length,
      rulesFiringOnClean: ruleList.filter((r) => r.cleanRepos.length > 0).length
    },
    repos: repoResults,
    recall,
    rules: ruleList
  };
  // Rules firing HIGH/CRITICAL on clean repos that were not reviewed as true positives become experimental
  const experimental = ruleList
    .filter((r) => r.cleanRepos.length > 0 && (r.severity === 'CRITICAL' || r.severity === 'HIGH') && !(r.ruleId in REVIEWED_TRUE_POSITIVES))
    .map((r) => ({ ruleId: r.ruleId, title: r.title, severity: r.severity, cleanRepos: r.cleanRepos.length, cleanFindings: r.cleanFindings }))
    .sort((a, b) => a.ruleId - b.ruleId);
  writeFileSync(join(root, 'data/rule-maturity.generated.json'), JSON.stringify({ generatedAt: out.generatedAt, cleanRepos: cleanCount, experimental }, null, 1) + '\n');
  (out.summary as Record<string, unknown>).experimentalRules = experimental.length;

  mkdirSync(join(root, 'docs/benchmark'), { recursive: true });
  writeFileSync(join(root, 'docs/benchmark/results.json'), JSON.stringify(out, null, 1) + '\n');
  // Compact, UI-facing copy: the landing page shows exactly these measured numbers
  writeFileSync(join(root, 'data/benchmark-summary.generated.json'), JSON.stringify({
    generatedAt: out.generatedAt,
    summary: out.summary,
    repos: repoResults.map((r) => ({ repo: r.repo, sha: String(r.sha).slice(0, 7), kind: r.kind, stack: r.stack, files: r.files, scanMs: r.scanMs, gate: r.gate, critical: r.critical, high: r.high })),
    flaws: recall.map((r) => ({ repo: r.repo, file: r.file, flaw: r.flaw, found: r.found, blocksGate: r.blocksGate }))
  }, null, 1) + '\n');
  console.log(out.summary);
})();
