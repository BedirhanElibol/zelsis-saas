import type { Finding } from '@/data/schema';
import type { Dependency } from './dependencies';

/**
 * Known-vulnerability lookup for resolved dependencies against OSV.dev (GitHub Advisory Database,
 * PyPA, RustSec, Go, RubyGems and other sources). Every finding cites real advisory IDs.
 */

export const OSV_RULE_ID = 26001;
const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 10;

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface OsvAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  /** Lowest version that fixes this advisory for the queried package, when OSV lists one. */
  fixed?: string;
}

export interface DependencyAuditSummary {
  status: 'ok' | 'unavailable' | 'no-dependencies' | 'disabled';
  packages: number;
  vulnerablePackages: number;
  advisories: number;
  error?: string;
}

export interface OsvOptions {
  fetchImpl?: typeof fetch;
  /** Total time budget for all OSV requests. */
  timeoutMs?: number;
  /** Advisory detail lookups are capped; advisories beyond the cap are reported by ID with MEDIUM severity. */
  maxDetails?: number;
}

interface OsvVulnJson {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  withdrawn?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    severity?: { type: string; score: string }[];
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
}

const SEVERITY_RANK: Record<Severity, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/** CVSS v3.x base score from a vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). */
export function cvss3BaseScore(vector: string): number | null {
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV as 'N'];
  const AC = { L: 0.77, H: 0.44 }[m.AC as 'L'];
  const UI = { N: 0.85, R: 0.62 }[m.UI as 'N'];
  const changed = m.S === 'C';
  const PR = changed ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR as 'N'] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR as 'N'];
  const cia = (k: string) => ({ H: 0.56, L: 0.22, N: 0 } as Record<string, number>)[m[k]];
  const [C, I, A] = [cia('C'), cia('I'), cia('A')];
  if ([AV, AC, UI, PR, C, I, A].some((v) => v === undefined) || !/^CVSS:3/.test(vector)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  const raw = changed ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(raw * 10 - 1e-9) / 10;
}

const scoreToSeverity = (score: number): Severity =>
  score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';

function advisorySeverity(v: OsvVulnJson): Severity {
  const label = v.database_specific?.severity?.toUpperCase();
  if (label === 'CRITICAL' || label === 'HIGH' || label === 'LOW') return label;
  if (label === 'MODERATE' || label === 'MEDIUM') return 'MEDIUM';
  const vectors = [...(v.severity ?? []), ...(v.affected ?? []).flatMap((a) => a.severity ?? [])];
  for (const s of vectors) {
    if (s.type === 'CVSS_V3') {
      const score = cvss3BaseScore(s.score);
      if (score !== null) return scoreToSeverity(score);
    }
  }
  return 'MEDIUM';
}

/** Compares dotted versions numerically segment by segment (good enough to pick the highest fix). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/);
  const pb = b.split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) { if (nx !== ny) return nx - ny; }
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function fixedVersionFor(v: OsvVulnJson, dep: Dependency): string | undefined {
  const fixes = (v.affected ?? [])
    .filter((a) => a.package?.name?.toLowerCase() === dep.name.toLowerCase())
    .flatMap((a) => a.ranges ?? [])
    .flatMap((r) => r.events ?? [])
    .map((e) => e.fixed)
    .filter((f): f is string => Boolean(f))
    .filter((f) => compareVersions(f, dep.version) > 0)
    .sort(compareVersions);
  return fixes[0];
}

async function runPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * Looks up every dependency in OSV.dev. Returns advisories per dependency index, or an error
 * when OSV could not be reached (the caller reports the audit as unavailable, never as clean).
 */
export async function queryOsv(
  deps: Dependency[],
  { fetchImpl = globalThis.fetch, timeoutMs = 15000, maxDetails = 200 }: OsvOptions = {}
): Promise<{ ok: true; advisories: OsvAdvisory[][] } | { ok: false; error: string }> {
  if (!fetchImpl) return { ok: false, error: 'fetch is not available in this runtime' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const idsPerDep: string[][] = [];
    for (let i = 0; i < deps.length; i += BATCH_SIZE) {
      const chunk = deps.slice(i, i + BATCH_SIZE);
      const res = await fetchImpl(`${OSV_API}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
        signal: controller.signal
      });
      if (!res.ok) return { ok: false, error: `OSV querybatch returned HTTP ${res.status}` };
      const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
      chunk.forEach((_, j) => idsPerDep.push((data.results?.[j]?.vulns ?? []).map((v) => v.id)));
    }

    const uniqueIds = [...new Set(idsPerDep.flat())];
    const detailIds = uniqueIds.slice(0, maxDetails);
    const details = new Map<string, OsvVulnJson>();
    await runPool(detailIds, DETAIL_CONCURRENCY, async (id) => {
      const res = await fetchImpl(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal: controller.signal });
      if (res.ok) details.set(id, (await res.json()) as OsvVulnJson);
    });

    const advisories = idsPerDep.map((ids, i) =>
      ids.flatMap((id): OsvAdvisory[] => {
        const v = details.get(id);
        if (!v) return [{ id, aliases: [], summary: 'See advisory for details', severity: 'MEDIUM' }];
        if (v.withdrawn) return [];
        return [{
          id,
          aliases: v.aliases ?? [],
          summary: (v.summary || v.details || 'See advisory for details').split('\n')[0].slice(0, 200),
          severity: advisorySeverity(v),
          fixed: fixedVersionFor(v, deps[i])
        }];
      })
    );
    return { ok: true, advisories };
  } catch (err) {
    return { ok: false, error: controller.signal.aborted ? `OSV lookup timed out after ${timeoutMs}ms` : (err as Error)?.message || 'OSV lookup failed' };
  } finally {
    clearTimeout(timer);
  }
}

const advisoryLabel = (a: OsvAdvisory) => a.aliases.find((x) => x.startsWith('CVE-')) ?? a.id;

/** One finding per vulnerable package version, at its lockfile line. Dev-only packages are capped at MEDIUM. */
export function buildDependencyFindings(deps: Dependency[], advisories: OsvAdvisory[][], fileLines: Map<string, string[]>): Finding[] {
  const findings: Finding[] = [];
  deps.forEach((dep, i) => {
    const list = advisories[i] ?? [];
    if (list.length === 0) return;
    const worst = list.reduce<Severity>((s, a) => (SEVERITY_RANK[a.severity] > SEVERITY_RANK[s] ? a.severity : s), 'LOW');
    const severity: Severity = dep.dev && SEVERITY_RANK[worst] > SEVERITY_RANK.MEDIUM ? 'MEDIUM' : worst;
    const fixes = list.map((a) => a.fixed).filter((f): f is string => Boolean(f)).sort(compareVersions);
    const target = fixes[fixes.length - 1];
    const labels = [...new Set(list.map(advisoryLabel))];
    const shown = labels.slice(0, 3).join(', ') + (labels.length > 3 ? ` +${labels.length - 3} more` : '');
    findings.push({
      id: `osv-${dep.ecosystem}-${dep.name}-${dep.version}-${i}`,
      ruleId: 26001,
      type: 'SECURITY',
      title: `DEP-01: ${dep.name}@${dep.version} has ${list.length} known vulnerabilit${list.length === 1 ? 'y' : 'ies'} (${shown})`,
      severity,
      category: 'Dependency Vulnerabilities (OSV.dev)',
      filePath: dep.file,
      lineRange: `L${dep.line}`,
      snippet: (fileLines.get(dep.file)?.[dep.line - 1] ?? `${dep.name}@${dep.version}`).trim().slice(0, 300),
      reproductionSteps: [
        `${dep.ecosystem} package ${dep.name} resolves to ${dep.version} in ${dep.file}:${dep.line}${dep.dev ? ' (development dependency: not shipped, capped at MEDIUM)' : ''}.`,
        ...list.slice(0, 10).map((a) => `${a.id}${a.aliases.length ? ` (${a.aliases.join(', ')})` : ''} [${a.severity}]: ${a.summary}${a.fixed ? ` Fixed in ${a.fixed}.` : ' No fixed version listed.'} https://osv.dev/vulnerability/${a.id}`),
        ...(list.length > 10 ? [`${list.length - 10} more advisories on https://osv.dev/list?q=${encodeURIComponent(dep.name)}`] : [])
      ],
      remediationPrompt: target
        ? `Upgrade ${dep.name} from ${dep.version} to ${target} or later (the highest fixed version across its advisories), regenerate the lockfile, and re-run the tests. If it is a transitive dependency, upgrade the direct dependency that pulls it in or add an override/resolution.`
        : `No fixed release of ${dep.name} is listed for these advisories. Check whether the vulnerable code path is reachable, replace the package, or accept the risk explicitly.`,
      status: 'OPEN',
      falsePositive: false
    });
  });
  return findings;
}
