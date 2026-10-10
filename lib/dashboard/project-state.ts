import type { Finding, Project } from '@/data/schema';
import { calculateGateStatus, calculateReadinessScore, gatingFindings } from '@/lib/scanner/scoring';
import { UNDETECTED_FRAMEWORK } from '@/lib/scanner/stack-detect';

const LOCAL_AUDIT_PROJECT_IDS = new Set(['proj-zelsis-self', 'proj-shipguard-self']);

export const isLocalAuditProject = (p: Pick<Project, 'id' | 'repoUrl'>): boolean =>
  p.repoUrl === 'local' || LOCAL_AUDIT_PROJECT_IDS.has(p.id);

/** Returns the project with its findings replaced and gate, score and open counts recomputed. */
export function withRecalculatedFindings(proj: Project, findings: Finding[]): Project {
  // Same basis as the scanner: open findings from gating (non-experimental) rules
  const gating = gatingFindings(findings);
  const openCount = (match: (f: Finding) => boolean) => gating.filter(match).length;
  return {
    ...proj,
    findings,
    gateStatus: calculateGateStatus(findings),
    readinessScore: calculateReadinessScore(findings),
    criticalCount: openCount((f) => f.severity === 'CRITICAL'),
    highCount: openCount((f) => f.severity === 'HIGH'),
    mediumCount: openCount((f) => f.severity === 'MEDIUM'),
    lowCount: openCount((f) => f.severity === 'LOW'),
    uiClicheCount: openCount((f) => f.type === 'VIBEPOLISH')
  };
}

/**
 * Applies `update` to every finding matching `isTarget`. Projects without a matching finding
 * are returned unchanged (same reference); the others get recalculated stats.
 */
export function updateMatchingFindings(
  projects: Project[],
  isTarget: (f: Finding) => boolean,
  update: (f: Finding) => Finding
): Project[] {
  return projects.map((proj) => {
    const findings = proj.findings ?? [];
    if (!findings.some(isTarget)) return proj;
    return withRecalculatedFindings(proj, findings.map((f) => (isTarget(f) ? update(f) : f)));
  });
}

const findingKey = (f: Finding) => `${f.ruleId}|${f.filePath}|${f.title}`;

/**
 * Brings a project stored on this device up to date with the account's cloud copy when the cloud
 * scanned it more recently (another device, a teammate, the weekly rescan). Findings the user
 * triaged here (resolved / accepted risk) keep that status.
 */
export function refreshFromCloud(local: Project, cloud: Project): Project {
  const cloudAt = Date.parse(cloud.lastScanIso ?? '');
  if (!Number.isFinite(cloudAt)) return local;
  const localAt = Date.parse(local.lastScanIso ?? '');
  if (Number.isFinite(localAt) && localAt >= cloudAt) return local;
  // A summary without its findings (scan job pruned) would wipe the detail kept here
  const cloudOpen = cloud.criticalCount + cloud.highCount + cloud.mediumCount + cloud.lowCount;
  if (cloud.findings.length === 0 && cloudOpen > 0) return local;

  const triaged = new Map(local.findings.filter((f) => f.status !== 'OPEN').map((f) => [findingKey(f), f.status] as const));
  const findings = cloud.findings.map((f) => {
    const status = triaged.get(findingKey(f));
    return status ? { ...f, status } : f;
  });
  const merged: Project = {
    ...local,
    lastScanAt: cloud.lastScanAt,
    lastScanIso: cloud.lastScanIso,
    isPrivate: cloud.isPrivate ?? local.isPrivate,
    readinessScore: cloud.readinessScore,
    gateStatus: cloud.gateStatus,
    criticalCount: cloud.criticalCount,
    highCount: cloud.highCount,
    mediumCount: cloud.mediumCount,
    lowCount: cloud.lowCount,
    uiClicheCount: cloud.uiClicheCount,
    findings,
  };
  return findings.some((f) => triaged.has(findingKey(f))) ? withRecalculatedFindings(merged, findings) : merged;
}

/** Last project in `next` that changed relative to `prev` and has the given id. */
export function findUpdatedProject(prev: Project[], next: Project[], projectId: string): Project | null {
  let updated: Project | null = null;
  next.forEach((p, i) => {
    if (p !== prev[i] && p.id === projectId) updated = p;
  });
  return updated;
}

/** Fills missing or placeholder fields of a project loaded from storage or the UI. */
export function normalizeProject(p: Project, fallback: Project): Project {
  const cleanRepoUrl = typeof p.repoUrl === 'string' && p.repoUrl.trim() && p.repoUrl !== 'undefined'
    ? p.repoUrl.trim()
    : fallback.repoUrl;
  const cleanName = typeof p.name === 'string' && p.name.trim() && p.name !== 'undefined'
    ? p.name.trim()
    : (cleanRepoUrl ? cleanRepoUrl.split('/').pop() || 'Target Repository' : fallback.name);

  return {
    ...p,
    id: p.id || `proj-${Date.now()}`,
    name: cleanName,
    repoUrl: cleanRepoUrl,
    framework: p.framework || UNDETECTED_FRAMEWORK,
    providers: Array.isArray(p.providers) ? p.providers : [],
    lastScanAt: p.lastScanAt || (Array.isArray(p.findings) && p.findings.length ? 'Earlier scan (date unknown)' : 'Never audited'),
    readinessScore: typeof p.readinessScore === 'number' ? p.readinessScore : 100,
    gateStatus: p.gateStatus || 'PASSED',
    criticalCount: typeof p.criticalCount === 'number' ? p.criticalCount : 0,
    highCount: typeof p.highCount === 'number' ? p.highCount : 0,
    mediumCount: typeof p.mediumCount === 'number' ? p.mediumCount : 0,
    lowCount: typeof p.lowCount === 'number' ? p.lowCount : 0,
    uiClicheCount: typeof p.uiClicheCount === 'number' ? p.uiClicheCount : 0,
    findings: Array.isArray(p.findings) ? p.findings : []
  };
}

/**
 * Strips tokens and trims findings so the project list fits in localStorage.
 * `compact` keeps only the fields the dashboard needs, for when the full form exceeds the quota.
 */
export function serializeProjectsForStorage(projects: Project[], allowLocalAudit: boolean, compact: boolean): string {
  const sanitized = allowLocalAudit ? projects : projects.filter((p) => !isLocalAuditProject(p));
  const stored = sanitized.map((p) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { githubToken, ...safeProject } = p;
    const findings = compact
      ? (p.findings ?? []).slice(0, 20).map((f) => ({
          id: f.id,
          ruleId: f.ruleId,
          type: f.type,
          title: f.title,
          severity: f.severity,
          filePath: f.filePath,
          status: f.status
        }))
      : (p.findings ?? []).slice(0, 60).map((f) => ({
          ...f,
          snippet: typeof f.snippet === 'string' && f.snippet.length > 150 ? f.snippet.slice(0, 150) + '...' : f.snippet,
          reproductionSteps: Array.isArray(f.reproductionSteps) ? f.reproductionSteps.slice(0, 1) : []
        }));
    return { ...safeProject, findings };
  });
  return JSON.stringify(stored);
}

/** One key per repository: "owner/repo", "https://github.com/owner/repo/" and "...repo.git" are the same project. */
export function repoKey(url?: string): string {
  return (url || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/^github\.com\//, '')
    .replace(/\.git$/, '').replace(/\/+$/, '');
}

/** Collapses projects that point at the same repository, keeping the one with the most recent scan and findings. */
export function dedupeProjects(projects: Project[]): Project[] {
  const rank = (p: Project) => [Array.isArray(p.findings) && p.findings.length > 0 ? 1 : 0, p.lastScanIso || ""] as const;
  const byKey = new Map<string, Project>();
  const order: string[] = [];
  for (const p of projects) {
    const key = isLocalAuditProject(p) || !p.repoUrl ? `id:${p.id}` : repoKey(p.repoUrl);
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, p); order.push(key); continue; }
    const [pf, pd] = rank(p);
    const [qf, qd] = rank(prev);
    if (pf > qf || (pf === qf && pd > qd)) byKey.set(key, p);
  }
  return order.map((k) => byKey.get(k)!);
}
