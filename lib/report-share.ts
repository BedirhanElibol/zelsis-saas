import { randomBytes } from 'crypto';

/**
 * Read-only report links (/r/<token>). The token is the only credential, so it carries 256 random bits.
 * The public report never includes code snippets, diffs, reproduction steps or fix prompts: the repository
 * may be private, and those fields quote its code.
 */

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/** 32 random bytes, base64url (43 characters). */
export function createShareToken(): string {
  return randomBytes(32).toString('base64url');
}

export function isShareToken(value: string): boolean {
  return TOKEN_RE.test(value);
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface PublicFinding {
  title: string;
  severity: Severity;
  category: string;
  filePath: string;
  lineRange: string;
}

export interface PublicReport {
  target: string;
  scannedAt: string;
  score: number;
  gateStatus: 'PASSED' | 'WARNING' | 'FAILED';
  counts: Record<Severity, number>;
  findings: PublicFinding[];
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const isSeverity = (s: unknown): s is Severity => typeof s === 'string' && (SEVERITY_ORDER as string[]).includes(s);
const str = (v: unknown, max = 300): string => (typeof v === 'string' ? v.slice(0, max) : '');

/** Owner/name for GitHub URLs, the hostname for sites, so the page never echoes tokens or query strings. */
export function displayTarget(repoUrl: string): string {
  const gh = /github\.com[/:]([\w.-]+\/[\w.-]+?)(?:\.git)?(?:[/?#]|$)/i.exec(repoUrl);
  if (gh) return gh[1];
  try {
    return new URL(/^https?:\/\//i.test(repoUrl) ? repoUrl : `https://${repoUrl}`).hostname;
  } catch {
    return 'Repository';
  }
}

/**
 * The shareable view of a stored scan result: open, non-false-positive findings with title, severity,
 * category and location only, most severe first.
 */
export function toPublicReport(resultData: unknown, repoUrl: string, scannedAt: string): PublicReport | null {
  if (!resultData || typeof resultData !== 'object') return null;
  const r = resultData as Record<string, unknown>;
  const gate = r.gateStatus;
  if (typeof r.score !== 'number' || (gate !== 'PASSED' && gate !== 'WARNING' && gate !== 'FAILED')) return null;
  const raw = Array.isArray(r.findings) ? (r.findings as Record<string, unknown>[]) : [];
  const findings: PublicFinding[] = raw
    .filter((f) => f && !f.falsePositive && (f.status ?? 'OPEN') === 'OPEN' && f.maturity !== 'experimental' && isSeverity(f.severity))
    .map((f) => ({
      title: str(f.title),
      severity: f.severity as Severity,
      category: str(f.category, 80),
      filePath: str(f.filePath, 300),
      lineRange: str(f.lineRange, 40),
    }))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return { target: displayTarget(repoUrl), scannedAt, score: Math.max(0, Math.min(100, Math.round(r.score))), gateStatus: gate, counts, findings };
}
