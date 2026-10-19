import { randomBytes } from 'crypto';
import { RISK_LABEL, riskKind, type RiskKind } from '@/lib/scanner/risk-kind';

/**
 * Public trust pages (/verified/<slug>): what a project owner can show customers. Built from the latest scan,
 * but only aggregate facts leave the server: date, gate, score and how many open issues each risk area has.
 * No titles, files, lines or code, because the repository may be private and the issues may be unfixed.
 */

export const TRUST_MAX_AGE_DAYS = 30;
const RISK_ORDER: RiskKind[] = ['DATA_LEAK', 'FINANCIAL', 'ACCOUNT_TAKEOVER', 'CODE_EXECUTION', 'DOWNTIME'];

export type TrustStatus = 'verified' | 'issues-open' | 'stale';

export interface TrustSummary {
  status: TrustStatus;
  scannedAt: string;
  score: number;
  /** Open CRITICAL / HIGH findings: what stands between the project and a verified page. */
  blockers: number;
  areas: { kind: RiskKind; label: string; open: number }[];
}

/** `Acme Billing` -> `acme-billing-k3x9q2` (the suffix keeps slugs unguessable and unique). */
export function trustSlug(name: string): string {
  const base = name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'project';
  const suffix = randomBytes(4).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6).padEnd(6, '0');
  return `${base}-${suffix}`;
}

export const isTrustSlug = (s: string) => /^[a-z0-9][a-z0-9-]{2,62}$/.test(s);

type RawFinding = { ruleId?: number; severity?: string; status?: string; maturity?: string; falsePositive?: boolean; category?: string; type?: string; risk?: string };

/** Summary for the public page from a stored scan result; null when the result cannot be read. */
export function toTrustSummary(resultData: unknown, scannedAt: string, now = Date.now()): TrustSummary | null {
  if (!resultData || typeof resultData !== 'object') return null;
  const r = resultData as { score?: unknown; findings?: unknown };
  if (typeof r.score !== 'number') return null;
  const findings = (Array.isArray(r.findings) ? r.findings : []) as RawFinding[];
  const open = findings.filter((f) => f && !f.falsePositive && (f.status ?? 'OPEN') === 'OPEN' && f.maturity !== 'experimental');
  // Unproven CRITICAL counts as HIGH (like the gate); both still block a verified page
  const serious = open.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const counts = new Map<RiskKind, number>();
  for (const f of serious) {
    const kind = (f.risk as RiskKind | undefined) ?? riskKind({ ruleId: f.ruleId ?? 0, category: f.category, type: f.type });
    if (kind) counts.set(kind, (counts.get(kind) ?? 0) + 1);
  }
  const ageDays = (now - Date.parse(scannedAt)) / 86_400_000;
  const status: TrustStatus = ageDays > TRUST_MAX_AGE_DAYS ? 'stale' : serious.length > 0 ? 'issues-open' : 'verified';
  return {
    status,
    scannedAt,
    score: Math.max(0, Math.min(100, Math.round(r.score))),
    blockers: serious.length,
    areas: RISK_ORDER.map((kind) => ({ kind, label: RISK_LABEL[kind], open: counts.get(kind) ?? 0 })),
  };
}
