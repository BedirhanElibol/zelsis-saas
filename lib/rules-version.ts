import version from '@/data/rules-version.generated.json';

/** Day the detection rules last changed (written by scripts/rule-audit.ts). Scans before it may show outdated results. */
export const RULES_UPDATED_AT: string = version.updatedAt;

/** True when the project's findings come from a scan older than the current rules, or from a scan without a date. */
export function isScanOutdated(p: { findings?: unknown[]; lastScanIso?: string }): boolean {
  if (!Array.isArray(p.findings) || p.findings.length === 0) return false;
  if (!p.lastScanIso) return true;
  return p.lastScanIso.slice(0, 10) < RULES_UPDATED_AT;
}
