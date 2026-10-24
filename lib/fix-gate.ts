import type { ScanResult } from './scanner-engine';

/** Lifetime number of fixes a Free account can reveal. */
export const FREE_FIX_TRIAL_LIMIT = 1;

export const LOCKED_FIX_TEXT = 'Fix guidance is included in Zelsis Pro.';

export interface StoredFix {
  remediationPrompt: string;
  diffPatch?: string;
  /** Location withheld from a Free private-repo result (see lockFindingLocations). */
  location?: { filePath: string; lineRange?: string; snippet?: string; reproductionSteps?: string[] };
}

/**
 * Removes fix text (remediation prompts and diff patches) from a scan result.
 * Each finding gets a `lockedFix` reference; the returned `fixes` map (keyed by
 * that ref) is stored server-side so the Free trial or a later upgrade can reveal it.
 */
export function redactScanResultFixes(
  result: ScanResult,
  jobId: string
): { result: ScanResult; fixes: Record<string, StoredFix> } {
  const fixes: Record<string, StoredFix> = {};
  const findings = result.findings.map((finding, index) => {
    const ref = String(index);
    fixes[ref] = {
      remediationPrompt: finding.remediationPrompt,
      ...(finding.diffPatch ? { diffPatch: finding.diffPatch } : {})
    };
    const { diffPatch: _omitted, ...rest } = finding;
    return { ...rest, remediationPrompt: LOCKED_FIX_TEXT, lockedFix: { jobId, ref } };
  });
  return { result: { ...result, findings }, fixes };
}

const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/** `app/api/pay/route.ts` -> `app/api/pay/` (the folder is shown, the file is not). */
export function folderOf(filePath: string): string {
  const i = filePath.lastIndexOf('/');
  return i === -1 ? './' : filePath.slice(0, i + 1);
}

/**
 * Free plan on a private repository: the most severe open finding stays fully visible, so the user can judge the
 * engine on their own code. Every other CRITICAL / HIGH finding keeps its title, risk, impact and folder, but
 * its file, line and snippet are removed from the stored result. The removed location goes into `fixes` (by the
 * same ref as lockedFix), which only the service role can read.
 */
export function lockFindingLocations(
  result: ScanResult,
  fixes: Record<string, StoredFix>
): { result: ScanResult; lockedCount: number } {
  const serious = result.findings
    .map((f, i) => ({ f, i }))
    .filter(({ f }) => f.status === 'OPEN' && (f.severity === 'CRITICAL' || f.severity === 'HIGH'))
    .sort((a, b) => (RANK[a.f.severity] ?? 9) - (RANK[b.f.severity] ?? 9));
  const keepOpen = serious[0]?.i;
  const toLock = new Set(serious.slice(1).map(({ i }) => i));
  const findings = result.findings.map((finding, index) => {
    if (!toLock.has(index) || index === keepOpen) return finding;
    const ref = finding.lockedFix?.ref ?? String(index);
    fixes[ref] = {
      ...(fixes[ref] ?? { remediationPrompt: finding.remediationPrompt }),
      location: { filePath: finding.filePath, lineRange: finding.lineRange, snippet: finding.snippet, reproductionSteps: finding.reproductionSteps },
    };
    return { ...finding, filePath: folderOf(finding.filePath), lineRange: '', snippet: '', reproductionSteps: [], lockedLocation: true };
  });
  return { result: { ...result, findings }, lockedCount: toLock.size };
}
