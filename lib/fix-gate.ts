import type { ScanResult } from './scanner-engine';

/** Lifetime number of fixes a Free account can reveal. */
export const FREE_FIX_TRIAL_LIMIT = 1;

export const LOCKED_FIX_TEXT = 'Fix guidance is included in Zelsis Pro.';

export interface StoredFix {
  remediationPrompt: string;
  diffPatch?: string;
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
