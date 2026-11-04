import type { Finding } from '@/data/schema';

/**
 * One definition of "how many findings" for every screen, export and API answer.
 * Verified: open findings from rules proven precise. Suggestions: open findings from experimental or
 * unproven rules; they are listed, but never counted as risks, scored as blockers or allowed to move the gate.
 */
export const isSuggestion = (f: Finding | null | undefined): boolean =>
  f?.maturity === 'experimental' || f?.maturity === 'unproven';

export const openFindings = (findings: readonly (Finding | null | undefined)[] | null | undefined): Finding[] =>
  (Array.isArray(findings) ? findings : []).filter((f): f is Finding => Boolean(f) && f!.status === 'OPEN');

export const verifiedFindings = (findings: readonly (Finding | null | undefined)[] | null | undefined): Finding[] =>
  openFindings(findings).filter((f) => !isSuggestion(f));

export const suggestionFindings = (findings: readonly (Finding | null | undefined)[] | null | undefined): Finding[] =>
  openFindings(findings).filter(isSuggestion);

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export function severityCounts(list: readonly Finding[]): SeverityCounts {
  const c = { critical: 0, high: 0, medium: 0, low: 0, total: list.length };
  for (const f of list) {
    if (f.severity === 'CRITICAL') c.critical++;
    else if (f.severity === 'HIGH') c.high++;
    else if (f.severity === 'MEDIUM') c.medium++;
    else c.low++;
  }
  return c;
}

/** Security, infrastructure and legal findings: the ones a release gate is about. */
export const isRiskType = (f: Finding): boolean =>
  f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE';

export const isUiType = (f: Finding): boolean => f.type === 'VIBEPOLISH';

export interface FindingSummary {
  verified: SeverityCounts;
  suggestions: SeverityCounts;
  /** Verified security / infra / legal findings at Critical or High: what "open risks" means everywhere. */
  openRisks: number;
  verifiedUi: number;
  suggestionUi: number;
}

export function summarizeFindings(findings: readonly (Finding | null | undefined)[] | null | undefined): FindingSummary {
  const verified = verifiedFindings(findings);
  const suggestions = suggestionFindings(findings);
  return {
    verified: severityCounts(verified),
    suggestions: severityCounts(suggestions),
    openRisks: verified.filter((f) => isRiskType(f) && (f.severity === 'CRITICAL' || f.severity === 'HIGH')).length,
    verifiedUi: verified.filter(isUiType).length,
    suggestionUi: suggestions.filter(isUiType).length,
  };
}
