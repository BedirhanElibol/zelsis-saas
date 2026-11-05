/** Columns every scan reads from finding_dismissals. */
export const DISMISSAL_COLUMNS = 'rule_id, file_path, expires_at';

export interface DismissalRow { rule_id: number; file_path: string; expires_at?: string | null }

/**
 * Dismissals still in force: an accepted risk with an end date stops counting once that date passes,
 * so the finding opens again on the next scan. Rows without an end date never expire.
 */
export function activeDismissals(rows: DismissalRow[] | null | undefined, now: Date = new Date()): { ruleId: number; filePath: string }[] {
  return (rows ?? [])
    .filter((r) => !r.expires_at || new Date(r.expires_at).getTime() > now.getTime())
    .map((r) => ({ ruleId: r.rule_id, filePath: r.file_path }));
}

/** End date for a new dismissal: accepted risks default to 90 days, false positives and test code have none. */
export function dismissalExpiry(reason: string, days: number | null | undefined, now: Date = new Date()): string | null {
  const span = days === undefined ? (reason === 'accepted_risk' ? 90 : null) : days;
  if (!span) return null;
  return new Date(now.getTime() + span * 86_400_000).toISOString();
}
