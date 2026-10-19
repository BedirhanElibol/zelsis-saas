/**
 * Friday summary for a team lead: what the PR and CI gates did this week, from recorded gate runs
 * (scans with trigger_type WEBHOOK or CI_CD). Only real counts; nothing is estimated.
 */
export interface GateRun {
  user_id: string;
  project_id: string;
  gate_status: 'PASSED' | 'WARNING' | 'FAILED' | string;
  critical_count: number;
  high_count: number;
  scanned_at: string;
}

export interface WeeklySummary {
  runs: number;
  blocked: number;
  warned: number;
  criticalStopped: number;
  highFlagged: number;
  /** Projects with at least one blocked run, most blocked first. */
  topProjects: { projectId: string; blocked: number }[];
}

export const GATE_TRIGGERS = ['WEBHOOK', 'CI_CD'] as const;

export function summarizeWeek(runs: GateRun[]): WeeklySummary {
  const blockedByProject = new Map<string, number>();
  let blocked = 0;
  let warned = 0;
  let criticalStopped = 0;
  let highFlagged = 0;
  for (const r of runs) {
    if (r.gate_status === 'FAILED') {
      blocked++;
      criticalStopped += r.critical_count;
      blockedByProject.set(r.project_id, (blockedByProject.get(r.project_id) ?? 0) + 1);
    } else if (r.gate_status === 'WARNING') {
      warned++;
    }
    highFlagged += r.high_count;
  }
  const topProjects = [...blockedByProject.entries()]
    .map(([projectId, n]) => ({ projectId, blocked: n }))
    .sort((a, b) => b.blocked - a.blocked)
    .slice(0, 5);
  return { runs: runs.length, blocked, warned, criticalStopped, highFlagged, topProjects };
}

/** One sentence for the email subject line. */
export function summarySubject(s: WeeklySummary): string {
  if (s.blocked > 0) {
    return `Zelsis stopped ${s.criticalStopped} critical issue${s.criticalStopped === 1 ? '' : 's'} before merge this week`;
  }
  return `Zelsis checked ${s.runs} pull request${s.runs === 1 ? '' : 's'} this week: nothing critical got through`;
}
