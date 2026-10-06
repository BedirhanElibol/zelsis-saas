import type { SupabaseClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';
import { sendNewFindingsAlertEmail } from '@/lib/email';

export interface AlertFinding {
  ruleId: number;
  title: string;
  severity: string;
  filePath: string;
  maturity?: string;
  status?: string;
}

export interface NewFindingSummary {
  ruleId: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH';
  filePath: string;
}

const MAX_LISTED = 20;

// Line numbers move between commits, so a finding is identified by rule, file and title.
function fingerprint(f: AlertFinding): string {
  return `${f.ruleId}|${f.filePath}|${f.title}`;
}

function isAlertable(f: AlertFinding): f is AlertFinding & { severity: 'CRITICAL' | 'HIGH' } {
  return (f.severity === 'CRITICAL' || f.severity === 'HIGH')
    && f.maturity !== 'experimental'
    && f.status !== 'RESOLVED';
}

/** CRITICAL/HIGH findings in `current` that were not present in `previous`. */
export function diffNewFindings(previous: AlertFinding[], current: AlertFinding[]): NewFindingSummary[] {
  const seen = new Set(previous.map(fingerprint));
  const out: NewFindingSummary[] = [];
  for (const f of current) {
    if (!isAlertable(f) || seen.has(fingerprint(f))) continue;
    seen.add(fingerprint(f));
    out.push({ ruleId: f.ruleId, title: f.title, severity: f.severity, filePath: f.filePath });
  }
  return out.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'CRITICAL' ? -1 : 1));
}

/**
 * Compares a scheduled rescan with the user's previous completed scan of the same repo and,
 * when new CRITICAL/HIGH findings appear, stores a dashboard alert and emails the owner.
 * The first scan of a repo is the baseline and never alerts.
 */
export async function recordRescanAlert(params: {
  adminClient: SupabaseClient;
  jobId: string;
  userId: string;
  userEmail?: string | null;
  projectId: string;
  projectName: string;
  repoUrl: string;
  findings: AlertFinding[];
}): Promise<void> {
  const { adminClient, jobId, userId, userEmail, projectId, projectName, repoUrl, findings } = params;

  const { data: project } = await adminClient
    .from('projects')
    .select('alert_new_cves_enabled')
    .eq('id', projectId)
    .maybeSingle();
  if (!project?.alert_new_cves_enabled) return;

  const { data: prevJob } = await adminClient
    .from('scan_jobs')
    .select('result_data')
    .eq('user_id', userId)
    .eq('repo_url', repoUrl)
    .eq('status', 'COMPLETED')
    .neq('id', jobId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  const previous = (prevJob?.result_data as { findings?: AlertFinding[] } | null)?.findings;
  if (!Array.isArray(previous)) return;

  const fresh = diffNewFindings(previous, findings);
  if (fresh.length === 0) return;

  const newCritical = fresh.filter((f) => f.severity === 'CRITICAL').length;
  const newHigh = fresh.length - newCritical;

  let emailed = false;
  if (userEmail) {
    const res = await sendNewFindingsAlertEmail({
      toEmail: userEmail,
      projectName,
      repoUrl,
      newCritical,
      newHigh,
      findings: fresh.slice(0, MAX_LISTED),
    });
    emailed = res.success;
  }

  const { error } = await adminClient.from('project_alerts').insert({
    user_id: userId,
    project_id: projectId,
    scan_job_id: jobId,
    new_critical: newCritical,
    new_high: newHigh,
    findings: fresh.slice(0, MAX_LISTED),
    emailed,
  });
  if (error) logger.warn(`[Rescan] Could not store alert for job ${jobId}:`, error);
}
