import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { sendWeeklyRiskSummaryEmail } from '@/lib/email';
import { unsubscribeToken } from '@/lib/lifecycle-emails';
import { GATE_TRIGGERS, summarizeWeek, summarySubject, type GateRun } from '@/lib/weekly-summary';

const MAX_SENDS_PER_RUN = 200;
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/** Sends the Friday gate summary. Run by the daily lifecycle cron on Fridays and by /api/cron/weekly-summary. */
export async function sendWeeklySummaries(): Promise<NextResponse> {
  const admin = getSupabaseAdmin();
  if (!admin || !process.env.RESEND_API_KEY || !unsubscribeToken('probe')) {
    logger.error('[Weekly Summary] Not configured (database, RESEND_API_KEY or INTERNAL_API_SECRET missing)');
    return NextResponse.json({ error: 'Weekly summary is not configured' }, { status: 500 });
  }

  const since = new Date(Date.now() - WEEK_MS).toISOString();
  const { data: rows, error } = await admin
    .from('scans')
    .select('user_id, project_id, gate_status, critical_count, high_count, scanned_at')
    .in('trigger_type', [...GATE_TRIGGERS])
    .gte('scanned_at', since)
    .limit(20000);
  if (error) {
    logger.error('[Weekly Summary] Could not read gate runs:', error.message);
    return NextResponse.json({ error: 'Could not read gate runs' }, { status: 500 });
  }

  const byUser = new Map<string, GateRun[]>();
  for (const r of (rows ?? []) as GateRun[]) byUser.set(r.user_id, [...(byUser.get(r.user_id) ?? []), r]);

  const projectIds = [...new Set((rows ?? []).map((r: GateRun) => r.project_id))];
  const { data: projects } = projectIds.length
    ? await admin.from('projects').select('id, name, repo_url').in('id', projectIds)
    : { data: [] };
  const projectName = new Map<string, string>(
    (projects ?? []).map((p: { id: string; name?: string | null; repo_url?: string | null }) => [p.id, p.name || p.repo_url || 'project']),
  );

  const appUrl = getConfiguredAppUrl();
  let sent = 0;
  for (const [userId, runs] of [...byUser.entries()].slice(0, MAX_SENDS_PER_RUN)) {
    const { data: userData } = await admin.auth.admin.getUserById(userId);
    const user = userData?.user;
    if (!user?.email || user.app_metadata?.email_opt_out) continue;

    const summary = summarizeWeek(runs);
    const token = unsubscribeToken(userId)!;
    const res = await sendWeeklyRiskSummaryEmail({
      toEmail: user.email,
      unsubscribeUrl: `${appUrl}/api/v1/email/unsubscribe?u=${encodeURIComponent(userId)}&t=${encodeURIComponent(token)}`,
      subject: summarySubject(summary),
      runs: summary.runs,
      blocked: summary.blocked,
      warned: summary.warned,
      criticalStopped: summary.criticalStopped,
      highFlagged: summary.highFlagged,
      topProjects: summary.topProjects.map((p) => ({ name: projectName.get(p.projectId) ?? 'project', blocked: p.blocked })),
    });
    if (res.success) sent++;
    else logger.warn(`[Weekly Summary] Not sent to ${userId}: ${res.error}`);
  }
  return NextResponse.json({ success: true, accounts: byUser.size, sent });
}
