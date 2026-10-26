import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { isAuthorizedCron } from '@/lib/cron-auth';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { sendFirstScanNudgeEmail, sendGateNudgeEmail } from '@/lib/email';
import { pickFirstScanNudges, pickGateNudges, unsubscribeToken, type LifecycleUser } from '@/lib/lifecycle-emails';
import { sendWeeklySummaries } from '@/lib/weekly-summary-job';
import { GATE_TRIGGERS } from '@/lib/weekly-summary';

export const maxDuration = 30;
export const dynamic = 'force-dynamic';

const PAGE_SIZE = 200;
const MAX_PAGES = 10;
const MAX_SENDS_PER_RUN = 50;

/**
 * Daily: one "run your first scan" email to confirmed accounts that have not scanned a day after signing up, and one
 * "add the pull request gate" email to accounts that scanned but whose pull requests never reached the gate.
 */
export async function GET(req: Request) {
  if (!isAuthorizedCron(req.headers.get('authorization'))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const admin = getSupabaseAdmin();
  if (!admin || !process.env.RESEND_API_KEY || !unsubscribeToken('probe')) {
    logger.error('[Lifecycle] Not configured (database, RESEND_API_KEY or INTERNAL_API_SECRET missing)');
    return NextResponse.json({ error: 'Lifecycle email is not configured' }, { status: 500 });
  }

  // Fridays: the weekly gate summary runs from this cron (one Vercel cron slot for all product email)
  let weekly: unknown = null;
  if (new Date().getUTCDay() === 5) {
    weekly = await (await sendWeeklySummaries()).json().catch(() => null);
  }

  const users: LifecycleUser[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: PAGE_SIZE });
    if (error) {
      logger.error('[Lifecycle] listUsers failed:', error.message);
      return NextResponse.json({ error: 'Could not list users' }, { status: 500 });
    }
    users.push(...(data.users as LifecycleUser[]));
    if (data.users.length < PAGE_SIZE) break;
  }

  const appUrl = getConfiguredAppUrl();
  let sent = 0;
  const send = async (
    u: LifecycleUser,
    mail: typeof sendFirstScanNudgeEmail,
    markKey: 'first_scan_nudge_at' | 'gate_nudge_at',
  ) => {
    const token = unsubscribeToken(u.id)!;
    const unsubscribeUrl = `${appUrl}/api/v1/email/unsubscribe?u=${encodeURIComponent(u.id)}&t=${encodeURIComponent(token)}`;
    const res = await mail({ toEmail: u.email!, unsubscribeUrl });
    if (!res.success) {
      logger.warn(`[Lifecycle] ${markKey} email not sent to ${u.id}: ${res.error}`);
      return;
    }
    sent++;
    // If this write fails, a later run inside the window would send again, so log it as an error
    const { error } = await admin.auth.admin.updateUserById(u.id, {
      app_metadata: { ...(u.app_metadata ?? {}), [markKey]: new Date().toISOString() },
    });
    if (error) logger.error(`[Lifecycle] Could not record ${markKey} for ${u.id}:`, error.message);
  };

  // Only the recent signups need the scan check
  const recent = pickFirstScanNudges(users, new Set());
  let firstScanTargets: LifecycleUser[] = [];
  if (recent.length > 0) {
    const { data: jobs } = await admin
      .from('scan_jobs')
      .select('user_id')
      .in('user_id', recent.map((u) => u.id));
    const scanned = new Set((jobs ?? []).map((j: { user_id: string }) => j.user_id));
    firstScanTargets = pickFirstScanNudges(recent, scanned).slice(0, MAX_SENDS_PER_RUN);
    for (const u of firstScanTargets) await send(u, sendFirstScanNudgeEmail, 'first_scan_nudge_at');
  }

  // Accounts that scanned a few days ago but whose pull requests never reached the gate
  const gateCandidates = pickGateNudges(users, new Set(users.map((u) => u.id)), new Set());
  let gateTargets: LifecycleUser[] = [];
  if (gateCandidates.length > 0 && sent < MAX_SENDS_PER_RUN) {
    const ids = gateCandidates.map((u) => u.id);
    const [{ data: jobs }, { data: gateScans }] = await Promise.all([
      admin.from('scan_jobs').select('user_id').in('user_id', ids),
      admin.from('scans').select('user_id').in('user_id', ids).in('trigger_type', [...GATE_TRIGGERS]),
    ]);
    const scanned = new Set((jobs ?? []).map((j: { user_id: string }) => j.user_id));
    const gated = new Set((gateScans ?? []).map((s: { user_id: string }) => s.user_id));
    gateTargets = pickGateNudges(gateCandidates, scanned, gated).slice(0, MAX_SENDS_PER_RUN - sent);
    for (const u of gateTargets) await send(u, sendGateNudgeEmail, 'gate_nudge_at');
  }

  return NextResponse.json({ success: true, candidates: firstScanTargets.length + gateTargets.length, sent, weekly });
}
