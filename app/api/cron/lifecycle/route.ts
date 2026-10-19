import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { isAuthorizedCron } from '@/lib/cron-auth';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { sendFirstScanNudgeEmail } from '@/lib/email';
import { pickFirstScanNudges, unsubscribeToken, type LifecycleUser } from '@/lib/lifecycle-emails';
import { sendWeeklySummaries } from '@/lib/weekly-summary-job';

export const maxDuration = 30;
export const dynamic = 'force-dynamic';

const PAGE_SIZE = 200;
const MAX_PAGES = 10;
const MAX_SENDS_PER_RUN = 50;

/** Daily: one "run your first scan" email to confirmed accounts that have not scanned a day after signing up. */
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

  // Only the recent signups need the scan check
  const recent = pickFirstScanNudges(users, new Set());
  if (recent.length === 0) return NextResponse.json({ success: true, sent: 0, weekly });
  const { data: jobs } = await admin
    .from('scan_jobs')
    .select('user_id')
    .in('user_id', recent.map((u) => u.id));
  const scanned = new Set((jobs ?? []).map((j: { user_id: string }) => j.user_id));
  const targets = pickFirstScanNudges(recent, scanned).slice(0, MAX_SENDS_PER_RUN);

  const appUrl = getConfiguredAppUrl();
  let sent = 0;
  for (const u of targets) {
    const token = unsubscribeToken(u.id)!;
    const unsubscribeUrl = `${appUrl}/api/v1/email/unsubscribe?u=${encodeURIComponent(u.id)}&t=${encodeURIComponent(token)}`;
    const res = await sendFirstScanNudgeEmail({ toEmail: u.email!, unsubscribeUrl });
    if (!res.success) {
      logger.warn(`[Lifecycle] Nudge not sent to ${u.id}: ${res.error}`);
      continue;
    }
    sent++;
    // If this write fails, a later run inside the 3-day window would send again, so log it as an error
    const { error } = await admin.auth.admin.updateUserById(u.id, {
      app_metadata: { ...(u.app_metadata ?? {}), first_scan_nudge_at: new Date().toISOString() },
    });
    if (error) logger.error(`[Lifecycle] Could not record nudge for ${u.id}:`, error.message);
  }
  return NextResponse.json({ success: true, candidates: targets.length, sent, weekly });
}
