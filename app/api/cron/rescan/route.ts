import { timingSafeEqual } from 'crypto';
import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { getInternalBaseUrl, getInternalSecret } from '@/lib/internal-auth';

export const maxDuration = 30;
export const dynamic = 'force-dynamic';

// Each scan runs in its own process-job invocation; the cron only has to hand the request off.
const DISPATCH_TIMEOUT_MS = 1500;

function isAuthorizedCron(header: string | null): boolean {
  const secret = process.env.CRON_SECRET?.trim();
  if (!secret || !header) return false;
  const expected = Buffer.from(`Bearer ${secret}`);
  const received = Buffer.from(header);
  return expected.length === received.length && timingSafeEqual(expected, received);
}

export async function GET(req: Request) {
  if (!isAuthorizedCron(req.headers.get('authorization'))) {
    logger.warn('[Cron] Unauthorized attempt to trigger rescan');
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const adminClient = getSupabaseAdmin();
  const internalSecret = getInternalSecret();
  const baseUrl = getInternalBaseUrl();
  if (!adminClient || !internalSecret || !baseUrl) {
    logger.error('[Cron] Rescan is not configured (database, INTERNAL_API_SECRET or NEXT_PUBLIC_APP_URL missing)');
    return NextResponse.json({ error: 'Rescan is not configured' }, { status: 500 });
  }

  const { data: projects, error } = await adminClient
    .from('projects')
    .select('id, user_id, repo_url, name')
    .eq('weekly_rescan_enabled', true)
    .like('repo_url', 'https://github.com/%')
    // No GitHub token is stored server-side, so only public repos can be rescanned unattended.
    .or('is_private.is.null,is_private.eq.false');

  if (error || !projects) {
    logger.error('[Cron] Failed to fetch projects for rescan:', error);
    return NextResponse.json({ error: 'Failed to fetch projects' }, { status: 500 });
  }

  logger.info(`[Cron] Found ${projects.length} projects opted in for weekly rescan`);

  const dispatches = projects.map(async (p) => {
    const { data: jobRow, error: jobErr } = await adminClient
      .from('scan_jobs')
      .insert({
        user_id: p.user_id,
        project_id: p.id,
        repo_url: p.repo_url,
        status: 'QUEUED',
        current_phase: 'Scheduled weekly rescan initiated'
      })
      .select('id')
      .single();

    if (jobErr || !jobRow) {
      logger.warn(`[Cron] Failed to create scan_job for project ${p.id}:`, jobErr);
      return null;
    }

    try {
      await fetch(`${baseUrl}/api/v1/scans/process-job`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-zelsis-internal-secret': internalSecret
        },
        body: JSON.stringify({
          jobId: jobRow.id,
          repoUrl: p.repo_url,
          targetName: p.name,
          isRescan: true
        }),
        signal: AbortSignal.timeout(DISPATCH_TIMEOUT_MS)
      });
    } catch (e) {
      // A timeout only means the scan is still running in its own invocation.
      if (!(e instanceof Error && e.name === 'TimeoutError')) {
        logger.error(`[Cron] Error triggering rescan job ${jobRow.id}:`, e);
        return null;
      }
    }
    return { projectId: p.id, jobId: jobRow.id };
  });

  const results = (await Promise.all(dispatches)).filter(Boolean);
  return NextResponse.json({ success: true, triggered: results.length, jobs: results });
}
