import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { getEffectivePlanTier } from '@/lib/organization';

export const maxDuration = 30; // Max allowed by Vercel for pro plans
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const authHeader = req.headers.get('authorization');
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    logger.warn('[Cron] Unauthorized attempt to trigger rescan');
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const adminClient = getSupabaseAdmin();
  if (!adminClient) {
    return NextResponse.json({ error: 'Database connection failed' }, { status: 500 });
  }

  // Find all projects where weekly_rescan_enabled is true
  const { data: projects, error } = await adminClient
    .from('projects')
    .select('id, user_id, repo_url, name, alert_new_cves_enabled')
    .eq('weekly_rescan_enabled', true);

  if (error || !projects) {
    logger.error('[Cron] Failed to fetch projects for rescan:', error);
    return NextResponse.json({ error: 'Failed to fetch projects' }, { status: 500 });
  }

  const results = [];
  const internalSecret = process.env.ZELSIS_INTERNAL_SECRET || '';

  logger.info(`[Cron] Found ${projects.length} projects opted in for weekly rescan`);

  for (const p of projects) {
    try {
      // Create a scan_job for the rescan
      const { data: jobRow, error: jobErr } = await adminClient
        .from('scan_jobs')
        .insert({
          user_id: p.user_id,
          repo_url: p.repo_url,
          status: 'QUEUED',
          current_phase: 'Scheduled weekly rescan initiated'
        })
        .select('id')
        .single();

      if (jobErr || !jobRow) {
        logger.warn(`[Cron] Failed to create scan_job for project ${p.id}:`, jobErr);
        continue;
      }

      const userTier = await getEffectivePlanTier(adminClient, p.user_id);
      const isFree = userTier === 'Free';

      const payload = {
        jobId: jobRow.id,
        repoUrl: p.repo_url,
        targetName: p.name,
        authenticatedUserId: p.user_id,
        userTier,
        osvOnly: isFree,
        isRescan: true,
        // Optional: you can pass the alert flag if you want to conditionally alert
        // But we will handle the check via diffing in executeScanJob
      };

      // Asynchronously trigger the scan processing so the cron doesn't time out
      fetch(`${getConfiguredAppUrl()}/api/v1/scans/process-job`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-zelsis-internal-secret': internalSecret
        },
        body: JSON.stringify(payload)
      }).catch(e => logger.error(`[Cron] Error triggering rescan job ${jobRow.id}:`, e));

      results.push({ projectId: p.id, jobId: jobRow.id, type: isFree ? 'OSV_ONLY' : 'FULL' });
    } catch (e) {
      logger.error(`[Cron] Rescan trigger failed for project ${p.id}`, e);
    }
  }

  return NextResponse.json({ success: true, triggered: results.length, jobs: results });
}
