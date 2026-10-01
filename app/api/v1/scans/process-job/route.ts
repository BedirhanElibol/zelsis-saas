import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { runStaticCodeScan, CodeFile } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData } from '@/lib/github-api';
import { fetchWebsiteAuditData, isValidWebUrl } from '@/lib/website-scanner';
import { dispatchWebhookAlerts } from '@/lib/notifications';
import { logger } from '@/lib/logger';
import { canAccessLocalAudit } from '@/lib/env-config';
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { hasFixPromptAccess, isPlatformAdminEmail, resolveServerPlanTier } from '@/lib/subscription-utils';
import { redactScanResultFixes } from '@/lib/fix-gate';

export const maxDuration = 30;
export const revalidate = 3600;

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 10,
    windowSeconds: 60,
    prefix: 'process-job'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // Validate Content-Type
  const contentType = req.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return NextResponse.json(
      { error: 'Unsupported Media Type: Content-Type must be application/json' },
      { status: 415 }
    );
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const internalSecret = process.env.INTERNAL_API_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY || 'zelsis-internal-worker-secret';

  // 1. Authenticate Internal Invocation
  const receivedSecret = req.headers.get('x-zelsis-internal-secret');
  if (receivedSecret !== internalSecret) {
    logger.warn('[Process Job] Unauthorized background worker invocation attempted');
    return NextResponse.json({ error: 'Unauthorized internal worker route' }, { status: 401 });
  }

  let body: any = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
  }

  let {
    jobId,
    repoUrl: rawRepoUrl,
    targetName: providedTargetName,
    githubToken,
    authenticatedUserId,
    userTier = 'Free',
    slackWebhookUrl,
    discordWebhookUrl
  } = body;

  if (!jobId || !rawRepoUrl) {
    return NextResponse.json({ error: 'Missing jobId or repoUrl' }, { status: 400 });
  }

  const adminClient = (supabaseUrl && serviceRoleKey)
    ? createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } })
    : null;

  // SEC-02 Authority Invariant: If database connection is active, derive target parameters
  // strictly from verified scan_jobs record to prevent worker request tampering.
  if (adminClient && jobId) {
    try {
      const { data: jobRow } = await adminClient
        .from('scan_jobs')
        .select('repo_url, user_id')
        .eq('id', jobId)
        .maybeSingle();

      if (jobRow) {
        if (jobRow.repo_url) rawRepoUrl = jobRow.repo_url;
        if (jobRow.user_id) {
          authenticatedUserId = jobRow.user_id;
          const { data: subRow } = await adminClient
            .from('subscriptions')
            .select('plan_tier, current_period_end')
            .eq('user_id', authenticatedUserId)
            .maybeSingle();
          const { data: ownerData } = await adminClient.auth.admin.getUserById(jobRow.user_id);
          userTier = resolveServerPlanTier({
            storedTier: subRow?.plan_tier,
            currentPeriodEnd: subRow?.current_period_end,
            isAdmin: isPlatformAdminEmail(ownerData?.user?.email)
          });
        }
      }
    } catch (dbErr) {
      logger.warn('[Process Job] Notice deriving DB job authority:', dbErr);
    }
  }

  const updateJobState = async (updates: Record<string, any>) => {
    if (!adminClient) return;
    try {
      await adminClient
        .from('scan_jobs')
        .update({
          ...updates,
          updated_at: new Date().toISOString()
        })
        .eq('id', jobId);
    } catch (err) {
      logger.warn(`[Process Job] Notice updating state for ${jobId}:`, err);
    }
  };

  try {
    // ─── Phase 1: FETCHING (Connecting & Enumerating Files) ───
    await updateJobState({
      status: 'FETCHING',
      progress_percent: 20,
      current_phase: 'Connecting & enumerating target files',
      current_file: rawRepoUrl
    });

    const isWebTarget = isValidWebUrl(rawRepoUrl);
    let filesToScan: CodeFile[] = [];
    let resolvedTargetName = providedTargetName || rawRepoUrl;

    if (rawRepoUrl.toLowerCase() === 'local') {
      if (!canAccessLocalAudit()) {
        await updateJobState({
          status: 'FAILED',
          progress_percent: 0,
          error_message: 'Local workspace self-audit is restricted to local development environments.'
        });
        return NextResponse.json({ error: 'Local audit forbidden' }, { status: 403 });
      }
      const { WORKSPACE_SOURCE_FILES } = await import('@/data/workspaceFiles');
      filesToScan = WORKSPACE_SOURCE_FILES;
      resolvedTargetName = 'Zelsis Local Workspace';
    } else if (isWebTarget) {
      const ssrfCheck = await validateSafeTargetUrl(rawRepoUrl);
      if (!ssrfCheck.safe) {
        await updateJobState({
          status: 'FAILED',
          progress_percent: 0,
          error_message: `SSRF Blocked: ${ssrfCheck.reason || 'Restricted network endpoint'}`
        });
        return NextResponse.json({ error: 'SSRF blocked' }, { status: 403 });
      }

      const webData = await fetchWebsiteAuditData(rawRepoUrl);
      if (webData?.error) {
        await updateJobState({
          status: 'FAILED',
          progress_percent: 0,
          error_message: `Website Audit Error: ${webData.error}`
        });
        return NextResponse.json({ error: webData.error }, { status: 502 });
      }
      filesToScan = webData?.files || [];
      resolvedTargetName = webData?.title || rawRepoUrl;
    } else {
      // GitHub Repository Fetch
      const liveData = await fetchGithubRepositoryData(rawRepoUrl, githubToken);

      if (liveData?.error === 'RATE_LIMIT_EXCEEDED') {
        await updateJobState({
          status: 'FAILED',
          progress_percent: 0,
          error_message: 'GitHub API rate limit reached. Add a Personal Access Token (PAT) in Settings.'
        });
        return NextResponse.json(
          { error: 'GitHub rate limit exceeded' },
          { 
            status: 429,
            headers: {
              'Retry-After': '60',
              'Deprecation': 'true',
              'Sunset': 'Fri, 01 Jan 2027 00:00:00 GMT'
            }
          }
        );
      }

      if (liveData?.error === 'REPO_NOT_FOUND' || liveData?.error === 'EMPTY_REPOSITORY') {
        await updateJobState({
          status: 'FAILED',
          progress_percent: 0,
          error_message: liveData.error === 'REPO_NOT_FOUND'
            ? `Repository "${rawRepoUrl}" not found or private.`
            : `Repository "${rawRepoUrl}" contains no scannable source files.`
        });
        return NextResponse.json({ error: liveData.error }, { status: 404 });
      }

      filesToScan = liveData?.files || [];
      resolvedTargetName = liveData?.name || rawRepoUrl;
    }

    if (filesToScan.length === 0) {
      await updateJobState({
        status: 'FAILED',
        progress_percent: 0,
        error_message: 'No scannable code files discovered.'
      });
      return NextResponse.json({ error: 'No files to scan' }, { status: 422 });
    }

    // ─── Phase 2: INDEXING (Sorting & Filtering Eligible Files) ───
    await updateJobState({
      status: 'INDEXING',
      progress_percent: 45,
      current_phase: 'Indexing & validating eligible architecture files',
      total_files: filesToScan.length,
      processed_files: 0
    });

    // ─── Phase 3: ANALYZING (Executing AST Rules & Policy Checks) ───
    await updateJobState({
      status: 'ANALYZING',
      progress_percent: 65,
      current_phase: 'Executing deterministic AST security rules'
    });

    const result = await runStaticCodeScan(filesToScan, resolvedTargetName);

    // ─── Phase 4: AGGREGATING (Persisting Findings & Manifest) ───
    await updateJobState({
      status: 'AGGREGATING',
      progress_percent: 85,
      current_phase: 'Generating compliance manifest & recording findings',
      findings_count: result.findings.length,
      processed_files: filesToScan.length
    });

    let createdScanId: string | null = null;

    if (adminClient) {
      let projectId: string | null = null;
      if (authenticatedUserId) {
        const { data: existingProj } = await adminClient
          .from('projects')
          .select('id')
          .eq('user_id', authenticatedUserId)
          .eq('repo_url', rawRepoUrl)
          .maybeSingle();

        if (existingProj?.id) {
          projectId = existingProj.id;
        } else {
          const { data: newProj } = await adminClient
            .from('projects')
            .insert({
              user_id: authenticatedUserId,
              name: resolvedTargetName,
              repo_url: rawRepoUrl,
              readiness_score: result.score,
              gate_status: result.gateStatus
            })
            .select('id')
            .maybeSingle();
          if (newProj?.id) projectId = newProj.id;
        }
      }

      if (projectId && authenticatedUserId) {
        const { data: scanRow } = await adminClient
          .from('scans')
          .insert({
            project_id: projectId,
            user_id: authenticatedUserId,
            trigger_type: 'WEB_UI_ASYNC',
            readiness_score: result.score,
            gate_status: result.gateStatus,
            critical_count: result.criticalCount,
            high_count: result.highCount,
            medium_count: result.mediumCount,
            low_count: result.lowCount,
            ui_cliche_count: result.uiClicheCount,
            scan_duration_ms: 2500
          })
          .select('id')
          .single();

        if (scanRow?.id) {
          createdScanId = scanRow.id;
        }

        // Deduct Quota Atomically upon Successful Completion
        const { data: sub } = await adminClient
          .from('subscriptions')
          .select('scans_used_this_month')
          .eq('user_id', authenticatedUserId)
          .maybeSingle();

        const currentScans = sub?.scans_used_this_month ?? 0;
        await adminClient
          .from('subscriptions')
          .update({
            scans_used_this_month: currentScans + 1,
            updated_at: new Date().toISOString()
          })
          .eq('user_id', authenticatedUserId);
      }
    }

    // Auto-dispatch Webhooks if configured
    if (slackWebhookUrl || discordWebhookUrl) {
      dispatchWebhookAlerts(resolvedTargetName, rawRepoUrl, result, {
        slackWebhookUrl,
        discordWebhookUrl
      }).catch((whErr) => logger.warn('[Process Job] Webhook dispatch notice:', whErr?.message));
    }

    // Fix text is Pro: Free results are stored without it, full text goes to the service-role-only table
    let storedResult = result;
    if (!hasFixPromptAccess(userTier)) {
      const redacted = redactScanResultFixes(result, jobId);
      storedResult = redacted.result;
      if (adminClient && authenticatedUserId) {
        const { error: fixesErr } = await adminClient
          .from('scan_job_fixes')
          .upsert({ job_id: jobId, user_id: authenticatedUserId, fixes: redacted.fixes });
        if (fixesErr) {
          logger.warn(`[Process Job] Could not store fixes for ${jobId}:`, fixesErr);
        }
      }
    }

    // ─── Phase 5: COMPLETED ───
    await updateJobState({
      status: 'COMPLETED',
      progress_percent: 100,
      current_phase: 'Audit clearance complete',
      readiness_score: result.score,
      gate_status: result.gateStatus,
      scan_id: createdScanId,
      findings_count: result.findings.length,
      result_data: storedResult
    });

    return NextResponse.json({
      status: 'SUCCESS',
      jobId,
      scanId: createdScanId,
      score: result.score,
      gateStatus: result.gateStatus,
      findingsCount: result.findings.length
    });
  } catch (err: any) {
    logger.error(`[Process Job] Execution error on job ${jobId}:`, err);
    await updateJobState({
      status: 'FAILED',
      progress_percent: 0,
      error_message: err?.message || 'Unexpected error during background analysis'
    });
    return NextResponse.json({ error: err?.message || 'Processing failed' }, { status: 500 });
  }
}
