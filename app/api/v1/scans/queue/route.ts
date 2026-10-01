import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { logger } from '@/lib/logger';
import { isValidGithubUrl, parseGithubUrl } from '@/lib/github-api';
import { isValidWebUrl } from '@/lib/website-scanner';
import { z } from 'zod';

export const dynamic = 'force-dynamic';

const QueueScanRequestSchema = z.object({
  repoUrl: z.string().min(1, 'Target repository or web URL is required'),
  targetName: z.string().optional(),
  githubToken: z.string().optional(),
  commitSha: z.string().optional(),
  projectId: z.string().uuid().optional(),
  slackWebhookUrl: z.string().url().optional(),
  discordWebhookUrl: z.string().url().optional()
});

export async function POST(req: NextRequest) {
  try {
    // 1. Rate Limiting (20 queue dispatches per minute per IP)
    const rateLimit = await checkRateLimit(req, {
      maxRequests: 20,
      windowSeconds: 60,
      prefix: 'scans-queue'
    });

    if (!rateLimit.allowed) {
      return createRateLimitResponse(rateLimit);
    }

    // 2. Parse & Validate Payload
    let body: z.infer<typeof QueueScanRequestSchema>;
    try {
      const rawJson = await req.json();
      body = QueueScanRequestSchema.parse(rawJson);
    } catch (valErr: any) {
      return NextResponse.json(
        {
          status: 'ERROR',
          error: valErr?.errors?.[0]?.message || 'Invalid queue request schema'
        },
        { status: 400 }
      );
    }

    const rawRepoUrl = body.repoUrl.trim();
    const isWeb = isValidWebUrl(rawRepoUrl);
    const isGithub = !isWeb && (isValidGithubUrl(rawRepoUrl) || parseGithubUrl(rawRepoUrl) !== null);

    if (!isWeb && !isGithub && rawRepoUrl.toLowerCase() !== 'local') {
      return NextResponse.json(
        {
          status: 'ERROR',
          error: `Invalid URL: "${rawRepoUrl}" must be a valid GitHub repository or HTTPS website URL.`
        },
        { status: 400 }
      );
    }

    // 3. User Authentication & Authorization
    const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    let authenticatedUserId: string | null = null;
    let userTier: 'Free' | 'Pro' | 'Enterprise' = 'Free';

    if (authHeader && supabaseUrl && anonKey) {
      try {
        const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
        const { data: { user } } = await authClient.auth.getUser(authHeader);
        if (user) {
          authenticatedUserId = user.id;
        }
      } catch {
        // Non-blocking parse
      }
    }

    if (!authenticatedUserId) {
      return NextResponse.json(
        { status: 'ERROR', error: 'Please sign in or create a free account to run audits.' },
        { status: 401 }
      );
    }

    // 4. Quota Gate Verification
    if (serviceRoleKey) {
      try {
        const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
        const { data: sub } = await adminClient
          .from('subscriptions')
          .select('plan_tier, monthly_scan_quota, scans_used_this_month, current_period_end')
          .eq('user_id', authenticatedUserId)
          .maybeSingle();

        if (sub) {
          const periodElapsed = Boolean(sub.current_period_end && new Date(sub.current_period_end).getTime() < Date.now());
          userTier = periodElapsed ? 'Free' : ((sub.plan_tier as any) || 'Free');
          const monthlyQuota = userTier === 'Free' ? 3 : (sub.monthly_scan_quota ?? 3);
          const scansUsed = periodElapsed ? 0 : (sub.scans_used_this_month ?? 0);

          // /api/v1/quota already reserved this scan, so the counter includes it
          if (userTier === 'Free' && scansUsed > monthlyQuota) {
            return NextResponse.json(
              {
                status: 'ERROR',
                error: `Monthly scan limit reached (${scansUsed}/${monthlyQuota}). Upgrade to Zelsis Pro for unlimited automated scans.`,
                quotaExceeded: true
              },
              { status: 403 }
            );
          }
        }
      } catch (quotaErr) {
        logger.warn('[Scans Queue] Quota verification notice:', quotaErr);
      }
    }

    // 5. Create Job Record in Database
    let jobId: string | null = null;
    if (serviceRoleKey && supabaseUrl) {
      const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

      const { data: insertedJob, error: insertErr } = await adminClient
        .from('scan_jobs')
        .insert({
          project_id: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.projectId || '') ? body.projectId : null,
          user_id: authenticatedUserId,
          repo_url: rawRepoUrl,
          commit_sha: body.commitSha || null,
          status: 'QUEUED',
          progress_percent: 5,
          current_phase: 'QUEUED',
          current_file: 'Queued in execution pipeline',
          total_files: 0,
          processed_files: 0,
          findings_count: 0
        })
        .select('id')
        .single();

      if (insertErr || !insertedJob?.id) {
        logger.error('[Scans Queue] Failed to insert scan_job:', insertErr);
        return NextResponse.json(
          { status: 'ERROR', error: 'Database queue transaction failed' },
          { status: 500 }
        );
      }

      jobId = insertedJob.id;
    } else {
      // Ephemeral fallback ID if no database credentials
      const crypto = await import('crypto');
      jobId = crypto.randomUUID();
    }

    // 6. Asynchronous Worker Trigger (Fire-and-Forget)
    const host = req.headers.get('host') || 'localhost:3000';
    const protocol = req.headers.get('x-forwarded-proto') || (host.startsWith('localhost') ? 'http' : 'https');
    const workerUrl = `${protocol}://${host}/api/v1/scans/process-job`;
    const internalSecret = process.env.INTERNAL_API_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY || 'zelsis-internal-worker-secret';

    // Trigger background execution without awaiting completion
    fetch(workerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-zelsis-internal-secret': internalSecret
      },
      body: JSON.stringify({
        jobId,
        repoUrl: rawRepoUrl,
        targetName: body.targetName,
        githubToken: body.githubToken,
        authenticatedUserId,
        userTier,
        slackWebhookUrl: body.slackWebhookUrl,
        discordWebhookUrl: body.discordWebhookUrl
      })
    }).catch((triggerErr) => {
      logger.warn('[Scans Queue] Background worker trigger notice:', triggerErr?.message);
    });

    return NextResponse.json(
      {
        status: 'SUCCESS',
        jobId,
        phase: 'QUEUED',
        progress: 5,
        trackingUrl: `/api/v1/scans/jobs/${jobId}`,
        message: 'Scan task successfully queued for asynchronous execution.'
      },
      {
        status: 202,
        headers: {
          'Deprecation': '@1798761600',
          'Sunset': 'Fri, 01 Jan 2027 00:00:00 GMT',
          'Link': '<https://zelsis.com/docs/api/v1>; rel="deprecation"'
        }
      }
    );
  } catch (err: any) {
    logger.error('[Scans Queue] Unexpected error:', err);
    return NextResponse.json(
      { status: 'ERROR', error: err?.message || 'Internal queue processing error' },
      { status: 500 }
    );
  }
}
