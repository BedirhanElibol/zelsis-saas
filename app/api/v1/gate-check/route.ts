import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { runStaticCodeScan, CodeFile } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData, isValidGithubUrl, parseGithubUrl } from '@/lib/github-api';
import { fetchWebsiteAuditData, isValidWebUrl } from '@/lib/website-scanner';
import { dispatchWebhookAlerts } from '@/lib/notifications';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { GateCheckRequestSchema, validateRequestBody } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';
import { canAccessLocalAudit } from '@/lib/env-config';
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';
import { hasFixPromptAccess } from '@/lib/subscription-utils';
import { getEffectivePlanTier, getOrgPolicy } from '@/lib/organization';
import { LOCKED_FIX_TEXT } from '@/lib/fix-gate';
import { calculateGateStatus, gateSeverity, gatingFindings } from '@/lib/scanner/scoring';

// F-31: Bounded execution duration for static code scans (bounded to 30s for serverless SLA)
export const maxDuration = 30;
export const dynamic = 'force-dynamic';

function isAllowedWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    // Only allow HTTPS
    if (parsed.protocol !== 'https:') return false;
    // Block private/internal IPs
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('172.') ||
      hostname === '169.254.169.254' ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.local')
    ) {
      return false;
    }
    // Only allow known webhook domains
    const allowedDomains = ['hooks.slack.com', 'discord.com', 'discordapp.com'];
    return allowedDomains.some(d => hostname === d || hostname.endsWith('.' + d));
  } catch {
    return false;
  }
}

export async function POST(req: NextRequest) {
  try {
    // 1. Sliding-Window Rate Limiting (Max 20 audits per minute per IP)
    const rateLimit = await checkRateLimit(req, {
      maxRequests: 20,
      windowSeconds: 60,
      prefix: 'gate-check'
    });

    if (!rateLimit.allowed) {
      const response = createRateLimitResponse(rateLimit);
      response.headers.set('Retry-After', String(Math.ceil(rateLimit.resetSeconds)));
      return response;
    }

    // 2. Validate Content-Type
    const contentType = req.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: 'Unsupported Media Type: Content-Type must be application/json',
          timestamp: new Date().toISOString()
        },
        { status: 415 }
      );
    }

    // 3. Safe JSON body extraction and Zod validation
    const rawBody = await req.json().catch(() => null);
    if (!rawBody || typeof rawBody !== 'object') {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: 'Bad Request: JSON body is missing or malformed',
          timestamp: new Date().toISOString()
        },
        { status: 400 }
      );
    }

    const validation = validateRequestBody(GateCheckRequestSchema, rawBody);
    if (!validation.success) {
      return validation.response;
    }

    const body = validation.data as any;
    const rawRepoUrl = (body.repoUrl || body.targetUrl || '').trim();

    // Early validation of webhook URLs to prevent SSRF and avoid wasting compute
    const slackWebhookUrl = body.slackWebhookUrl || process.env.SLACK_WEBHOOK_URL;
    const discordWebhookUrl = body.discordWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

    if (slackWebhookUrl && !isAllowedWebhookUrl(slackWebhookUrl)) {
      return NextResponse.json({ error: 'Invalid Slack webhook URL' }, { status: 400 });
    }
    if (discordWebhookUrl && !isAllowedWebhookUrl(discordWebhookUrl)) {
      return NextResponse.json({ error: 'Invalid Discord webhook URL' }, { status: 400 });
    }

    const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
    const apiKeyHeader = req.headers.get('x-api-key')?.trim();
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || '127.0.0.1';
    const githubToken = (body.githubToken || authHeader || '').trim() || undefined;

    // Database Quota Verification
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    let authenticatedUserId: string | null = null;
    let userTier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
    let canSeeFixes = false;
    let orgPolicy: string | null = null;

    if (authHeader && supabaseUrl && anonKey) {
      try {
        const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
        const { data: { user } } = await authClient.auth.getUser(authHeader);
        if (user) {
          authenticatedUserId = user.id;
        }
      } catch {
        // Non-blocking auth parse
      }
    }

    if (!authenticatedUserId && apiKeyHeader && serviceRoleKey) {
      try {
        const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
        const crypto = await import('crypto');
        const hash = crypto.createHash('sha256').update(apiKeyHeader).digest('hex');
        const { data: keyRow } = await adminClient
          .from('api_keys')
          .select('id, user_id, expires_at')
          .eq('key_hash', hash)
          .maybeSingle();

        if (keyRow) {
          // F-30: Enforce API Key expiration check
          if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
            return NextResponse.json(
              {
                status: 'ERROR',
                gateStatus: 'FAILED',
                error: 'Unauthorized: The provided API key has expired. Please generate a new key in Project Settings.',
                timestamp: new Date().toISOString()
              },
              { status: 401 }
            );
          }

          authenticatedUserId = keyRow.user_id;

          // F-30: Update last_used_at telemetry
          adminClient
            .from('api_keys')
            .update({ last_used_at: new Date().toISOString() })
            .eq('id', keyRow.id)
            .then(
              () => {},
              (err) => logger.warn('[Gate Check] Notice updating last_used_at:', err)
            );
        }
      } catch (keyErr) {
        logger.warn('[Gate Check] API Key validation error:', keyErr);
      }
    }

    let shouldDeductQuota = false;
    let currentScansUsed = 0;

    if (authenticatedUserId && serviceRoleKey) {
      try {
        const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
        const { data: sub } = await adminClient
          .from('subscriptions')
          .select('plan_tier, monthly_scan_quota, scans_used_this_month, current_period_end')
          .eq('user_id', authenticatedUserId)
          .maybeSingle();

        // Own plan (an expired period counts as Free) or a seat in an Enterprise workspace
        userTier = await getEffectivePlanTier(adminClient, authenticatedUserId);
        canSeeFixes = hasFixPromptAccess(userTier);
        orgPolicy = await getOrgPolicy(adminClient, authenticatedUserId);

        if (sub) {
          const monthlyQuota = sub.monthly_scan_quota ?? 3;
          const scansUsed = sub.scans_used_this_month ?? 0;

          if (userTier === 'Free' && scansUsed >= monthlyQuota) {
            return NextResponse.json(
              {
                status: 'ERROR',
                gateStatus: 'FAILED',
                error: `Monthly scan quota reached (${scansUsed}/${monthlyQuota} scans used). Upgrade to Zelsis Pro for unlimited automated audits.`,
                timestamp: new Date().toISOString()
              },
              { status: 402 }
            );
          }

          // F-40: Defer quota deduction until after the scan completes successfully
          if (userTier === 'Free') {
            shouldDeductQuota = true;
            currentScansUsed = scansUsed;
          }
        }
      } catch (subErr) {
        logger.warn('[Gate Check] Quota check notice:', subErr);
      }
    }

    const isWebTarget = isValidWebUrl(rawRepoUrl);
    const isGithubTarget = !isWebTarget && (isValidGithubUrl(rawRepoUrl) || parseGithubUrl(rawRepoUrl) !== null);

    if (!isWebTarget && !isGithubTarget && rawRepoUrl.toLowerCase() !== 'local') {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: `Bad Request: Provided URL "${rawRepoUrl}" is neither a valid GitHub repository URL nor a valid HTTP/HTTPS website URL.`,
          timestamp: new Date().toISOString()
        },
        { status: 400 }
      );
    }

    if (rawRepoUrl.toLowerCase() === 'local' && !canAccessLocalAudit()) {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: 'Local workspace self-audit is restricted to local development environments.',
          timestamp: new Date().toISOString()
        },
        { status: 403 }
      );
    }

    // Option B: Hybrid CI/CD Async Queue Support (?async=true)
    const isAsync = req.nextUrl?.searchParams?.get('async') === 'true';
    if (isAsync) {
      const host = req.headers.get('host') || 'localhost:3000';
      const protocol = req.headers.get('x-forwarded-proto') || (host.startsWith('localhost') ? 'http' : 'https');
      const queueUrl = `${protocol}://${host}/api/v1/scans/queue`;

      const forwardHeaders: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      if (authHeader) forwardHeaders['Authorization'] = `Bearer ${authHeader}`;

      const queueRes = await fetch(queueUrl, {
        method: 'POST',
        headers: forwardHeaders,
        body: JSON.stringify({
          repoUrl: rawRepoUrl,
          targetName: (body as any).repoName || rawRepoUrl,
          githubToken,
          slackWebhookUrl,
          discordWebhookUrl
        })
      });

      const queueData = await queueRes.json().catch(() => ({}));
      return NextResponse.json(
        {
          status: 'SUCCESS',
          gateStatus: 'QUEUED',
          jobId: queueData.jobId,
          trackingUrl: `/api/v1/scans/jobs/${queueData.jobId}`,
          message: 'Release gate check queued for asynchronous execution.',
          timestamp: new Date().toISOString()
        },
        { status: 202 }
      );
    }

    let filesToScan: CodeFile[] = [];
    let targetName = rawRepoUrl;
    let changedFiles: string[] | null = null;

    if (rawRepoUrl.toLowerCase() === 'local') {
      const { WORKSPACE_SOURCE_FILES } = await import('@/data/workspaceFiles');
      filesToScan = WORKSPACE_SOURCE_FILES;
      targetName = 'Zelsis Local Workspace';
    } else if (isWebTarget) {
      const ssrfCheck = await validateSafeTargetUrl(rawRepoUrl);
      if (!ssrfCheck.safe || !ssrfCheck.url) {
        logger.warn(`[SSRF Blocked in Gate-Check] Prohibited target: ${rawRepoUrl} - Reason: ${ssrfCheck.reason}`);
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            error: `SSRF Protection Blocked Request: ${ssrfCheck.reason || 'Access to internal, private, or restricted network endpoints is forbidden.'}`,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        );
      }

      logger.info(`[Gate Check] Initiating website audit for ${rawRepoUrl}`);
      const webData = await fetchWebsiteAuditData(rawRepoUrl);
      filesToScan = webData?.files || [];
      targetName = webData?.title || rawRepoUrl;

      if (webData?.error === 'CLOUDFLARE_BOT_PROTECTION') {
        return NextResponse.json({
          status: 'ERROR',
          gateStatus: 'FAILED',
          readinessScore: 0,
          error: `Automated audit blocked by Cloudflare Bot Protection on "${rawRepoUrl}". Disable bot challenge for scanner user-agents or run audit against a staging endpoint.`,
          timestamp: new Date().toISOString()
        }, { status: 403 });
      }

      if (!webData || filesToScan.length === 0) {
        return NextResponse.json({
          status: 'ERROR',
          gateStatus: 'FAILED',
          readinessScore: 0,
          error: `Web endpoint unreachable or returned no scannable content: ${rawRepoUrl}`,
          timestamp: new Date().toISOString()
        }, { status: 502 });
      }
    } else if (isGithubTarget) {
      logger.info(`[Gate Check] Initiating GitHub repository audit for ${rawRepoUrl}`);
      const liveData = await fetchGithubRepositoryData(rawRepoUrl, githubToken, undefined, undefined, body.ref, body.base);
      changedFiles = (liveData as any)?.changedFiles || null;

      if (liveData?.error === 'REPO_NOT_FOUND') {
        logger.warn(`[Gate Check] Repository not found: ${rawRepoUrl}`);
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            readinessScore: 0,
            error: `GitHub repository not found: "${rawRepoUrl}". Verify the owner and repository name for typos.`,
            timestamp: new Date().toISOString()
          },
          { status: 404 }
        );
      }

      if (liveData?.error === 'RATE_LIMIT_EXCEEDED') {
        logger.warn(`[Gate Check] Rate limit exceeded for: ${rawRepoUrl}`);
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            readinessScore: 0,
            error: 'GitHub API rate limit reached (60 req/hr). Add a GitHub Personal Access Token (PAT) in Settings to unlock 5,000 req/hr.',
            timestamp: new Date().toISOString()
          },
          { status: 429 }
        );
      }

      if (liveData?.error === 'PRIVATE_OR_UNAUTHENTICATED' || liveData?.requiresAuth || (liveData?.isPrivate && !githubToken)) {
        logger.warn(`[Gate Check] Private or unauthenticated repository rejected: ${rawRepoUrl}`);
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            readinessScore: 0,
            error: `Private Repository Access Restricted: Unable to access "${rawRepoUrl}". A GitHub Personal Access Token (PAT) with 'repo' scope must be provided in the request body ({ "githubToken": "ghp_..." }).`,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        );
      }

      if (liveData?.isPrivate && userTier === 'Free') {
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            readinessScore: 0,
            error: 'Private repository scans are part of Zelsis Pro. Use an API key from a Pro or Enterprise account to gate private repositories.',
            timestamp: new Date().toISOString()
          },
          { status: 402 }
        );
      }

      filesToScan = liveData?.files || [];
      targetName = liveData?.name || rawRepoUrl;

      if (filesToScan.length === 0) {
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            readinessScore: 0,
            error: liveData?.error === 'EMPTY_REPOSITORY' || liveData?.isEmpty
              ? `Empty repository. No scannable source code files found in "${rawRepoUrl}".`
              : `No scannable source code files found in "${rawRepoUrl}". Verify the repository is accessible and contains source code.`,
            timestamp: new Date().toISOString()
          },
          { status: 422 }
        );
      }
    }

    const result = await runStaticCodeScan(filesToScan, targetName, { dependencyAudit: { timeoutMs: 8000 }, orgPolicy });

    // Auto-dispatch webhook notifications if URLs provided
    if (slackWebhookUrl || discordWebhookUrl) {
      dispatchWebhookAlerts(targetName, rawRepoUrl, result, { slackWebhookUrl, discordWebhookUrl }).catch((err) =>
        logger.warn('[Webhook Auto-dispatch Error]:', err?.message)
      );
    }

    // Persist scan run and audit log to Supabase
    if (serviceRoleKey) {
      try {
        const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

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
                name: targetName,
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
          await adminClient.from('scans').insert({
            project_id: projectId,
            user_id: authenticatedUserId,
            trigger_type: 'CI_CD',
            readiness_score: result.score,
            gate_status: result.gateStatus,
            critical_count: result.criticalCount,
            high_count: result.highCount,
            medium_count: result.mediumCount,
            low_count: result.lowCount,
            ui_cliche_count: result.uiClicheCount,
            scan_duration_ms: 3000
          });
        }

        await adminClient.from('audit_logs').insert({
          user_id: authenticatedUserId,
          action: 'CI_CD_SCAN_EXECUTED',
          entity_type: 'scan',
          entity_id: rawRepoUrl,
          metadata: {
            repoUrl: rawRepoUrl,
            gateStatus: result.gateStatus,
            score: result.score,
            tier: userTier
          },
          ip_address: clientIp
        });

        // F-40 / F-31: Atomically deduct quota only after scan has succeeded
        if (shouldDeductQuota && authenticatedUserId) {
          const { count } = await adminClient
            .from('subscriptions')
            .update({ scans_used_this_month: currentScansUsed + 1, updated_at: new Date().toISOString() }, { count: 'exact' })
            .eq('user_id', authenticatedUserId)
            .lte('scans_used_this_month', currentScansUsed);

          if (count === 0) {
            logger.warn(`[Gate Check] Concurrent quota decrement detected for user ${authenticatedUserId}.`);
          }
        }
      } catch (telemetryErr) {
        logger.warn('[Gate Check] Telemetry record notice:', telemetryErr);
      }
    }

    let finalGateStatus = result.gateStatus;
    let newFindings = result.findings;
    let existingFindings: typeof result.findings = [];

    if (changedFiles !== null) {
      newFindings = result.findings.filter(f => changedFiles!.includes(f.filePath));
      existingFindings = result.findings.filter(f => !changedFiles!.includes(f.filePath));

      const gFindings = gatingFindings(newFindings);
      finalGateStatus = calculateGateStatus(gFindings);
    }

    const failOnBlock = req.nextUrl.searchParams.get('failOnBlock') === 'true';
    const isPassed = finalGateStatus === 'PASSED';
    const statusCode = (failOnBlock && !isPassed) ? 422 : 200;

    return NextResponse.json(
      {
        status: 'SUCCESS',
        gateStatus: finalGateStatus,
        readinessScore: result.score,
        summary: finalGateStatus === 'PASSED'
          ? 'Production Audit PASSED. All security and design compliance checks cleared.'
          : finalGateStatus === 'WARNING'
          ? `Release WARNING. Detected ${result.highCount} High and ${result.mediumCount} Medium findings. Review recommended before production deployment.`
          : `Release BLOCKED. Detected ${result.criticalCount} Critical blocker(s) requiring immediate remediation.`,
        metrics: {
          score: result.score,
          criticalCount: result.criticalCount,
          highCount: result.highCount,
          mediumCount: result.mediumCount,
          lowCount: result.lowCount,
          uiClicheCount: result.uiClicheCount,
          filesAnalyzed: filesToScan.length,
          openFindingsCount: result.findings.length
        },
        findings: changedFiles !== null ? {
          new: newFindings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            filePath: f.filePath,
            lineRange: f.lineRange,
            remediationPrompt: canSeeFixes ? f.remediationPrompt : LOCKED_FIX_TEXT
          })),
          existing: existingFindings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            filePath: f.filePath,
            lineRange: f.lineRange,
            remediationPrompt: canSeeFixes ? f.remediationPrompt : LOCKED_FIX_TEXT
          }))
        } : result.findings.map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          category: f.category,
          filePath: f.filePath,
          lineRange: f.lineRange,
          remediationPrompt: canSeeFixes ? f.remediationPrompt : LOCKED_FIX_TEXT
        })),
        timestamp: new Date().toISOString()
      },
      {
        status: statusCode,
        headers: {
          'Deprecation': '@1798761600',
          'Sunset': 'Fri, 01 Jan 2027 00:00:00 GMT',
          'Link': '<https://zelsis.com/docs/api/v1>; rel="deprecation"'
        }
      }
    );
  } catch (error: any) {
    logger.error('[Gate Check] Internal execution error:', error);
    return NextResponse.json(
      {
        status: 'ERROR',
        gateStatus: 'FAILED',
        error: process.env.NODE_ENV === 'production'
          ? 'Internal Release Gate Audit Error'
          : (error?.message || 'Internal Release Gate Audit Error'),
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}
