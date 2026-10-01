import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { FREE_SCAN_LIMIT } from '@/lib/quota-manager';
import { isPlatformAdminEmail } from '@/lib/subscription-utils';
import { getEffectivePlanTier } from '@/lib/organization';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

function getAdminClient() {
  if (!SUPABASE_URL) return null;
  const key = SERVICE_ROLE_KEY || ANON_KEY;
  if (!key) return null;
  return createClient(SUPABASE_URL, key, {
    auth: { persistSession: false }
  });
}

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1'
  );
}

/**
 * Resolves user from Supabase JWT Bearer token
 */
async function resolveAuthUser(req: NextRequest) {
  const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!authHeader) return null;

  try {
    const authClient = createClient(SUPABASE_URL, ANON_KEY, {
      auth: { persistSession: false }
    });
    const { data: { user }, error } = await authClient.auth.getUser(authHeader);
    if (error || !user) return null;
    return user;
  } catch (err) {
    logger.warn('[Quota API] Error resolving JWT bearer token:', err);
    return null;
  }
}

/**
 * GET /api/v1/quota
 * Fetches authoritative scan quota, tier limits, and billing cycle for the authenticated user.
 * Automatically performs monthly rollover reset if current_period_end has elapsed.
 */
export async function GET(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 60,
    windowSeconds: 60,
    prefix: 'quota-get'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const user = await resolveAuthUser(req);
  if (!user) {
    return NextResponse.json({
      tier: 'Free',
      scansUsed: 0,
      scansLimit: FREE_SCAN_LIMIT,
      remaining: FREE_SCAN_LIMIT,
      billingCycleReset: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      status: 'unauthenticated'
    });
  }

  const userEmail = (user.email || '').toLowerCase().trim();
  if (isPlatformAdminEmail(userEmail)) {
    return NextResponse.json({
      tier: 'Enterprise',
      scansUsed: 0,
      scansLimit: 'Unlimited',
      remaining: 'Unlimited',
      billingCycleReset: '2099-12-31T23:59:59.999Z',
      status: 'active'
    });
  }

  const adminClient = getAdminClient();
  if (!adminClient) {
    return NextResponse.json({
      tier: 'Free',
      scansUsed: 0,
      scansLimit: FREE_SCAN_LIMIT,
      remaining: FREE_SCAN_LIMIT,
      billingCycleReset: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      status: 'active'
    });
  }
  const userId = user.id;

  try {
    // 1. Fetch user profile and subscription
    const { data: sub, error: subError } = await adminClient
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .maybeSingle();

    if (subError) {
      logger.warn(`[Quota API] Subscriptions query notice for ${userId}:`, subError.message);
    }

    const { data: profile } = await adminClient
      .from('profiles')
      .select('tier, status')
      .eq('id', userId)
      .maybeSingle();

    let planTier: 'Free' | 'Pro' | 'Enterprise' = (sub?.plan_tier as any) || (profile?.tier as any) || 'Free';
    let status = sub?.status || profile?.status || 'active';
    let scansUsed = sub?.scans_used_this_month ?? 0;
    let periodEnd = sub?.current_period_end ? new Date(sub.current_period_end) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    // 2. Check Monthly Rollover (Computed in-memory for idempotent GET requests)
    if (periodEnd.getTime() < Date.now()) {
      logger.info(`[Quota API] Monthly period expired for ${userId}. Projecting rollover counter in-memory.`);
      scansUsed = 0;
      const newEnd = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      periodEnd = new Date(newEnd);
      // A paid period that elapsed without a webhook renewal no longer grants paid access
      if (planTier !== 'Free') {
        planTier = 'Free';
        status = 'canceled';
      }
    }
    // A seat in an Enterprise workspace grants Pro even without an own subscription
    if (planTier === 'Free') planTier = await getEffectivePlanTier(adminClient, userId, user.email);
    const monthlyQuota = planTier === 'Free' ? FREE_SCAN_LIMIT : (sub?.monthly_scan_quota ?? 1000);

    const isUnlimited = planTier !== 'Free';
    const remaining = isUnlimited ? 'Unlimited' : Math.max(0, monthlyQuota - scansUsed);

    const payload = {
      tier: planTier,
      scansUsed,
      scansLimit: isUnlimited ? 'Unlimited' : monthlyQuota,
      remaining,
      billingCycleReset: periodEnd.toISOString(),
      status
    };

    const payloadStr = JSON.stringify(payload);
    const etag = `"${crypto.createHash('sha256').update(`${userId}:${planTier}:${scansUsed}:${remaining}`).digest('base64url').substring(0, 27)}"`;
    const ifNoneMatch = req.headers.get('if-none-match');

    const headers: Record<string, string> = {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'private, max-age=10, s-maxage=10, stale-while-revalidate=30',
      'ETag': etag,
    };

    if (ifNoneMatch && ifNoneMatch === etag) {
      return new NextResponse(null, { status: 304, headers });
    }

    return new NextResponse(payloadStr, { headers });
  } catch (err: unknown) {
    logger.error('[Quota API] Error retrieving quota:', err instanceof Error ? err.message : String(err));
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

/**
 * POST /api/v1/quota
 * Enforces atomic scan reservation, deducts monthly quota, records scan executions in public.scans,
 * and logs telemetry in public.audit_logs.
 */
export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'quota-post'
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

  const user = await resolveAuthUser(req);
  const body = await req.json().catch(() => ({}));
  const action = body.action || 'consume_scan';
  const ip = getClientIp(req);
  const adminClient = getAdminClient();

  // 1. Scans require an authenticated account
  if (!user) {
    return NextResponse.json(
      {
        allowed: false,
        error: 'Please sign in or create a free account to run audits.',
        status: 'unauthenticated'
      },
      { status: 401 }
    );
  }

  const userId = user.id;
  const userEmail = (user.email || '').toLowerCase().trim();
  const isAdmin = isPlatformAdminEmail(userEmail);

  if (!adminClient) {
    return NextResponse.json({
      allowed: true,
      scansUsed: 1,
      scansLimit: FREE_SCAN_LIMIT,
      remaining: FREE_SCAN_LIMIT - 1,
      scanId: `scan-${Date.now()}`
    });
  }

  try {
    // 2. Fetch active subscription & profile
    const { data: sub } = await adminClient
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .maybeSingle();

    const { data: profile } = await adminClient
      .from('profiles')
      .select('tier, status')
      .eq('id', userId)
      .maybeSingle();

    // Billing period elapsed: Free quota rolls over, unrenewed paid plans fall back to Free
    const periodElapsed = Boolean(sub?.current_period_end && new Date(sub.current_period_end).getTime() < Date.now());
    const storedTier: 'Free' | 'Pro' | 'Enterprise' = (sub?.plan_tier as any) || (profile?.tier as any) || 'Free';
    let planTier: 'Free' | 'Pro' | 'Enterprise' = isAdmin
      ? 'Enterprise'
      : (periodElapsed ? 'Free' : storedTier);
    // A seat in an Enterprise workspace grants Pro even without an own subscription
    if (planTier === 'Free') planTier = await getEffectivePlanTier(adminClient, userId, userEmail);
    const isFree = planTier === 'Free';
    const monthlyQuota = isFree ? FREE_SCAN_LIMIT : (sub?.monthly_scan_quota ?? FREE_SCAN_LIMIT);
    const currentScansUsed = periodElapsed ? 0 : (sub?.scans_used_this_month ?? 0);

    // 3. ACTION: CONSUME_SCAN
    if (action === 'consume_scan') {
      if (isFree && currentScansUsed >= monthlyQuota) {
        logger.warn(`[Quota API] User ${userId} (${user.email}) exceeded free monthly quota: ${currentScansUsed}/${monthlyQuota}`);
        return NextResponse.json(
          {
            allowed: false,
            error: `Monthly scan quota reached (${currentScansUsed}/${monthlyQuota} scans used). Upgrade to Zelsis Pro for unlimited automated audits.`,
            tier: planTier,
            scansUsed: currentScansUsed,
            scansLimit: monthlyQuota,
            remaining: 0
          },
          { status: 402 }
        );
      }

      const newScansUsed = currentScansUsed + 1;
      if (SERVICE_ROLE_KEY && isFree && sub) {
        const now = Date.now();
        await adminClient
          .from('subscriptions')
          .update({
            ...(periodElapsed
              ? {
                  plan_tier: 'Free',
                  status: storedTier === 'Free' ? (sub.status || 'active') : 'canceled',
                  current_period_start: new Date(now).toISOString(),
                  current_period_end: new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString()
                }
              : {}),
            scans_used_this_month: newScansUsed,
            updated_at: new Date(now).toISOString()
          })
          .eq('user_id', userId);
      }

      let targetProjectId: string | null = null;
      const rawProjectId = body.projectId;
      const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawProjectId || '');

      if (isUuid && rawProjectId) {
        const { data: existingProj } = await adminClient
          .from('projects')
          .select('id')
          .eq('id', rawProjectId)
          .eq('user_id', userId)
          .maybeSingle();
        if (existingProj?.id) {
          targetProjectId = existingProj.id;
        }
      }

      if (!targetProjectId && body.repoUrl && SERVICE_ROLE_KEY) {
        const { data: existingByUrl } = await adminClient
          .from('projects')
          .select('id')
          .eq('user_id', userId)
          .eq('repo_url', body.repoUrl)
          .maybeSingle();

        if (existingByUrl?.id) {
          targetProjectId = existingByUrl.id;
        } else {
          const { data: newProj } = await adminClient
            .from('projects')
            .insert({
              user_id: userId,
              name: body.projectName || body.repoUrl.split('/').pop() || 'Audit Project',
              repo_url: body.repoUrl,
              framework: body.framework || 'Auto-Detect',
              readiness_score: body.readinessScore ?? 100,
              gate_status: body.gateStatus ?? 'PASSED'
            })
            .select('id')
            .maybeSingle();
          if (newProj?.id) {
            targetProjectId = newProj.id;
          }
        }
      }

      let scanId: string | null = null;
      if (targetProjectId && SERVICE_ROLE_KEY) {
        const { data: scanRecord } = await adminClient
          .from('scans')
          .insert({
            project_id: targetProjectId,
            user_id: userId,
            trigger_type: body.triggerType || 'MANUAL',
            readiness_score: body.readinessScore ?? 100,
            gate_status: body.gateStatus || 'PASSED',
            critical_count: body.criticalCount ?? 0,
            high_count: body.highCount ?? 0,
            medium_count: body.mediumCount ?? 0,
            low_count: body.lowCount ?? 0,
            ui_cliche_count: body.uiClicheCount ?? 0,
            scan_duration_ms: body.scanDurationMs ?? 0
          })
          .select('id')
          .maybeSingle();

        if (scanRecord?.id) {
          scanId = scanRecord.id;
        }
      }

      if (SERVICE_ROLE_KEY) {
        await adminClient.from('audit_logs').insert({
          user_id: userId,
          action: 'SCAN_EXECUTED',
          entity_type: 'scan',
          entity_id: scanId || targetProjectId || userId,
          metadata: {
            repoUrl: body.repoUrl,
            tier: planTier,
            scansUsed: newScansUsed,
            quotaLimit: monthlyQuota,
            scanId
          },
          ip_address: ip
        });
      }

      logger.info(`[Quota API] Scan successfully authorized for ${user.email} (tier: ${planTier}, used: ${newScansUsed})`);

      return NextResponse.json({
        allowed: true,
        tier: planTier,
        scansUsed: newScansUsed,
        scansLimit: isFree ? monthlyQuota : 'Unlimited',
        remaining: isFree ? Math.max(0, monthlyQuota - newScansUsed) : 'Unlimited',
        scanId,
        projectId: targetProjectId
      });
    }

    // 4. ACTION: COMPLETE_SCAN (Updates final scan metrics)
    if (action === 'complete_scan') {
      const scanId = body.scanId;
      const isUuidScan = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scanId || '');
      if (isUuidScan && SERVICE_ROLE_KEY) {
        // Ownership check: only the scan owner may finalize it
        const { data: ownedScan } = await adminClient
          .from('scans')
          .select('id, project_id')
          .eq('id', scanId)
          .eq('user_id', userId)
          .maybeSingle();

        if (!ownedScan) {
          return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
        }

        await adminClient
          .from('scans')
          .update({
            readiness_score: body.readinessScore,
            gate_status: body.gateStatus,
            critical_count: body.criticalCount,
            high_count: body.highCount,
            medium_count: body.mediumCount,
            low_count: body.lowCount,
            ui_cliche_count: body.uiClicheCount,
            scan_duration_ms: body.scanDurationMs
          })
          .eq('id', ownedScan.id);

        if (ownedScan.project_id) {
          await adminClient
            .from('projects')
            .update({
              readiness_score: body.readinessScore,
              gate_status: body.gateStatus,
              critical_count: body.criticalCount,
              high_count: body.highCount,
              medium_count: body.mediumCount,
              low_count: body.lowCount,
              ui_cliche_count: body.uiClicheCount,
              last_scan_at: new Date().toISOString()
            })
            .eq('id', ownedScan.project_id)
            .eq('user_id', userId);
        }

        await adminClient.from('audit_logs').insert({
          user_id: userId,
          action: 'SCAN_COMPLETED',
          entity_type: 'scan',
          entity_id: scanId,
          metadata: {
            score: body.readinessScore,
            gateStatus: body.gateStatus,
            durationMs: body.scanDurationMs
          },
          ip_address: ip
        });
      }

      return NextResponse.json({ success: true });
    }

    return NextResponse.json({ error: `Unknown action: ${action}` }, { status: 400 });
  } catch (err: unknown) {
    logger.error('[Quota API] Post handler error:', err instanceof Error ? err.message : String(err));
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
