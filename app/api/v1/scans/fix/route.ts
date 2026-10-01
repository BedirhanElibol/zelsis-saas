import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { RevealFixRequestSchema, validateRequestBody } from '@/lib/validations/api-schemas';
import { hasFixPromptAccess, isPlatformAdminEmail, resolveServerPlanTier } from '@/lib/subscription-utils';
import { FREE_FIX_TRIAL_LIMIT, StoredFix } from '@/lib/fix-gate';

export const dynamic = 'force-dynamic';

function errorResponse(error: string, status: number, extra: Record<string, unknown> = {}) {
  return NextResponse.json({ status: 'ERROR', error, ...extra }, { status });
}

/**
 * Reveals the withheld fix text for one finding of a Free-tier scan job.
 * Pro/Enterprise: always allowed. Free: allowed for findings already revealed,
 * otherwise consumes the lifetime trial (subscriptions.fix_prompts_used).
 */
export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'scans-fix'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return errorResponse('Database service configuration missing', 500);
  }

  const parsed = validateRequestBody<z.infer<typeof RevealFixRequestSchema>>(RevealFixRequestSchema, await req.json().catch(() => null));
  if (!parsed.success) return parsed.response;
  const { jobId, ref } = parsed.data;

  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    return errorResponse('Please sign in to view fixes.', 401);
  }
  const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
  const { data: { user } } = await authClient.auth.getUser(token);
  if (!user) {
    return errorResponse('Please sign in to view fixes.', 401);
  }

  const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  try {
    const { data: fixRow } = await adminClient
      .from('scan_job_fixes')
      .select('fixes, revealed_finding_ids')
      .eq('job_id', jobId)
      .eq('user_id', user.id)
      .maybeSingle();

    const fix = (fixRow?.fixes as Record<string, StoredFix> | undefined)?.[ref];
    if (!fixRow || !fix) {
      return errorResponse('Fix not found for this finding.', 404);
    }

    const { data: sub } = await adminClient
      .from('subscriptions')
      .select('plan_tier, current_period_end, fix_prompts_used')
      .eq('user_id', user.id)
      .maybeSingle();

    const tier = resolveServerPlanTier({
      storedTier: sub?.plan_tier,
      currentPeriodEnd: sub?.current_period_end,
      isAdmin: isPlatformAdminEmail(user.email)
    });
    const revealed: string[] = fixRow.revealed_finding_ids || [];
    const trialUsed: number = sub?.fix_prompts_used ?? 0;

    if (hasFixPromptAccess(tier) || revealed.includes(ref)) {
      return NextResponse.json({ status: 'SUCCESS', fix, trialUsed, trialLimit: FREE_FIX_TRIAL_LIMIT });
    }

    if (!sub || trialUsed >= FREE_FIX_TRIAL_LIMIT) {
      return errorResponse('Free fix trial used. Upgrade to Zelsis Pro for unlimited fixes.', 403, {
        trialUsed,
        trialLimit: FREE_FIX_TRIAL_LIMIT
      });
    }

    // Compare-and-set so parallel requests cannot spend the trial twice
    const { data: claimed } = await adminClient
      .from('subscriptions')
      .update({ fix_prompts_used: trialUsed + 1 })
      .eq('user_id', user.id)
      .eq('fix_prompts_used', trialUsed)
      .select('user_id');

    if (!claimed || claimed.length === 0) {
      return errorResponse('Free fix trial used. Upgrade to Zelsis Pro for unlimited fixes.', 403, {
        trialUsed: trialUsed + 1,
        trialLimit: FREE_FIX_TRIAL_LIMIT
      });
    }

    const { error: revealErr } = await adminClient
      .from('scan_job_fixes')
      .update({ revealed_finding_ids: [...revealed, ref] })
      .eq('job_id', jobId);
    if (revealErr) {
      logger.warn(`[Scan Fix] Could not record revealed finding for ${jobId}:`, revealErr);
    }

    return NextResponse.json({ status: 'SUCCESS', fix, trialUsed: trialUsed + 1, trialLimit: FREE_FIX_TRIAL_LIMIT });
  } catch (err: unknown) {
    logger.error('[Scan Fix] Unexpected error:', err);
    return errorResponse('Could not load fix.', 500);
  }
}
