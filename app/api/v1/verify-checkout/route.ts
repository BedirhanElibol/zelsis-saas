import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';
import { detectPolarPlanTier } from '@/lib/polar';

export const maxDuration = 15;
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'verify-checkout'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const { checkoutId, email, planId } = body;
  if (!checkoutId || typeof checkoutId !== 'string') {
    return NextResponse.json({ error: 'checkout_id is required' }, { status: 400 });
  }

  // F-14: MANDATORY Caller Authorization — reject unauthenticated requests
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;

  if (!token || !supabaseUrl || !anonKey) {
    return NextResponse.json(
      { error: 'Authentication required to verify checkout' },
      { status: 401 }
    );
  }

  let authenticatedUserId: string | null = null;
  let authenticatedEmail: string | null = null;

  try {
    const authClient = createClient(supabaseUrl, anonKey);
    const { data: authData, error: authError } = await authClient.auth.getUser(token);
    if (authError || !authData?.user) {
      return NextResponse.json(
        { error: 'Invalid or expired authentication token' },
        { status: 401 }
      );
    }
    authenticatedUserId = authData.user.id;
    authenticatedEmail = authData.user.email?.toLowerCase().trim() || null;
  } catch {
    return NextResponse.json(
      { error: 'Authentication verification failed' },
      { status: 401 }
    );
  }

  // 1. Enforce Polar API verification requirement
  if (!polarAccessToken) {
    logger.warn('[Verify Checkout] Polar API access token is missing');
    return NextResponse.json(
      { verified: false, status: 'unverified', error: 'Polar API verification is not configured on server' },
      { status: 500 }
    );
  }

  let isVerified = false;
  let resolvedTier: 'Pro' | 'Enterprise' = planId === 'vibecare' ? 'Enterprise' : 'Pro';
  let customerEmail = authenticatedEmail || email || null;
  let effectiveExpiry: string = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  let billingCycle: 'monthly' | 'annual' = 'monthly';

  // 2. Query Polar API for authentic checkout status
  try {
    const response = await fetch(`https://api.polar.sh/v1/checkouts/${checkoutId}`, {
      headers: {
        'Authorization': `Bearer ${polarAccessToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const checkout = await response.json();
      // 'confirmed' only means the payment is being processed; access is granted on 'succeeded'.
      if (checkout.status === 'succeeded') {
        isVerified = true;
        customerEmail = checkout.customer_email || customerEmail;
        resolvedTier = detectPolarPlanTier(checkout.product?.name);
        const isAnnual = checkout.product_price?.recurring_interval === 'year' || checkout.product?.recurring_interval === 'year';
        billingCycle = isAnnual ? 'annual' : 'monthly';
        // Anchor the fallback period to when the checkout happened, so replaying an old
        // checkout id cannot extend access indefinitely.
        const checkoutTime = new Date(checkout.modified_at || checkout.created_at || Date.now()).getTime();
        const periodStart = isNaN(checkoutTime) ? Date.now() : Math.min(checkoutTime, Date.now());
        effectiveExpiry = new Date(periodStart + (isAnnual ? 365 : 30) * 24 * 60 * 60 * 1000).toISOString();

        // F-14: Read the authentic period end from the created subscription. The checkout's own
        // `expires_at` is the checkout session expiry and must not be used as the plan expiry.
        const subscriptionId: string | undefined = checkout.subscription_id || checkout.subscription?.id;
        if (subscriptionId) {
          try {
            const subRes = await fetch(`https://api.polar.sh/v1/subscriptions/${encodeURIComponent(subscriptionId)}`, {
              headers: { 'Authorization': `Bearer ${polarAccessToken}`, 'Content-Type': 'application/json' }
            });
            if (subRes.ok) {
              const sub = await subRes.json();
              const polarExpiry = sub?.current_period_end ? new Date(sub.current_period_end) : null;
              if (polarExpiry && !isNaN(polarExpiry.getTime())) {
                effectiveExpiry = polarExpiry.toISOString();
              }
              if (sub?.recurring_interval === 'year') billingCycle = 'annual';
            }
          } catch (subErr: any) {
            logger.warn('[Verify Checkout] Polar subscription lookup failed:', subErr?.message);
          }
        }

        logger.info(`[Verify Checkout] Verified via Polar API: ${resolvedTier} for ${customerEmail} (expires: ${effectiveExpiry})`);
      }
    }
  } catch (apiErr: any) {
    logger.warn('[Verify Checkout] Polar API check exception:', apiErr?.message);
  }

  // Reject if Polar API did not verify the checkout
  if (!isVerified) {
    return NextResponse.json(
      { verified: false, status: 'unverified', error: 'Polar API checkout verification failed or pending' },
      { status: 400 }
    );
  }

  // F-14: Email cross-check — prevent user A from claiming user B's checkout
  if (customerEmail && authenticatedEmail && customerEmail.toLowerCase().trim() !== authenticatedEmail) {
    logger.warn(`[Verify Checkout] Email mismatch: authenticated=${authenticatedEmail}, checkout=${customerEmail}`);
    return NextResponse.json(
      { verified: false, error: 'Checkout email does not match authenticated user' },
      { status: 403 }
    );
  }

  logger.info(`[Verify Checkout] Verified checkout ${checkoutId} for user ${authenticatedUserId} (${authenticatedEmail})`);

  // 3. Persist verified tier to Supabase subscriptions and metadata via direct O(1) user ID lookup (F-14)
  if (isVerified && serviceRoleKey && supabaseUrl) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      const normalizedEmail = (customerEmail || '').toLowerCase().trim();

      // Direct O(1) user ID resolution (F-14: No O(N) listUsers({ perPage: 1000 }))
      let targetUserId = authenticatedUserId;

      if (!targetUserId && normalizedEmail) {
        // Query profiles table by email
        const { data: profile } = await adminClient
          .from('profiles')
          .select('id')
          .ilike('email', normalizedEmail)
          .maybeSingle();

        if (profile?.id) {
          targetUserId = profile.id;
        }
      }

      if (targetUserId) {
        // Fetch existing metadata directly for this user (O(1))
        let existingMetadata: Record<string, unknown> = {};
        try {
          const { data: userData } = await adminClient.auth.admin.getUserById(targetUserId);
          if (userData?.user?.user_metadata) {
            existingMetadata = userData.user.user_metadata;
          }
        } catch (getUserErr) {
          logger.warn(`[Verify Checkout] getUserById error for ${targetUserId}:`, getUserErr);
        }

        // Update user metadata in auth.users
        await adminClient.auth.admin.updateUserById(targetUserId, {
          user_metadata: {
            ...existingMetadata,
            tier: resolvedTier,
            subscriptionStatus: 'active',
            expiresAt: effectiveExpiry,
            billingCycle,
          }
        });

        // Upsert profiles record first to satisfy foreign key constraint
        await adminClient.from('profiles').upsert({
          id: targetUserId,
          email: normalizedEmail || existingMetadata.email,
          tier: resolvedTier,
          status: 'active',
          updated_at: new Date().toISOString()
        }, { onConflict: 'id' });

        // Upsert subscriptions record
        await adminClient.from('subscriptions').upsert({
          user_id: targetUserId,
          plan_tier: resolvedTier,
          status: 'active',
          current_period_end: effectiveExpiry,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'user_id' });

        logger.info(`[Verify Checkout] Persisted subscription tier ${resolvedTier} for user ${targetUserId} (expires: ${effectiveExpiry})`);
      }
    } catch (dbErr: any) {
      logger.warn('[Verify Checkout] Database update notice:', dbErr?.message);
    }
  }

  return NextResponse.json({
    verified: true,
    status: 'confirmed',
    tier: resolvedTier,
    expiresAt: effectiveExpiry,
    email: customerEmail
  });
}
