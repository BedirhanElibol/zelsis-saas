import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';
import { isPlatformAdminEmail } from '@/lib/subscription-utils';

// Verified subscriber registry & platform administrator list
const VERIFIED_SUBSCRIBER_EMAILS = new Set(
  (process.env.VERIFIED_SUBSCRIBERS || process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
);

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'subscription-sync'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 1. Enforce Supabase JWT Bearer token authentication
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;

  if (!supabaseUrl || !anonKey) {
    logger.error('[Subscription Sync] Supabase configuration missing');
    return NextResponse.json(
      { error: 'Authentication service configuration missing' },
      { status: 500 }
    );
  }

  const authClient = createClient(supabaseUrl, anonKey);
  const { data: authData, error: authError } = await authClient.auth.getUser(token);

  if (authError || !authData?.user) {
    logger.warn('[Subscription Sync] Unauthorized attempt with invalid or expired token:', authError?.message);
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  const authenticatedEmail = authData.user.email?.toLowerCase().trim();
  if (!authenticatedEmail) {
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  let body: { email?: string } = {};
  try {
    const rawText = await req.text();
    if (rawText) {
      body = JSON.parse(rawText);
    }
  } catch (parseErr) {
    void parseErr;
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const requestedEmail = (body?.email || '').trim().toLowerCase();
  if (requestedEmail && requestedEmail !== authenticatedEmail) {
    logger.warn(`[Subscription Sync] Email mismatch: authenticated user ${authenticatedEmail} requested ${requestedEmail}`);
    return NextResponse.json(
      { error: 'Forbidden: You can only query or synchronize your own subscription' },
      { status: 403 }
    );
  }

  const email = requestedEmail || authenticatedEmail;
  if (!email || !email.includes('@')) {
    return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
  }

  logger.info(`[Subscription Sync] Checking subscription for: ${email}`);

  if (isPlatformAdminEmail(email)) {
    logger.info(`[Subscription Sync] Immediate Platform Admin resolution for: ${email}`);
    return NextResponse.json({
      tier: 'Enterprise',
      active: true,
      status: 'active',
      expiresAt: '2099-12-31T23:59:59.999Z',
      isFounder: true
    });
  }

  let verifiedTier: 'Pro' | 'Enterprise' | 'Free' = 'Free';
  let isActive = false;
  let subStatus: 'active' | 'past_due' | 'canceled' = 'canceled';
  let expiresAt: string | undefined = undefined;
  let gracePeriodUntil: string | undefined = undefined;

  // 1. Check Polar API using multi-stage customer and subscription resolution
  if (polarAccessToken) {
    try {
      // Step A: Look up Polar customer by email
      const customerEndpoint = new URL('https://api.polar.sh/v1/customers');
      customerEndpoint.searchParams.set('email', email);
      const customerRes = await fetch(customerEndpoint.toString(), {
        headers: {
          'Authorization': `Bearer ${polarAccessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      let polarCustomerId: string | null = null;
      if (customerRes.ok) {
        const customerData = await customerRes.json();
        polarCustomerId = customerData?.items?.[0]?.id || null;
      }

      // Step B: Query subscriptions for this customer ID
      const queryParams = polarCustomerId ? `customer_id=${polarCustomerId}&active=true` : 'active=true';
      const polarRes = await fetch(`https://api.polar.sh/v1/subscriptions?${queryParams}`, {
        headers: {
          'Authorization': `Bearer ${polarAccessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (polarRes.ok) {
        const polarData = await polarRes.json();
        const polarSub = (polarData.items || []).find(
          (s: { customer_id?: string; status?: string; current_period_end?: string | null; product?: { name?: string }; customer?: { email?: string } }) => {
            const matchesId = polarCustomerId && s.customer_id === polarCustomerId;
            const matchesEmail = s.customer?.email && s.customer.email.toLowerCase() === email;
            return (matchesId || matchesEmail) && (s.status === 'active' || s.status === 'past_due');
          }
        );

          if (polarSub) {
          const periodEnd = polarSub.current_period_end ? new Date(polarSub.current_period_end) : null;
          const prodName = (polarSub.product?.name || '').toLowerCase();
          const detectedTier: 'Pro' | 'Enterprise' = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';

          if (periodEnd && periodEnd.getTime() <= Date.now()) {
            // Strictly expired: zero grace period
            logger.info(`[Subscription Sync] Polar subscription expired on ${periodEnd.toISOString()}`);
            isActive = false;
            subStatus = polarSub.status === 'past_due' ? 'past_due' : 'canceled';
            verifiedTier = 'Free';
          } else {
            // Still within valid paid period
            verifiedTier = detectedTier;
            isActive = true;
            subStatus = polarSub.status === 'past_due' ? 'past_due' : 'active';
            expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            logger.info(`[Subscription Sync] Polar active subscription confirmed: ${verifiedTier} for ${email} until ${expiresAt}`);
          }
        }
      }

      // Step C: If still not active and customer exists on Polar, check orders
      if (!isActive && polarCustomerId) {
        const ordersRes = await fetch(`https://api.polar.sh/v1/orders?customer_id=${polarCustomerId}`, {
          headers: {
            'Authorization': `Bearer ${polarAccessToken}`,
            'Content-Type': 'application/json'
          }
        });
        if (ordersRes.ok) {
          const ordersData = await ordersRes.json();
          const paidOrder = (ordersData.items || []).find(
            (o: { status?: string; product?: { name?: string }; created_at?: string }) =>
              o.status === 'paid' || o.status === 'succeeded'
          );
          if (paidOrder) {
            const prodName = (paidOrder.product?.name || '').toLowerCase();
            verifiedTier = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';
            isActive = true;
            subStatus = 'active';
            const orderDate = paidOrder.created_at ? new Date(paidOrder.created_at).getTime() : Date.now();
            expiresAt = new Date(orderDate + 30 * 24 * 60 * 60 * 1000).toISOString();
            logger.info(`[Subscription Sync] Confirmed via Polar order: ${verifiedTier} for ${email}`);
          }
        }
      }
    } catch (err: unknown) {
      logger.warn('[Subscription Sync] Polar API check failed:', err instanceof Error ? err.message : String(err));
    }
  }

  // 2. Check Supabase database if not found via Polar API
  if (!isActive) {
    const keyToUse = serviceRoleKey || anonKey;
    if (keyToUse) {
      try {
        const client = createClient(supabaseUrl, keyToUse);

        // A. Primary direct lookup by authenticated user_id
        let subRecord: { plan_tier?: string; status?: string; current_period_end?: string | null } | null = null;
        
        if (authData?.user?.id) {
          const { data: subByUserId } = await client
            .from('subscriptions')
            .select('plan_tier, status, current_period_end')
            .eq('user_id', authData.user.id)
            .maybeSingle();
          if (subByUserId) subRecord = subByUserId;
        }

        // B. Secondary lookup in profiles table by case-insensitive email
        if (!subRecord) {
          const { data: profile } = await client
            .from('profiles')
            .select('id, email, tier, status')
            .ilike('email', email.replace(/[\\%_]/g, (c) => `\\${c}`))
            .maybeSingle();

          if (profile?.id) {
            const { data: subByProfile } = await client
              .from('subscriptions')
              .select('plan_tier, status, current_period_end')
              .eq('user_id', profile.id)
              .maybeSingle();
            if (subByProfile) {
              subRecord = subByProfile;
            } else if (profile.tier === 'Pro' || profile.tier === 'Enterprise') {
              subRecord = {
                plan_tier: profile.tier,
                status: profile.status || 'active',
                current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
              };
            }
          }
        }

        if (subRecord) {
          const rawPlanTier = subRecord.plan_tier as string | undefined;
          const subPlanTier = rawPlanTier === 'Enterprise' ? 'Enterprise' : (rawPlanTier === 'Pro' ? 'Pro' : undefined);

          if (subPlanTier) {
            const periodEnd = subRecord.current_period_end ? new Date(subRecord.current_period_end) : null;

            if (periodEnd && periodEnd.getTime() <= Date.now()) {
              // Zero grace period: subscription period has elapsed
              logger.info(`[Subscription Sync] Supabase subscription expired on ${periodEnd.toISOString()}`);
              isActive = false;
              subStatus = (subRecord.status === 'past_due' || subRecord.status === 'canceled') ? subRecord.status : 'canceled';
              verifiedTier = 'Free';
            } else {
              // User has active valid time remaining (even if renewal is canceled or past_due)
              verifiedTier = subPlanTier;
              isActive = true;
              subStatus = (subRecord.status === 'past_due' || subRecord.status === 'canceled') ? subRecord.status : 'active';
              expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
              logger.info(`[Subscription Sync] Supabase subscription confirmed: ${verifiedTier} for ${email} until ${expiresAt}`);
            }
          }
        }
      } catch (err: unknown) {
        logger.warn('[Subscription Sync] Supabase check error:', err instanceof Error ? err.message : String(err));
      }
    }
  }

  // 3. Platform Administrator and Verified Subscriber Registry Resolution
  const userMetadata = authData.user.user_metadata || {};
  const isFounder = isPlatformAdminEmail(email);

  if (!isActive && isFounder) {
    verifiedTier = 'Enterprise';
    isActive = true;
    subStatus = 'active';
    expiresAt = '2099-12-31T23:59:59.999Z';
    logger.info(`[Subscription Sync] Confirmed administrator clearance: ${verifiedTier} for ${email}`);
  } else if (!isActive && VERIFIED_SUBSCRIBER_EMAILS.has(email)) {
    verifiedTier = isFounder ? 'Enterprise' : 'Pro';
    isActive = true;
    subStatus = 'active';
    expiresAt = isFounder ? '2099-12-31T23:59:59.999Z' : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    logger.info(`[Subscription Sync] Confirmed verified subscriber registry: ${verifiedTier} for ${email}`);
  }

  // 4. Strict Free Tier Enforcement & Cloud Metadata Auto-Healing for Non-Subscribers
  if (!isActive && !isFounder) {
    verifiedTier = 'Free';
    expiresAt = undefined;
    subStatus = 'canceled';

    // Auto-heal tainted user_metadata in Supabase database if previous buggy code stored Enterprise or 2099
    if (userMetadata.tier && (userMetadata.tier !== 'Free' || (userMetadata.expiresAt as string)?.includes('2099'))) {
      logger.info(`[Subscription Sync] Non-subscriber ${email} had tainted metadata. Auto-healing to Free in cloud database.`);
      if (serviceRoleKey) {
        try {
          const adminClient = createClient(supabaseUrl, serviceRoleKey);
          await adminClient.auth.admin.updateUserById(authData.user.id, {
            user_metadata: {
              ...userMetadata,
              tier: 'Free',
              expiresAt: null,
              subscriptionStatus: 'canceled'
            }
          });
        } catch (healErr) {
          logger.warn('[Subscription Sync] Failed to auto-heal tainted user_metadata in Supabase auth:', healErr);
        }
      }
    }
  }

  // 5. Update Supabase subscriptions and profiles if service role is present
  if (serviceRoleKey && isActive) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      const userId = authData.user.id;
      if (userId) {
        await adminClient.from('profiles').upsert({
          id: userId,
          email: email,
          tier: verifiedTier,
          status: subStatus,
          updated_at: new Date().toISOString()
        }, { onConflict: 'id' });

        await adminClient.from('subscriptions').upsert({
          user_id: userId,
          plan_tier: verifiedTier,
          status: subStatus,
          current_period_end: expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });

        await adminClient.auth.admin.updateUserById(userId, {
          user_metadata: {
            ...userMetadata,
            tier: verifiedTier,
            subscriptionStatus: subStatus,
            expiresAt: expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
          }
        }).catch(() => {});
      }
    } catch (syncUpdateErr: unknown) {
      logger.warn('[Subscription Sync] Admin update notice:', syncUpdateErr instanceof Error ? syncUpdateErr.message : String(syncUpdateErr));
    }
  }

  return NextResponse.json({
    active: isActive,
    status: subStatus,
    tier: verifiedTier,
    expiresAt,
    gracePeriodUntil,
    email
  });
}
