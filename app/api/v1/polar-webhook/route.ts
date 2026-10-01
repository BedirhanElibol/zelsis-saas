// Polar subscription webhook handler
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';

// Polar webhook events we handle
const HANDLED_EVENTS = [
  'subscription.created',
  'subscription.updated', 
  'subscription.active',
  'subscription.uncanceled',
  'subscription.canceled',
  'subscription.revoked',
  'subscription.past_due',
  'order.created',
  'order.paid',
  'order.refunded',
];

// SEC-06: In-memory event_id deduplication to prevent webhook replay attacks
// Vercel serverless functions persist module-level state within a single instance lifecycle
const DEDUP_MAX_SIZE = 10_000;
const DEDUP_EVICT_BATCH = 2_000;
const processedEventIds = new Set<string>();

import { verifyPolarWebhookSignature, resolvePolarEntitlement, type PolarEventData } from '@/lib/polar';

/**
 * ZERO-AUTH-43: Unconditional provider HMAC signature verification on webhook receiver endpoints.
 * Utilizes timing-safe equality and provider signature verification to prevent timing attacks.
 */
function verifySignature(rawBody: string, headers: Headers, secret: string): boolean {
  if (!rawBody || !secret) {
    return false;
  }
  return typeof crypto.timingSafeEqual === 'function' && verifyPolarWebhookSignature(rawBody, headers, secret);
}

export async function POST(req: NextRequest) {
  // ZERO-AUTH-43: Unconditional provider HMAC signature verification at entry point
  const webhookSecret = process.env.POLAR_WEBHOOK_SECRET;
  if (!webhookSecret) {
    logger.error('[Polar Webhook] POLAR_WEBHOOK_SECRET is not configured. Rejecting request for security.');
    return NextResponse.json({ error: 'Webhook configuration error' }, { status: 403 });
  }

  const signatureHeader =
    req.headers.get('webhook-signature') ||
    req.headers.get('polar-webhook-signature') ||
    req.headers.get('x-polar-signature');

  if (!signatureHeader) {
    logger.warn('[Polar Webhook] Missing webhook signature header');
    return NextResponse.json({ error: 'Missing webhook signature' }, { status: 401 });
  }

  const rawBody = await req.text();

  if (!verifySignature(rawBody, req.headers, webhookSecret)) {
    logger.warn('[Polar Webhook] Rejected webhook payload due to invalid HMAC signature');
    return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 });
  }

  // Replay Attack Protection: strictly enforce timestamp
  const timestampHeader = req.headers.get('webhook-timestamp') || req.headers.get('polar-webhook-timestamp');
  if (!timestampHeader) {
    return NextResponse.json({ error: 'Missing timestamp header' }, { status: 401 });
  }

  const timestampNum = parseInt(timestampHeader, 10);
  const nowSec = Math.floor(Date.now() / 1000);
  const eventSec = timestampNum > 1e11 ? Math.floor(timestampNum / 1000) : timestampNum;
  if (Math.abs(nowSec - eventSec) > 300) {
    logger.warn('[Polar Webhook] Rejected webhook payload due to stale timestamp (replay attack protection)');
    return NextResponse.json({ error: 'Webhook timestamp too old' }, { status: 401 });
  }

  // Rate limit: max 60 webhook events per minute
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 60,
    windowSeconds: 60,
    prefix: 'polar-webhook'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  let body: {
    type?: string;
    data?: PolarEventData & {
      id?: string;
      subscription_id?: string;
      metadata?: Record<string, unknown>;
      customer?: { email?: string; external_id?: string | null };
      user?: { email?: string };
      subscription?: {
        id?: string;
        metadata?: Record<string, unknown>;
        current_period_end?: string | null;
        recurring_interval?: string | null;
        product?: { name?: string };
      } | null;
    };
  } | null = null;
  try {
    body = JSON.parse(rawBody);
  } catch (parseErr) {
    void parseErr;
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  // SEC-06: Idempotency guard — Standard Webhooks carry the event id in the `webhook-id` header.
  // The event is only recorded as processed after it was applied, so Polar retries of a
  // failed delivery are not swallowed.
  const eventId =
    req.headers.get('webhook-id') ||
    req.headers.get('polar-webhook-id') ||
    ((body as Record<string, unknown>)?.event_id as string | undefined) ||
    undefined;
  const supabaseUrlForDedup = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKeyForDedup = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const dedupClient = supabaseUrlForDedup && serviceRoleKeyForDedup
    ? createClient(supabaseUrlForDedup, serviceRoleKeyForDedup, { auth: { persistSession: false } })
    : null;

  if (eventId) {
    if (processedEventIds.has(eventId)) {
      logger.info(`[Polar Webhook] Duplicate event_id detected in memory cache, skipping: ${eventId}`);
      return NextResponse.json({ received: true, deduplicated: true });
    }
    if (dedupClient) {
      try {
        const { data: existingEvent } = await dedupClient
          .from('webhook_events')
          .select('event_id')
          .eq('event_id', eventId)
          .maybeSingle();
        if (existingEvent) {
          logger.info(`[Polar Webhook] Duplicate event_id detected in database, skipping: ${eventId}`);
          processedEventIds.add(eventId);
          return NextResponse.json({ received: true, deduplicated: true });
        }
      } catch (dbErr) {
        logger.debug('[Polar Webhook] Database idempotency lookup failed, continuing:', dbErr);
      }
    }
  }

  const markProcessed = async () => {
    if (!eventId) return;
    processedEventIds.add(eventId);
    if (processedEventIds.size > DEDUP_MAX_SIZE) {
      const iter = processedEventIds.values();
      for (let i = 0; i < DEDUP_EVICT_BATCH; i++) {
        const next = iter.next();
        if (next.done) break;
        processedEventIds.delete(next.value);
      }
    }
    if (dedupClient) {
      try {
        await dedupClient
          .from('webhook_events')
          .insert({ event_id: eventId, source: 'polar', processed_at: new Date().toISOString() });
      } catch (dbErr) {
        logger.debug('[Polar Webhook] Failed to persist processed event id:', dbErr);
      }
    }
  };

  const eventType = body?.type;
  if (!eventType || !HANDLED_EVENTS.includes(eventType)) {
    logger.debug(`[Polar Webhook] Unhandled event type: ${eventType}`);
    return NextResponse.json({ received: true, handled: false });
  }

  logger.info(`[Polar Webhook] Received event: ${eventType}`);

  try {
    const data = body?.data;
    const customerEmail = data?.customer?.email || data?.user?.email;
    
    if (!customerEmail) {
      logger.warn(`[Polar Webhook] No customer email in ${eventType} event`);
      return NextResponse.json({ received: true, error: 'No customer email' }, { status: 200 });
    }

    const entitlement = resolvePolarEntitlement(eventType, data || {});
    if (!entitlement) {
      logger.info(`[Polar Webhook] ${eventType} (status: ${data?.status ?? 'n/a'}) does not change entitlement`);
      await markProcessed();
      return NextResponse.json({ received: true, handled: false });
    }
    const { tier, status, billingCycle } = entitlement;
    const effectiveCurrentPeriodEnd = entitlement.currentPeriodEnd;
    const polarSubscriptionId = eventType.startsWith('subscription.')
      ? data?.id || null
      : data?.subscription_id || data?.subscription?.id || null;

    // Update Supabase profile and subscription records if service role key is available
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    
    if (serviceRoleKey && supabaseUrl) {
      const { createClient } = await import('@supabase/supabase-js');
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      
      const normalizedEmail = customerEmail.toLowerCase().trim();
      const metadataUserId = (data?.customer?.external_id || data?.metadata?.userId || data?.metadata?.user_id || data?.subscription?.metadata?.userId) as string | undefined;
      let matchedUserId: string | null = metadataUserId || null;
      let existingMetadata: Record<string, unknown> = {};

      // 1. Direct query in profiles table by case-insensitive email
      if (!matchedUserId) {
        try {
          const { data: profile } = await adminClient
            .from('profiles')
            .select('id, email')
            .ilike('email', normalizedEmail.replace(/[\\%_]/g, (c) => `\\${c}`))
            .maybeSingle();
          if (profile?.id) {
            matchedUserId = profile.id;
          }
        } catch (profileLookupErr) {
          void profileLookupErr;
        }
      }

      // 2. Query auth.users via admin API with expanded perPage limit
      if (!matchedUserId) {
        try {
          const { data: users } = await adminClient.auth.admin.listUsers({ perPage: 1000 });
          const matchedUser = users?.users?.find(
            (u: { email?: string; id: string; user_metadata?: Record<string, unknown> }) =>
              u.email?.toLowerCase() === normalizedEmail
          );
          if (matchedUser) {
            matchedUserId = matchedUser.id;
            existingMetadata = matchedUser.user_metadata || {};
          }
        } catch (adminListErr) {
          void adminListErr;
        }
      } else {
        try {
          const { data: userData } = await adminClient.auth.admin.getUserById(matchedUserId);
          if (userData?.user?.user_metadata) {
            existingMetadata = userData.user.user_metadata;
          }
        } catch (fetchUserErr) {
          void fetchUserErr;
        }
      }

      if (matchedUserId) {
        const formattedTier: 'Free' | 'Pro' | 'Enterprise' =
          tier === 'Enterprise' ? 'Enterprise' : (tier === 'Pro' ? 'Pro' : 'Free');

        // A. Update user metadata in auth.users with complete subscription lifecycle properties
        try {
          await adminClient.auth.admin.updateUserById(matchedUserId, {
            user_metadata: {
              ...existingMetadata,
              tier: formattedTier,
              subscriptionStatus: status,
              expiresAt: effectiveCurrentPeriodEnd,
              billingCycle,
              lastPaymentEvent: eventType,
              lastPaymentDate: new Date().toISOString(),
            }
          });
          logger.info(`[Polar Webhook] Synced auth user_metadata for ${normalizedEmail} (ID: ${matchedUserId}) -> ${formattedTier} (expires: ${effectiveCurrentPeriodEnd})`);
        } catch (authMetaErr: unknown) {
          logger.warn('[Polar Webhook] User metadata update warning:', authMetaErr instanceof Error ? authMetaErr.message : String(authMetaErr));
        }

        // B. Upsert profiles table first to satisfy foreign key constraint on subscriptions
        try {
          await adminClient.from('profiles').upsert({
            id: matchedUserId,
            email: normalizedEmail,
            tier: formattedTier,
            status,
            updated_at: new Date().toISOString()
          }, { onConflict: 'id' });
          logger.info(`[Polar Webhook] Upserted profiles record for ${normalizedEmail} (tier: ${formattedTier}, status: ${status})`);
        } catch (profileError: unknown) {
          logger.warn(`[Polar Webhook] Profile upsert notice: ${profileError instanceof Error ? profileError.message : String(profileError)}`);
        }

        // C. Upsert subscriptions record with complete period end. This row is what the
        // server-side tier gates read, so a failed write returns 500 and lets Polar retry.
        const { error: subErr } = await adminClient.from('subscriptions').upsert({
          user_id: matchedUserId,
          plan_tier: formattedTier,
          status,
          current_period_end: effectiveCurrentPeriodEnd,
          ...(polarSubscriptionId ? { polar_subscription_id: polarSubscriptionId } : {}),
          cancel_at_period_end: status === 'canceled' && tier !== 'Free',
          updated_at: new Date().toISOString(),
        }, { onConflict: 'user_id' });
        if (subErr) {
          logger.error('[Polar Webhook] Subscriptions table update failed:', subErr.message);
          return NextResponse.json({ error: 'Persistence error' }, { status: 500 });
        }
        logger.info(`[Polar Webhook] Upserted subscriptions record for ${normalizedEmail} (tier: ${formattedTier}, status: ${status})`);
      } else {
        logger.warn(`[Polar Webhook] No registered user found for email: ${normalizedEmail}. Pending account registration.`);
      }
    } else {
      logger.error('[Polar Webhook] SUPABASE_SERVICE_ROLE_KEY not configured - cannot update tier server-side');
      return NextResponse.json({ error: 'Webhook configuration error' }, { status: 500 });
    }

    await markProcessed();
    return NextResponse.json({ received: true, tier, email: customerEmail });
  } catch (err: unknown) {
    logger.error(`[Polar Webhook] Error processing ${eventType}:`, err instanceof Error ? err.message : String(err));
    return NextResponse.json({ error: 'Processing error' }, { status: 500 });
  }
}
