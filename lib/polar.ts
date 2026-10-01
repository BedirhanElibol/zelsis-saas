import crypto from 'crypto';
import { logger } from '@/lib/logger';

/**
 * Verifies Polar / Standard Webhooks HMAC-SHA256 signatures.
 * Supports both Standard Webhooks format (v1,base64... where toSign is ${webhookId}.${timestamp}.${rawBody})
 * and raw HMAC-SHA256 hex or base64 signatures.
 */
export function verifyPolarWebhookSignature(
  rawBody: string,
  headers: Headers,
  secret: string
): boolean {
  const signatureHeader =
    headers.get('webhook-signature') ||
    headers.get('polar-webhook-signature') ||
    headers.get('x-polar-signature');

  if (!signatureHeader) {
    return false;
  }

  const webhookId =
    headers.get('webhook-id') ||
    headers.get('polar-webhook-id') ||
    '';
  const timestamp =
    headers.get('webhook-timestamp') ||
    headers.get('polar-webhook-timestamp') ||
    '';

  // Enforce timestamp freshness: reject payloads older than 5 minutes (300 seconds) or in the future
  if (timestamp) {
    const tsNum = parseInt(timestamp, 10);
    if (isNaN(tsNum)) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const eventSec = tsNum > 1e11 ? Math.floor(tsNum / 1000) : tsNum;
    if (Math.abs(nowSec - eventSec) > 300) {
      logger.warn('[Polar Webhook] Rejected webhook payload due to stale/future timestamp');
      return false;
    }
  }

  // Support keys starting with "whsec_" (standard webhooks) as base64 or raw
  const secretKeys: Buffer[] = [];
  if (secret.startsWith('whsec_')) {
    try {
      secretKeys.push(Buffer.from(secret.slice(6), 'base64'));
    } catch {
      // Ignore decoding failure
    }
  }
  secretKeys.push(Buffer.from(secret, 'utf-8'));

  // Prepare possible signing payloads
  const payloads: string[] = [];
  if (webhookId && timestamp) {
    payloads.push(`${webhookId}.${timestamp}.${rawBody}`);
  }
  payloads.push(rawBody);

  // Signatures can be space-delimited list of tokens, e.g. "v1,abc v1,def"
  const tokens = signatureHeader.trim().split(/\s+/);

  for (const token of tokens) {
    let sigCandidate = token;
    if (token.startsWith('v1,')) {
      sigCandidate = token.slice(3);
    } else if (token.includes(',')) {
      const parts = token.split(',');
      sigCandidate = parts[parts.length - 1];
    }

    for (const key of secretKeys) {
      for (const payload of payloads) {
        try {
          const hmac = crypto.createHmac('sha256', key).update(payload, 'utf-8').digest();
          const expectedBase64 = hmac.toString('base64');
          const expectedHex = hmac.toString('hex');

          // Base64 compare
          const candBase64Buf = Buffer.from(sigCandidate, 'utf-8');
          const expBase64Buf = Buffer.from(expectedBase64, 'utf-8');
          if (candBase64Buf.length === expBase64Buf.length && crypto.timingSafeEqual(candBase64Buf, expBase64Buf)) {
            return true;
          }

          // Hex compare
          const candHexBuf = Buffer.from(sigCandidate.toLowerCase(), 'utf-8');
          const expHexBuf = Buffer.from(expectedHex.toLowerCase(), 'utf-8');
          if (candHexBuf.length === expHexBuf.length && crypto.timingSafeEqual(candHexBuf, expHexBuf)) {
            return true;
          }

          // Direct byte buffer compare (if candidate is valid base64)
          try {
            const rawCandBuf = Buffer.from(sigCandidate, 'base64');
            if (rawCandBuf.length === hmac.length && crypto.timingSafeEqual(rawCandBuf, hmac)) {
              return true;
            }
          } catch {
            // Ignore
          }
        } catch {
          // Continue trying candidates
        }
      }
    }
  }

  return false;
}

export type PlanTier = 'Free' | 'Pro' | 'Enterprise';
export type EntitlementStatus = 'active' | 'past_due' | 'canceled';

/** Maps a Polar product name to the plan tier it grants. */
export function detectPolarPlanTier(productName?: string | null): 'Pro' | 'Enterprise' {
  const name = (productName || '').toLowerCase();
  return name.includes('enterprise') || name.includes('suite') ? 'Enterprise' : 'Pro';
}

export interface PolarEventData {
  status?: string;
  current_period_end?: string | null;
  ended_at?: string | null;
  cancel_at_period_end?: boolean | null;
  recurring_interval?: string | null;
  product?: { name?: string; recurring_interval?: string | null };
  subscription?: {
    current_period_end?: string | null;
    recurring_interval?: string | null;
    product?: { name?: string };
  } | null;
}

export interface PolarEntitlement {
  tier: PlanTier;
  status: EntitlementStatus;
  currentPeriodEnd: string;
  billingCycle: 'monthly' | 'annual';
}

/**
 * Derives the entitlement a Polar webhook event grants. Subscription events are
 * resolved from the subscription's own `status` (Polar sends `subscription.updated`
 * for every change, including cancellations and revocations), and order events
 * only grant access once the order is paid. Returns null when the event must not
 * change the stored entitlement (e.g. an unpaid order or an incomplete subscription).
 */
export function resolvePolarEntitlement(
  eventType: string,
  data: PolarEventData,
  now: number = Date.now()
): PolarEntitlement | null {
  const productName = data.product?.name || data.subscription?.product?.name;
  const paidTier = detectPolarPlanTier(productName);
  const interval = (
    data.recurring_interval ||
    data.subscription?.recurring_interval ||
    data.product?.recurring_interval ||
    ''
  ).toLowerCase();
  const isAnnual = interval === 'year' || /annual|year/i.test(productName || '');
  const billingCycle = isAnnual ? 'annual' : 'monthly';

  const rawPeriodEnd = data.current_period_end || data.subscription?.current_period_end || null;
  const parsedEnd = rawPeriodEnd ? new Date(rawPeriodEnd).getTime() : NaN;
  const hasPeriodEnd = !isNaN(parsedEnd);
  const defaultEnd = now + (isAnnual ? 365 : 30) * 24 * 60 * 60 * 1000;
  const periodEndIso = new Date(hasPeriodEnd ? parsedEnd : defaultEnd).toISOString();
  const nowIso = new Date(now).toISOString();
  const periodStillPaid = hasPeriodEnd && parsedEnd > now;

  const revoked = (): PolarEntitlement => ({ tier: 'Free', status: 'canceled', currentPeriodEnd: nowIso, billingCycle });

  if (eventType === 'subscription.revoked' || eventType === 'order.refunded') {
    return revoked();
  }

  if (eventType.startsWith('subscription.')) {
    const status = (data.status || '').toLowerCase();
    if (data.ended_at && new Date(data.ended_at).getTime() <= now) return revoked();
    switch (status) {
      case 'active':
      case 'trialing':
        // A cancellation scheduled for period end still keeps access until then.
        return {
          tier: paidTier,
          status: eventType === 'subscription.canceled' || data.cancel_at_period_end ? 'canceled' : 'active',
          currentPeriodEnd: periodEndIso,
          billingCycle,
        };
      case 'past_due':
        return periodStillPaid
          ? { tier: paidTier, status: 'past_due', currentPeriodEnd: periodEndIso, billingCycle }
          : { tier: 'Free', status: 'past_due', currentPeriodEnd: nowIso, billingCycle };
      case 'canceled':
        return periodStillPaid
          ? { tier: paidTier, status: 'canceled', currentPeriodEnd: periodEndIso, billingCycle }
          : revoked();
      case 'unpaid':
      case 'incomplete_expired':
        return revoked();
      default:
        // 'incomplete' (payment not captured yet) or unknown: leave entitlement unchanged.
        return null;
    }
  }

  if (eventType === 'order.paid' || eventType === 'order.created') {
    const status = (data.status || '').toLowerCase();
    if (status && status !== 'paid') return null;
    return { tier: paidTier, status: 'active', currentPeriodEnd: periodEndIso, billingCycle };
  }

  return null;
}
