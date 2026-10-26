/**
 * Lifecycle email helpers: signed one-click unsubscribe tokens and the selection of users who signed up
 * but never scanned. Sent/opt-out state lives in auth app_metadata (writable only with the service role).
 */
import { createHmac, timingSafeEqual } from 'crypto';
import { getInternalSecret } from '@/lib/internal-auth';

const DAY = 24 * 60 * 60 * 1000;

export interface LifecycleUser {
  id: string;
  email?: string | null;
  created_at: string;
  email_confirmed_at?: string | null;
  app_metadata?: Record<string, unknown> | null;
}

function sign(userId: string, secret: string): string {
  return createHmac('sha256', secret).update(`unsubscribe:${userId}`).digest('base64url');
}

/** Token for /api/v1/email/unsubscribe; null when no server secret is configured (then no lifecycle mail is sent). */
export function unsubscribeToken(userId: string): string | null {
  const secret = getInternalSecret();
  return secret ? sign(userId, secret) : null;
}

export function isValidUnsubscribeToken(userId: string, token: string | null | undefined): boolean {
  const secret = getInternalSecret();
  if (!secret || !userId || !token) return false;
  const expected = Buffer.from(sign(userId, secret));
  const received = Buffer.from(token);
  return expected.length === received.length && timingSafeEqual(expected, received);
}

/**
 * Confirmed accounts created 3-8 days ago that ran a scan but whose pull requests never reached the gate, were not
 * sent this nudge before and did not opt out. The window keeps a missed daily run from mailing old accounts.
 */
export function pickGateNudges(
  users: LifecycleUser[],
  scannedUserIds: Set<string>,
  gateUserIds: Set<string>,
  now = Date.now(),
): LifecycleUser[] {
  return users.filter((u) => {
    const meta = u.app_metadata ?? {};
    const age = now - Date.parse(u.created_at);
    return !!u.email && !!u.email_confirmed_at
      && age >= 3 * DAY && age <= 8 * DAY
      && !meta.email_opt_out && !meta.gate_nudge_at
      && scannedUserIds.has(u.id) && !gateUserIds.has(u.id);
  });
}

/**
 * Confirmed accounts created 1-3 days ago that never ran a scan, were not nudged before and did not opt out.
 * The window keeps a missed daily run from mailing old accounts.
 */
export function pickFirstScanNudges(users: LifecycleUser[], scannedUserIds: Set<string>, now = Date.now()): LifecycleUser[] {
  return users.filter((u) => {
    const meta = u.app_metadata ?? {};
    const age = now - Date.parse(u.created_at);
    return !!u.email && !!u.email_confirmed_at
      && age >= DAY && age <= 3 * DAY
      && !meta.email_opt_out && !meta.first_scan_nudge_at
      && !scannedUserIds.has(u.id);
  });
}
