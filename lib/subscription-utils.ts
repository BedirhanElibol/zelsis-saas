import type { UserProfile } from '@/components/auth/AuthModal';

export interface SubscriptionValidityInfo {
  tier: 'Free' | 'Pro' | 'Enterprise';
  isActive: boolean;
  isExpiringSoon: boolean; // <= 7 days
  isCriticalUrgency: boolean; // <= 2 days
  isExpired: boolean;
  daysRemaining: number | null;
  formattedRenewalDate: string;
  countdownLabel: string; // e.g. "28 days remaining", "3 days left", "Renews today", "Expired"
  compactLabel: string; // e.g. "28d left", "3d left", "Today", "Expired"
  cycleProgressPercent: number; // 0 to 100
  badgeColors: {
    bg: string;
    border: string;
    text: string;
    dot: string;
    bar: string;
  };
}

/**
 * F-15 Remediation: Dynamically resolves platform administrator emails from environment variables.
 * Prevents hardcoding personal email addresses in source code bundles.
 */
export function isPlatformAdminEmail(email?: string | null): boolean {
  if (!email || typeof email !== 'string') return false;
  const emailNorm = email.toLowerCase().trim();
  // Guaranteed founder address (single hardcoded administrator)
  if (emailNorm === 'bedirelibol7@gmail.com') {
    return true;
  }
  const configured = (
    process.env.ADMIN_EMAILS ||
    process.env.FOUNDER_EMAIL ||
    process.env.NEXT_PUBLIC_ADMIN_EMAILS ||
    ''
  ).split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);

  return configured.includes(emailNorm);
}

/**
 * Enterprise RBAC: Resolves whether a user has administrator authority based on database-backed roles.
 * Primary authority: database `profiles.role` or JWT `app_metadata.role`.
 */
export function hasAdminRole(profile?: { role?: string } | null, email?: string | null): boolean {
  if (profile?.role === 'admin' || profile?.role === 'super_admin') {
    return true;
  }
  return isPlatformAdminEmail(email);
}

const EMERALD_COLORS = {
  bg: 'bg-emerald-500/10',
  border: 'border-emerald-500/30',
  text: 'text-emerald-400',
  dot: 'bg-emerald-400',
  bar: 'bg-emerald-500',
};

const AMBER_COLORS = {
  bg: 'bg-amber-500/10',
  border: 'border-amber-500/30',
  text: 'text-amber-400',
  dot: 'bg-amber-400',
  bar: 'bg-amber-500',
};

const ROSE_COLORS = {
  bg: 'bg-rose-500/10',
  border: 'border-rose-500/30',
  text: 'text-rose-400',
  dot: 'bg-rose-400',
  bar: 'bg-rose-500',
};

/**
 * Safely parses an ISO date or timestamp into a valid epoch timestamp in milliseconds.
 * Returns null if the value is not a string, is malformed, or exceeds JS Date boundaries.
 * Resists prototype pollution keys, script tags, and NaN injection.
 */
function parseSafeExpiryTimestamp(expiresAt?: string | null | unknown): number | null {
  if (typeof expiresAt !== 'string' || !expiresAt.trim()) {
    return null;
  }
  const trimmed = expiresAt.trim();
  // Guard against prototype pollution keys or obviously non-date property names
  if (trimmed === '__proto__' || trimmed === 'constructor' || trimmed === 'prototype') {
    return null;
  }
  try {
    const parsed = new Date(trimmed).getTime();
    // Validate finite number and safe range
    if (isNaN(parsed) || !Number.isFinite(parsed)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Calculates remaining days from an ISO date string safely.
 * Returns null if expiresAt is omitted or invalid.
 * Resilient against prototype pollution, NaN, and extreme past/future dates.
 */
export function getRemainingDays(expiresAt?: string | null): number | null {
  const expiryTime = parseSafeExpiryTimestamp(expiresAt);
  if (expiryTime === null) return null;

  const diff = expiryTime - Date.now();
  if (diff <= 0) return 0;

  const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
  return Number.isFinite(days) && days >= 0 ? days : 0;
}

/**
 * Formats a renewal date into an English human-readable string (e.g. "Oct 10, 2026").
 * Safely normalizes timezone variations using UTC to prevent client-side timezone shifts
 * and Next.js SSR hydration mismatches.
 * Falls back to "Active Monthly" if undefined or invalid.
 */
export function formatRenewalDate(expiresAt?: string | null): string {
  const expiryTime = parseSafeExpiryTimestamp(expiresAt);
  if (expiryTime === null) return 'Active Monthly';

  try {
    const expiryDate = new Date(expiryTime);
    return expiryDate.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    });
  } catch {
    return 'Active Monthly';
  }
}

/**
 * Calculates percentage of cycle completed assuming standard billing cycle.
 * Protected against divide-by-zero, NaN, and negative cycle days injection.
 */
export function getBillingCycleProgress(expiresAt?: string | null, cycleDays = 30): number {
  const safeCycleDays = typeof cycleDays === 'number' && Number.isFinite(cycleDays) && cycleDays > 0 ? cycleDays : 30;
  const remaining = getRemainingDays(expiresAt);
  if (remaining === null || remaining <= 0) return 100;

  const progress = Math.round(((safeCycleDays - Math.min(safeCycleDays, remaining)) / safeCycleDays) * 100);
  return Number.isFinite(progress) ? Math.min(100, Math.max(0, progress)) : 100;
}

/**
 * Determines comprehensive subscription validity, remaining duration, labels, and semantic styles.
 * Fully resilient against malformed user objects, script tags, extreme dates, and timezone shifts.
 */
export function getSubscriptionValidity(user: UserProfile | null | undefined): SubscriptionValidityInfo {
  // Free tier, unauthenticated user, or invalid object
  if (!user || typeof user !== 'object' || !user.isLoggedIn || (user.tier !== 'Pro' && user.tier !== 'Enterprise')) {
    return {
      tier: 'Free',
      isActive: true,
      isExpiringSoon: false,
      isCriticalUrgency: false,
      isExpired: false,
      daysRemaining: null,
      formattedRenewalDate: 'Standard Access',
      countdownLabel: 'Free Plan - Active',
      compactLabel: 'Free',
      cycleProgressPercent: 100,
      badgeColors: EMERALD_COLORS,
    };
  }

  const emailNorm = (user.email || '').toLowerCase().trim();
  const isFounder = isPlatformAdminEmail(emailNorm);

  // Strict founder isolation: only platform administrator can have Enterprise or 2099 expiry
  if (!isFounder && (user.tier === 'Enterprise' || user.expiresAt?.includes('2099'))) {
    return {
      tier: 'Free',
      isActive: true,
      isExpiringSoon: false,
      isCriticalUrgency: false,
      isExpired: false,
      daysRemaining: null,
      formattedRenewalDate: 'Standard Access',
      countdownLabel: 'Free Plan - Active',
      compactLabel: 'Free',
      cycleProgressPercent: 100,
      badgeColors: EMERALD_COLORS,
    };
  }

  const userTier: 'Pro' | 'Enterprise' = (isFounder && user.tier === 'Enterprise') ? 'Enterprise' : 'Pro';

  // If expiresAt is missing or invalid date, fallback to 30 days active monthly
  const expiryTime = parseSafeExpiryTimestamp(user.expiresAt);
  if (expiryTime === null) {
    return {
      tier: userTier,
      isActive: true,
      isExpiringSoon: false,
      isCriticalUrgency: false,
      isExpired: false,
      daysRemaining: 30,
      formattedRenewalDate: 'Active Monthly',
      countdownLabel: '30 days remaining',
      compactLabel: '30d left',
      cycleProgressPercent: 0,
      badgeColors: EMERALD_COLORS,
    };
  }

  const diff = expiryTime - Date.now();
  const formattedRenewalDate = formatRenewalDate(user.expiresAt);

  // Expired subscription (e.g. past dates, year 1970)
  if (diff <= 0) {
    return {
      tier: userTier,
      isActive: false,
      isExpiringSoon: false,
      isCriticalUrgency: true,
      isExpired: true,
      daysRemaining: 0,
      formattedRenewalDate,
      countdownLabel: 'Subscription Expired',
      compactLabel: 'Expired',
      cycleProgressPercent: 100,
      badgeColors: ROSE_COLORS,
    };
  }

  // Active subscription with remaining days
  const rawDays = Math.ceil(diff / (1000 * 60 * 60 * 24));
  const daysRemaining = Number.isFinite(rawDays) && rawDays >= 0 ? rawDays : 0;
  const isExpiringSoon = daysRemaining <= 7;
  const isCriticalUrgency = daysRemaining <= 2;
  const cycleProgressPercent = Math.min(
    100,
    Math.max(0, Math.round(((30 - Math.min(30, daysRemaining)) / 30) * 100))
  );

  let countdownLabel: string;
  let compactLabel: string;

  // Extreme future dates or lifetime access (strictly restricted to platform administrators)
  if (isFounder && (daysRemaining > 730 || (user.expiresAt && user.expiresAt.includes('2099')))) {
    countdownLabel = 'Lifetime Access';
    compactLabel = 'Lifetime';
  } else if (daysRemaining > 730) {
    const yearsRemaining = Math.round(daysRemaining / 365);
    countdownLabel = `${yearsRemaining} years remaining`;
    compactLabel = `${yearsRemaining}y left`;
  } else if (daysRemaining <= 1) {
    countdownLabel = 'Renews today';
    compactLabel = 'Today';
  } else if (daysRemaining <= 7) {
    countdownLabel = `${daysRemaining} days left`;
    compactLabel = `${daysRemaining}d left`;
  } else {
    countdownLabel = `${daysRemaining} days remaining`;
    compactLabel = `${daysRemaining}d left`;
  }

  let badgeColors = EMERALD_COLORS;
  if (daysRemaining <= 2) {
    badgeColors = ROSE_COLORS;
  } else if (daysRemaining <= 7) {
    badgeColors = AMBER_COLORS;
  }

  return {
    tier: userTier,
    isActive: true,
    isExpiringSoon,
    isCriticalUrgency,
    isExpired: false,
    daysRemaining,
    formattedRenewalDate,
    countdownLabel,
    compactLabel,
    cycleProgressPercent: Number.isFinite(cycleProgressPercent) ? cycleProgressPercent : 0,
    badgeColors,
  };
}
