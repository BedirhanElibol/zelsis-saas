import { ZELSIS_PRICING_PLANS, SHIPGUARD_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';

export type LicenseErrorReason =
  | 'EMPTY_KEY'
  | 'CLIENT_VERIFICATION_DEPRECATED'
  | 'SERVER_SYNC_REQUIRED'
  | string;

export interface LicenseVerificationResult {
  valid: boolean;
  tier: 'Pro' | 'Enterprise' | 'Free';
  planId: string;
  planName: string;
  expiresAt: string;
  maxApplications: number;
  reason?: LicenseErrorReason;
  errorMessage?: string;
}

/**
 * Generates a cosmetic reference identifier for user orders and receipts.
 * NOTE: As per F-02 security remediation, reference keys are display-only
 * and cannot be used to forge or authorize paid tiers on the client.
 */
export function generateLicenseKey(planId: string, email?: string): string {
  const prefix = planId === 'vibecare' || planId === 'zelsis-suite' ? 'ZS-SUITE' : 'ZS-PRO';
  let randSegment = 'A1B2';
  try {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.randomUUID) {
      randSegment = globalThis.crypto.randomUUID().replace(/-/g, '').slice(0, 6).toUpperCase();
    }
  } catch (err) {
    console.debug('[LicenseKey] randomUUID unavailable, using static fallback', err);
  }
  const dateSegment = new Date().getFullYear().toString();
  return `${prefix}-${dateSegment}-REF-${randSegment}`;
}

/**
 * F-02 Remediation: Client-side offline license validation using FNV-1a checksums
 * and hardcoded master keys has been completely removed.
 * All paid tiers (Pro, Enterprise) must be verified through Polar webhooks
 * and server-side subscription synchronization.
 */
export function verifyLicenseKey(licenseKey: string, userEmail?: string): LicenseVerificationResult {
  if (!licenseKey || typeof licenseKey !== 'string' || !licenseKey.trim()) {
    return {
      valid: false,
      tier: 'Free',
      planId: 'none',
      planName: 'Empty Key',
      expiresAt: 'N/A',
      maxApplications: 1,
      reason: 'EMPTY_KEY',
      errorMessage: 'License key is empty. Please enter a valid subscription reference.',
    };
  }

  // Client-side offline tier elevation is strictly disabled.
  return {
    valid: false,
    tier: 'Free',
    planId: 'none',
    planName: 'Server Verification Required',
    expiresAt: 'N/A',
    maxApplications: 1,
    reason: 'CLIENT_VERIFICATION_DEPRECATED',
    errorMessage: 'Offline client-side license verification is disabled for security. Active subscriptions are synchronized securely via Polar and your account session.',
  };
}

/**
 * Optimistic client-side UI state updater following verified checkout.
 * NOTE: Does NOT write client-controlled tier to Supabase Auth metadata (F-02 / F-13).
 * Supabase subscriptions and profiles are updated exclusively by server-side endpoints.
 */
export async function activateUserTier(
  tier: 'Pro' | 'Enterprise',
  licenseKey?: string,
  fallbackProfile?: { name?: string; email?: string; avatarUrl?: string } | null
): Promise<boolean> {
  try {
    let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
    if (!savedUserStr && typeof document !== 'undefined') {
      const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
      if (match && match[3]) {
        savedUserStr = decodeURIComponent(match[3]);
      }
    }
    let userObj: any = null;
    const renewalDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    if (savedUserStr) {
      try {
        const parsed = JSON.parse(savedUserStr);
        const isMatchingEmail = !fallbackProfile?.email || (parsed?.email && parsed.email.toLowerCase().trim() === fallbackProfile.email.toLowerCase().trim());
        if (parsed && typeof parsed === 'object' && isMatchingEmail) {
          userObj = {
            ...parsed,
            tier: tier,
            isLoggedIn: true,
            expiresAt: parsed.expiresAt && new Date(parsed.expiresAt).getTime() > Date.now() ? parsed.expiresAt : renewalDate,
            subscriptionStatus: 'active',
            status: 'active',
            lastVerifiedAt: Date.now(),
          };
        }
      } catch (err) {
        console.warn('[Zelsis Activation] Failed to parse user from storage:', err);
      }
    }

    if (!userObj && fallbackProfile?.email) {
      userObj = {
        name: fallbackProfile.name || fallbackProfile.email.split('@')[0] || 'Customer',
        email: fallbackProfile.email.toLowerCase().trim(),
        avatarUrl: fallbackProfile.avatarUrl,
        tier: tier,
        isLoggedIn: true,
        emailVerified: true,
        expiresAt: renewalDate,
        subscriptionStatus: 'active',
        status: 'active',
        lastVerifiedAt: Date.now(),
      };
    }

    if (!userObj) {
      userObj = {
        name: 'Subscriber',
        email: 'customer@example.com',
        tier: tier,
        isLoggedIn: true,
        emailVerified: true,
        expiresAt: renewalDate,
        subscriptionStatus: 'active',
        status: 'active',
        lastVerifiedAt: Date.now(),
      };
    }

    const planId = tier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
    const effectiveKey = licenseKey || generateLicenseKey(planId, userObj.email);

    localStorage.setItem('zelsis_license_key', effectiveKey);
    localStorage.setItem('shipguard_license_key', effectiveKey);

    localStorage.setItem('zelsis_user', JSON.stringify(userObj));
    if (typeof document !== 'undefined') {
      const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
      const secureAttr = isHttps ? '; Secure' : '';
      // F-32 Remediation: Eliminate non-HttpOnly PII cookie to prevent client-side data exposure
      document.cookie = `zelsis_user=; path=/; max-age=0; SameSite=Lax${secureAttr}`;
      document.cookie = `shipguard_user=; path=/; max-age=0; SameSite=Lax${secureAttr}`;
    }
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('storage'));
    }

    // F-02: Do NOT call syncUserProfileToSupabase({ tier }) from client.
    // Server-side Polar webhook and verify-checkout API handle database persistence.
    return true;
  } catch (err) {
    console.error('[Zelsis Activation] Failed to activate tier locally:', err);
    return false;
  }
}
