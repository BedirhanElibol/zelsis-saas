import { PlanUsageQuota, UserTier } from '@/data/schema';
import { priceLabel, SUPPORT_TERMS } from '@/data/pricing-plans';

export const FREE_SCAN_LIMIT = 3;
export const FREE_PROJECT_LIMIT = 1;
export const FREE_AI_PROMPT_LIMIT = 1;

export interface TierFeatureConfig {
  tier: UserTier;
  displayName: string;
  priceMonthly: string;
  scanLimit: number | 'Unlimited';
  projectLimit: number | 'Unlimited';
  aiPromptLimit: number | 'Unlimited';
  privateRepoAccess: boolean;
  pdfExportAccess: boolean;
  cicdIntegration: boolean;
  customRules: boolean;
  ruleInventory: string;
  supportSla: string;
  concurrentWorkers: number | 'Unlimited';
  historyRetentionDays: number | 'Unlimited';
}

export const TIER_CONFIGS: Record<UserTier, TierFeatureConfig> = {
  Free: {
    tier: 'Free',
    displayName: 'Free Starter',
    priceMonthly: priceLabel('Free'),
    scanLimit: FREE_SCAN_LIMIT,
    projectLimit: FREE_PROJECT_LIMIT,
    aiPromptLimit: FREE_AI_PROMPT_LIMIT,
    privateRepoAccess: false,
    pdfExportAccess: false,
    cicdIntegration: false,
    customRules: false,
    ruleInventory: 'All active rules',
    supportSla: SUPPORT_TERMS.Free,
    concurrentWorkers: 1,
    historyRetentionDays: 7
  },
  Pro: {
    tier: 'Pro',
    displayName: 'Pro Developer',
    priceMonthly: priceLabel('Pro'),
    scanLimit: 'Unlimited',
    projectLimit: 'Unlimited',
    aiPromptLimit: 'Unlimited',
    privateRepoAccess: true,
    pdfExportAccess: true,
    cicdIntegration: true,
    customRules: false,
    ruleInventory: 'All active rules',
    supportSla: SUPPORT_TERMS.Pro,
    concurrentWorkers: 5,
    historyRetentionDays: 90
  },
  Enterprise: {
    tier: 'Enterprise',
    displayName: 'Enterprise Team',
    priceMonthly: priceLabel('Enterprise'),
    scanLimit: 'Unlimited',
    projectLimit: 'Unlimited',
    aiPromptLimit: 'Unlimited',
    privateRepoAccess: true,
    pdfExportAccess: true,
    cicdIntegration: true,
    customRules: true,
    ruleInventory: 'All active rules',
    supportSla: SUPPORT_TERMS.Enterprise,
    concurrentWorkers: 'Unlimited',
    historyRetentionDays: 'Unlimited'
  }
};

function getNextMonthlyResetDate(): string {
  const now = new Date();
  // 1st day of next month UTC
  const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0));
  return nextMonth.toISOString();
}

export function getInitialQuota(tier: UserTier = 'Free'): PlanUsageQuota {
  const isFree = tier === 'Free';
  return {
    scansUsed: 0,
    scansLimit: isFree ? FREE_SCAN_LIMIT : Infinity,
    projectsUsed: 0,
    projectsLimit: isFree ? FREE_PROJECT_LIMIT : Infinity,
    aiPromptsUsed: 0,
    aiPromptsLimit: isFree ? FREE_AI_PROMPT_LIMIT : Infinity,
    billingCycleReset: getNextMonthlyResetDate()
  };
}

export function loadUserQuota(tier: UserTier = 'Free'): PlanUsageQuota {
  if (typeof window === 'undefined') {
    return getInitialQuota(tier);
  }

  try {
    const raw = localStorage.getItem('zelsis_user_quota');
    if (raw) {
      const parsed: PlanUsageQuota = JSON.parse(raw);
      // Check monthly rollover reset
      const resetTime = new Date(parsed.billingCycleReset).getTime();
      if (!isNaN(resetTime) && Date.now() > resetTime) {
        const refreshed = getInitialQuota(tier);
        saveUserQuota(refreshed);
        return refreshed;
      }

      // Re-align limits if tier upgraded/changed
      const isFree = tier === 'Free';
      parsed.scansLimit = isFree ? FREE_SCAN_LIMIT : Infinity;
      parsed.projectsLimit = isFree ? FREE_PROJECT_LIMIT : Infinity;
      parsed.aiPromptsLimit = isFree ? FREE_AI_PROMPT_LIMIT : Infinity;
      return parsed;
    }
  } catch {
    // Fallback on storage errors
  }

  const initial = getInitialQuota(tier);
  saveUserQuota(initial);
  return initial;
}

export function saveUserQuota(quota: PlanUsageQuota): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem('zelsis_user_quota', JSON.stringify(quota));
  } catch {
    // Storage sandbox fallback
  }
}

export function checkScanQuota(quota: PlanUsageQuota, tier: UserTier = 'Free'): {
  allowed: boolean;
  remaining: number;
  reason?: string;
} {
  if (tier !== 'Free') {
    return { allowed: true, remaining: Infinity };
  }

  const remaining = Math.max(0, quota.scansLimit - quota.scansUsed);
  if (remaining <= 0) {
    return {
      allowed: false,
      remaining: 0,
      reason: `Monthly scan limit reached (${quota.scansUsed}/${quota.scansLimit} scans used). Upgrade to Pro for unlimited scans.`
    };
  }

  return { allowed: true, remaining };
}

export function consumeScanQuota(quota: PlanUsageQuota, tier: UserTier = 'Free'): PlanUsageQuota {
  if (tier !== 'Free') return quota;
  const updated: PlanUsageQuota = {
    ...quota,
    scansUsed: quota.scansUsed + 1
  };
  saveUserQuota(updated);
  return updated;
}

export function resetUserQuota(tier: UserTier = 'Free'): PlanUsageQuota {
  const initial = getInitialQuota(tier);
  saveUserQuota(initial);
  return initial;
}

export function checkAiPromptQuota(quota: PlanUsageQuota, tier: UserTier = 'Free'): {
  allowed: boolean;
  remaining: number;
  reason?: string;
} {
  if (tier !== 'Free') {
    return { allowed: true, remaining: Infinity };
  }

  const remaining = Math.max(0, quota.aiPromptsLimit - quota.aiPromptsUsed);
  if (remaining <= 0) {
    return {
      allowed: false,
      remaining: 0,
      reason: `Trial AI prompt used (${quota.aiPromptsUsed}/${quota.aiPromptsLimit}). Upgrade to Pro to copy unlimited 1-click Claude & Cursor code fix patches.`
    };
  }

  return { allowed: true, remaining };
}

export function consumeAiPromptQuota(quota: PlanUsageQuota, tier: UserTier = 'Free'): PlanUsageQuota {
  if (tier !== 'Free') return quota;
  const updated: PlanUsageQuota = {
    ...quota,
    aiPromptsUsed: quota.aiPromptsUsed + 1
  };
  saveUserQuota(updated);
  return updated;
}

export function checkProjectQuota(projectsCount: number, tier: UserTier = 'Free'): {
  allowed: boolean;
  remaining: number;
  reason?: string;
} {
  if (tier !== 'Free') {
    return { allowed: true, remaining: Infinity };
  }

  const remaining = Math.max(0, FREE_PROJECT_LIMIT - projectsCount);
  if (remaining <= 0) {
    return {
      allowed: false,
      remaining: 0,
      reason: `Free tier allows 1 active project. Upgrade to Pro for unlimited connected repositories.`
    };
  }

  return { allowed: true, remaining };
}

export function isPrivateRepoAllowed(tier: UserTier = 'Free'): boolean {
  return tier !== 'Free';
}

export function isPdfExportAllowed(tier: UserTier = 'Free'): boolean {
  return tier !== 'Free';
}

export function isCicdViewAllowed(tier: UserTier = 'Free'): boolean {
  return tier !== 'Free';
}

export function isCicdIntegrationAllowed(tier: UserTier = 'Free'): boolean {
  return TIER_CONFIGS[tier].cicdIntegration;
}

export function isBulkPatchAllowed(tier: UserTier = 'Free'): boolean {
  return tier !== 'Free';
}

export function isCustomRulesAllowed(tier: UserTier = 'Free'): boolean {
  return TIER_CONFIGS[tier].customRules;
}

export function getConcurrentWorkers(tier: UserTier = 'Free'): number | 'Unlimited' {
  return TIER_CONFIGS[tier].concurrentWorkers;
}

/**
 * Filters a list of scan history items by the tier's retention window.
 * Returns { visible, locked } — visible records are within retention, locked are outside.
 */
export function filterHistoryByRetention<T extends { date: string }>(
  records: T[],
  tier: UserTier = 'Free'
): { visible: T[]; locked: T[] } {
  const retentionDays = TIER_CONFIGS[tier].historyRetentionDays;
  if (retentionDays === 'Unlimited') {
    return { visible: records, locked: [] };
  }

  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const visible: T[] = [];
  const locked: T[] = [];

  for (const record of records) {
    const ts = new Date(record.date).getTime();
    // If the date can't be parsed (e.g., "2024-05-12" format), fall through to visible
    if (isNaN(ts) || ts >= cutoffMs) {
      visible.push(record);
    } else {
      locked.push(record);
    }
  }

  return { visible, locked };
}
