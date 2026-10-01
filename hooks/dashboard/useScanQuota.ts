import { useState, useEffect } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { PlanUsageQuota, UserTier } from '@/data/schema';
import type { UserProfile } from '@/components/auth/AuthModal';
import { isPlatformAdminEmail } from '@/lib/supabase';
import { getActiveUserAuth } from '@/lib/supabase-client';
import {
  FREE_SCAN_LIMIT,
  loadUserQuota,
  saveUserQuota,
  consumeScanQuota,
  consumeAiPromptQuota,
  checkScanQuota
} from '@/lib/quota-manager';

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

/**
 * Scan / AI-prompt quota: local cache kept in sync with /api/v1/quota, plus the
 * server calls that reserve a scan and report its result.
 */
export function useScanQuota(user: UserProfile | null, setAuthStatus: Dispatch<SetStateAction<AuthStatus>>) {
  const [quota, setQuota] = useState<PlanUsageQuota>(() => {
    return loadUserQuota((user?.tier as UserTier) || 'Free');
  });

  // Authoritative server quota synchronization
  useEffect(() => {
    let isCancelled = false;

    async function fetchAuthoritativeQuota() {
      try {
        const { accessToken } = await getActiveUserAuth();
        const headers: Record<string, string> = {};
        if (accessToken) {
          headers['Authorization'] = `Bearer ${accessToken}`;
        }

        const res = await fetch('/api/v1/quota', { headers });
        if (res.ok && !isCancelled) {
          const data = await res.json();
          const isPlatformAdmin = isPlatformAdminEmail(user?.email);
          const isFree = !isPlatformAdmin && data.tier === 'Free';
          setQuota((prev) => {
            // For unauthenticated users, preserve local quota count and do not let server wipe it to 0
            const authoritativeScansUsed = isPlatformAdmin
              ? 0
              : data.status === 'unauthenticated'
                ? prev.scansUsed
                : (data.scansUsed ?? prev.scansUsed);

            const updated: PlanUsageQuota = {
              ...prev,
              scansUsed: authoritativeScansUsed,
              scansLimit: isFree ? (data.scansLimit ?? FREE_SCAN_LIMIT) : Infinity,
              billingCycleReset: data.billingCycleReset || prev.billingCycleReset
            };
            saveUserQuota(updated);
            return updated;
          });
        }
      } catch (err) {
        // Fallback gracefully to cached localStorage quota
        void err;
      }
    }

    fetchAuthoritativeQuota();
    return () => {
      isCancelled = true;
    };
  }, [user?.email, user?.tier]);

  const recordScanUsage = () => {
    setQuota((prev) => {
      const updated = consumeScanQuota(prev, (user?.tier as UserTier) || 'Free');
      return updated;
    });
  };

  const requestScanAuthorization = async (scanDetails: {
    projectId?: string;
    projectName?: string;
    repoUrl: string;
    framework?: string;
  }): Promise<{ allowed: boolean; reason?: string; scanId?: string; projectId?: string }> => {
    try {
      const { accessToken } = await getActiveUserAuth();
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      const res = await fetch('/api/v1/quota', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          action: 'consume_scan',
          projectId: scanDetails.projectId,
          projectName: scanDetails.projectName,
          repoUrl: scanDetails.repoUrl,
          framework: scanDetails.framework
        })
      });

      const data = await res.json();
      if (res.status === 401) {
        setAuthStatus('unauthenticated');
        return { allowed: false, reason: data.error || 'Please sign in to run audits.' };
      }
      if (!res.ok || !data.allowed) {
        return {
          allowed: false,
          reason: data.error || 'Scan limit reached. Please upgrade to Pro.'
        };
      }

      setQuota((prev) => {
        const updated: PlanUsageQuota = {
          ...prev,
          scansUsed: data.scansUsed ?? (prev.scansUsed + 1),
          scansLimit: data.scansLimit === 'Unlimited' ? Infinity : (data.scansLimit ?? prev.scansLimit)
        };
        saveUserQuota(updated);
        return updated;
      });

      return {
        allowed: true,
        scanId: data.scanId,
        projectId: data.projectId
      };
    } catch (err) {
      void err;
      const localCheck = checkScanQuota(quota, (user?.tier as UserTier) || 'Free');
      if (!localCheck.allowed) {
        return { allowed: false, reason: localCheck.reason };
      }
      setQuota((prev) => consumeScanQuota(prev, (user?.tier as UserTier) || 'Free'));
      return { allowed: true };
    }
  };

  const completeScanTelemetry = async (details: {
    scanId?: string;
    projectId?: string;
    readinessScore: number;
    gateStatus: 'PASSED' | 'FAILED' | 'WARNING';
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    uiClicheCount: number;
    scanDurationMs: number;
  }) => {
    try {
      const { accessToken } = await getActiveUserAuth();
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      await fetch('/api/v1/quota', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          action: 'complete_scan',
          ...details
        })
      });
    } catch {
      // Non-blocking telemetry
    }
  };

  const recordAiPromptUsage = () => {
    setQuota((prev) => {
      const updated = consumeAiPromptQuota(prev, (user?.tier as UserTier) || 'Free');
      return updated;
    });
  };

  return {
    quota,
    setQuota,
    recordScanUsage,
    requestScanAuthorization,
    completeScanTelemetry,
    recordAiPromptUsage
  };
}
