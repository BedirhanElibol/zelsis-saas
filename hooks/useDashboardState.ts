import { useState, useEffect } from 'react';
import { Project, Finding, PlanUsageQuota, UserTier } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/mockData';
import { calculateReadinessScore, calculateGateStatus } from '@/lib/scanner-engine';
import { UserProfile } from '@/components/auth/AuthModal';
import { supabaseSignIn, supabaseSignUp, supabaseResetPassword, supabaseSignOut, resolveVerifiedSession, fetchCloudProjects, getSupabase, mapSupabaseUserToProfile, syncUserProfileToSupabase, isPlatformAdminEmail } from '@/lib/supabase';
import { purgeZelsisStorage, safeSetStorageItem } from '@/lib/storage';
import { getActiveUserAuth } from '@/lib/supabase-client';
import { canAccessLocalAudit } from '@/lib/env-config';
import { verifyLicenseKey, generateLicenseKey } from '@/lib/stripe-checkout';
import { useSearchParams } from 'next/navigation';
import {
  FREE_SCAN_LIMIT,
  loadUserQuota,
  saveUserQuota,
  consumeScanQuota,
  consumeAiPromptQuota,
  checkScanQuota,
  checkAiPromptQuota,
  checkProjectQuota,
  isPrivateRepoAllowed,
  isPdfExportAllowed
} from '@/lib/quota-manager';

const VALID_NAVS = [
  'dashboard', 'projects', 'scans', 'security', 'compliance',
  'infra', 'vibepolish', 'aicliche', 'aimaster', 'vibecare',
  'cicd', 'remediation', 'checkout', 'settings'
];

export function useDashboardState() {
  const searchParams = useSearchParams();
  const rawNav = searchParams.get('nav');
  const initialNav = rawNav && VALID_NAVS.includes(rawNav) ? rawNav : 'dashboard';
  const [activeNav, setActiveNav] = useState<string>(initialNav);
  const [projects, setProjects] = useState<Project[]>([MOCK_PROJECTS[0]]);
  const [selectedProject, setSelectedProject] = useState<Project>(MOCK_PROJECTS[0]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  // Only a server-verified Supabase session unlocks the dashboard
  const [authStatus, setAuthStatus] = useState<'loading' | 'authenticated' | 'unauthenticated'>('loading');
  const authParam = searchParams.get('auth');
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(() => {
    if (!authParam) return false;
    if (typeof window === 'undefined') return false;
    try {
      const saved = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
      if (saved) {
        const p = JSON.parse(saved);
        if (p && p.isLoggedIn) return false;
      }
    } catch (err) {
      void err;
    }
    return true;
  });
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>(
    authParam === 'signup' ? 'signup' : 'signin'
  );
  const [isCheckoutOpen, setIsCheckoutOpen] = useState<boolean>(false);
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

  useEffect(() => {
    const nav = searchParams.get('nav');
    if (nav) {
      setActiveNav(VALID_NAVS.includes(nav) ? nav : 'dashboard');
    }
    const auth = searchParams.get('auth');
    if (auth === 'signin' || auth === 'signup') {
      const isCurrentLoggedIn = Boolean(user?.isLoggedIn);
      const isSavedLoggedIn = typeof window !== 'undefined' && (() => {
        try {
          const s = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
          return s ? JSON.parse(s)?.isLoggedIn : false;
        } catch { return false; }
      })();

      if (isCurrentLoggedIn || isSavedLoggedIn) {
        setIsAuthModalOpen(false);
        if (typeof window !== 'undefined') {
          const cleanUrl = new URL(window.location.href);
          if (cleanUrl.searchParams.has('auth')) {
            cleanUrl.searchParams.delete('auth');
            window.history.replaceState({}, '', cleanUrl.toString());
          }
        }
      } else {
        setAuthInitialMode(auth);
        setIsAuthModalOpen(true);
      }
    }
  }, [searchParams, user]);

  useEffect(() => {
    const loadProjectsFromStorage = () => {
      try {
        const CURRENT_DATA_VERSION = 'v12_resilient_sanitized_starter';
        const savedVersion = localStorage.getItem('zelsis_data_version') || localStorage.getItem('shipguard_data_version');
        const allowedLocal = canAccessLocalAudit();

        // Helper to obtain single starter demo project for clean initial state
        const getBaseProjects = () => [MOCK_PROJECTS[0]];

        // Check if there is an active user session in localStorage or cookie first
        let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!savedUserStr && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            try {
              savedUserStr = decodeURIComponent(match[3]);
              localStorage.setItem('zelsis_user', savedUserStr);
            } catch (err) {
              void err;
            }
          }
        }

        let authenticatedEmail: string | null = null;
        if (savedUserStr) {
          try {
            const parsed = JSON.parse(savedUserStr);
            if (parsed && typeof parsed === 'object' && parsed.isLoggedIn && parsed.email) {
              authenticatedEmail = (parsed.email || '').toLowerCase().trim();
            }
          } catch {
            // ignore parse errors
          }
        }

        if (savedVersion !== CURRENT_DATA_VERSION) {
          safeSetStorageItem('zelsis_data_version', CURRENT_DATA_VERSION);
          localStorage.removeItem('shipguard_data_version');
          localStorage.removeItem('shipguard_projects');
          localStorage.removeItem('shipguard_selected_project_id');
          localStorage.removeItem('zelsis_projects');
          localStorage.removeItem('zelsis_selected_project_id');
          const cleanProjects = getBaseProjects();
          setProjects(cleanProjects);
          setSelectedProject(MOCK_PROJECTS[0]);
          safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
        }

        let currentProjects = getBaseProjects();

        if (authenticatedEmail) {
          // Logged-in user: Check user-scoped projects first, then fallback to general storage
          const userProjectsKey = `zelsis_user_projects_${authenticatedEmail}`;
          const savedUserProjectsStr = localStorage.getItem(userProjectsKey);
          const savedProjectsStr = savedUserProjectsStr || localStorage.getItem('zelsis_projects') || localStorage.getItem('shipguard_projects');

          if (savedProjectsStr) {
            try {
              const parsed = JSON.parse(savedProjectsStr);
              if (Array.isArray(parsed) && parsed.length > 0) {
                currentProjects = (parsed as Project[]).map((p) => {
                  if (p.repoUrl === 'https://github.com/example/shipguard' || p.id === 'proj-zelsis-self' || p.id === 'proj-shipguard-self') {
                    return { ...p, repoUrl: 'local' };
                  }
                  return p;
                });
                if (!savedUserProjectsStr) {
                  safeSetStorageItem(userProjectsKey, JSON.stringify(currentProjects));
                }
              }
            } catch (jsonErr) {
              console.warn('[Zelsis Storage] Corrupted user projects in localStorage; resetting to default.', jsonErr);
              currentProjects = getBaseProjects();
            }
          }
        } else {
          // Guest / Signed out user:
          // A signed-out visitor must NEVER see an authenticated user's old searches or scanned repositories!
          // We wipe leftover session projects from localStorage and present ONLY the clean demo showcase.
          localStorage.removeItem('zelsis_projects');
          localStorage.removeItem('shipguard_projects');
          localStorage.removeItem('zelsis_selected_project_id');
          localStorage.removeItem('shipguard_selected_project_id');
          currentProjects = getBaseProjects();
        }

        // Filter out legacy mock projects that might be lingering in localStorage
        currentProjects = currentProjects.filter(
          (p) => p && p.id !== 'proj-react-core' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self' && p.id !== 'proj-preset-self'
        );

        // Deduplicate projects by repoUrl to prevent duplicate dropdown items
        const seenUrls = new Set<string>();
        currentProjects = currentProjects.filter((p) => {
          const pUrl = p?.repoUrl || '';
          const norm = (pUrl === 'local' ? 'local' : pUrl.replace(/\/+$/, '')).toLowerCase().trim();
          if (seenUrls.has(norm)) return false;
          seenUrls.add(norm);
          return true;
        });

        // Environment isolation: Filter out local self-audit project if not permitted
        if (!allowedLocal) {
          currentProjects = currentProjects.filter(
            (p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self'
          );
        }

        if (currentProjects.length === 0) {
          currentProjects = getBaseProjects();
        }

        // Sanitize projects to auto-heal any corrupt or undefined repoUrl from legacy storage
        currentProjects = currentProjects.map((p) => {
          if (!p || typeof p !== 'object' || ('nativeEvent' in p)) return MOCK_PROJECTS[0];
          let cleanRepoUrl = typeof p.repoUrl === 'string' ? p.repoUrl.trim() : '';
          if (!cleanRepoUrl || cleanRepoUrl === 'undefined' || cleanRepoUrl === 'null') {
            cleanRepoUrl = MOCK_PROJECTS[0].repoUrl;
          }
          let cleanName = typeof p.name === 'string' && p.name.trim() && p.name !== 'undefined'
            ? p.name.trim()
            : (cleanRepoUrl ? cleanRepoUrl.split('/').pop() || 'Target Repository' : MOCK_PROJECTS[0].name);
          return {
            ...p,
            id: p.id || `proj-${Date.now()}`,
            name: cleanName,
            repoUrl: cleanRepoUrl,
            framework: p.framework || 'Next.js 15',
            providers: Array.isArray(p.providers) ? p.providers : ['GitHub Action', 'Vercel'],
            lastScanAt: p.lastScanAt || 'Never audited',
            readinessScore: typeof p.readinessScore === 'number' ? p.readinessScore : 100,
            gateStatus: p.gateStatus || 'PASSED',
            criticalCount: typeof p.criticalCount === 'number' ? p.criticalCount : 0,
            highCount: typeof p.highCount === 'number' ? p.highCount : 0,
            mediumCount: typeof p.mediumCount === 'number' ? p.mediumCount : 0,
            lowCount: typeof p.lowCount === 'number' ? p.lowCount : 0,
            uiClicheCount: typeof p.uiClicheCount === 'number' ? p.uiClicheCount : 0,
            findings: Array.isArray(p.findings) ? p.findings : [],
          };
        });

        setProjects(currentProjects);

        const savedSelectedId = localStorage.getItem('zelsis_selected_project_id') || localStorage.getItem('shipguard_selected_project_id');
        let chosenProject = currentProjects[0] || MOCK_PROJECTS[0];

        if (savedSelectedId) {
          const isStaleLocal = savedSelectedId === 'proj-zelsis-self' || savedSelectedId === 'proj-shipguard-self';
          const found = currentProjects.find((p) => p.id === savedSelectedId);

          if (!allowedLocal && (isStaleLocal || found?.repoUrl === 'local')) {
            chosenProject = currentProjects[0] || MOCK_PROJECTS[0];
            safeSetStorageItem('zelsis_selected_project_id', chosenProject.id);
          } else if (found) {
            chosenProject = found;
          } else {
            chosenProject = currentProjects[0] || MOCK_PROJECTS[0];
            safeSetStorageItem('zelsis_selected_project_id', chosenProject.id);
          }
        } else {
          safeSetStorageItem('zelsis_selected_project_id', chosenProject.id);
        }

        if (chosenProject) {
          let cleanRepoUrl = typeof chosenProject.repoUrl === 'string' ? chosenProject.repoUrl.trim() : '';
          if (!cleanRepoUrl || cleanRepoUrl === 'undefined' || cleanRepoUrl === 'null') {
            cleanRepoUrl = MOCK_PROJECTS[0].repoUrl;
          }
          let cleanName = typeof chosenProject.name === 'string' && chosenProject.name.trim() && chosenProject.name !== 'undefined'
            ? chosenProject.name.trim()
            : MOCK_PROJECTS[0].name;
          chosenProject = {
            ...chosenProject,
            id: chosenProject.id || `proj-${Date.now()}`,
            name: cleanName,
            repoUrl: cleanRepoUrl,
            framework: chosenProject.framework || 'Next.js 15',
            providers: Array.isArray(chosenProject.providers) ? chosenProject.providers : ['GitHub Action', 'Vercel'],
            lastScanAt: chosenProject.lastScanAt || 'Never audited',
            readinessScore: typeof chosenProject.readinessScore === 'number' ? chosenProject.readinessScore : 100,
            gateStatus: chosenProject.gateStatus || 'PASSED',
            criticalCount: typeof chosenProject.criticalCount === 'number' ? chosenProject.criticalCount : 0,
            highCount: typeof chosenProject.highCount === 'number' ? chosenProject.highCount : 0,
            mediumCount: typeof chosenProject.mediumCount === 'number' ? chosenProject.mediumCount : 0,
            lowCount: typeof chosenProject.lowCount === 'number' ? chosenProject.lowCount : 0,
            uiClicheCount: typeof chosenProject.uiClicheCount === 'number' ? chosenProject.uiClicheCount : 0,
            findings: Array.isArray(chosenProject.findings) ? chosenProject.findings : [],
          };
        }

        setSelectedProject(chosenProject);



        if (savedUserStr) {
          try {
            const parsedUser = JSON.parse(savedUserStr);
            if (parsedUser && typeof parsedUser === 'object' && parsedUser.isLoggedIn) {
              const email = (parsedUser.email || '').toLowerCase().trim();
              // Platform Administrator Detection (Configured via ADMIN_EMAILS)
              const isPlatformAdmin = isPlatformAdminEmail(email);

              let resolvedTier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
              let expiresAt: string | undefined = undefined;

              if (isPlatformAdmin) {
                resolvedTier = 'Enterprise';
                expiresAt = '2099-12-31T23:59:59.999Z';
              } else {
                // Non-founder: strictly reject tainted 2099 founder dates or unauthorized Enterprise tier
                const rawExpiry = parsedUser.expiresAt;
                const expiryYear = rawExpiry ? new Date(rawExpiry).getFullYear() : 0;
                const isTainted = rawExpiry && (rawExpiry.includes('2099') || expiryYear > 2028);

                if (isTainted || !parsedUser.tier || parsedUser.tier === 'Free' || parsedUser.tier === 'Enterprise') {
                  resolvedTier = 'Free';
                  expiresAt = undefined;
                  localStorage.removeItem('zelsis_license_key');
                  localStorage.removeItem('shipguard_license_key');
                  parsedUser.tier = 'Free';
                  parsedUser.expiresAt = undefined;
                  try {
                    localStorage.setItem('zelsis_user', JSON.stringify(parsedUser));
                  } catch (writeErr) {
                    console.warn('[DashboardState] LocalStorage write notice:', writeErr);
                  }
                } else {
                  // Legitimate Pro tier candidate: verify license key bound to email
                  const savedLicenseKey = localStorage.getItem('zelsis_license_key');
                  if (savedLicenseKey && email) {
                    const licResult = verifyLicenseKey(savedLicenseKey, email);
                    if (licResult.valid && !licResult.expiresAt?.includes('2099')) {
                      resolvedTier = licResult.tier;
                      expiresAt = licResult.expiresAt;
                    } else {
                      localStorage.removeItem('zelsis_license_key');
                      localStorage.removeItem('shipguard_license_key');
                    }
                  }

                  if (resolvedTier !== 'Free' && expiresAt) {
                    const expiryTime = new Date(expiresAt).getTime();
                    if (isNaN(expiryTime) || Date.now() > expiryTime) {
                      resolvedTier = 'Free';
                      expiresAt = undefined;
                    }
                  }
                }
              }

              const activeUser: UserProfile = {
                name: parsedUser.name || 'User',
                email: parsedUser.email || '',
                avatarUrl: parsedUser.avatarUrl || undefined,
                tier: resolvedTier,
                isLoggedIn: Boolean(parsedUser.isLoggedIn),
                emailVerified: parsedUser.emailVerified !== undefined ? Boolean(parsedUser.emailVerified) : true,
                expiresAt,
                status: parsedUser.status || 'active',
                gracePeriodUntil: undefined,
                lastVerifiedAt: parsedUser.lastVerifiedAt || Date.now(),
              };
              setUser(activeUser);
              setIsAuthModalOpen(false);
              if (typeof window !== 'undefined' && window.location.search.includes('auth=')) {
                const cleanUrl = new URL(window.location.href);
                cleanUrl.searchParams.delete('auth');
                window.history.replaceState({}, '', cleanUrl.toString());
              }
              localStorage.setItem('zelsis_user', JSON.stringify(activeUser));

              // 3. Lazy Background Revalidation (Every 12 hours)
              const lastVerified = parsedUser.lastVerifiedAt || 0;
              if (email && (Date.now() - lastVerified > 12 * 60 * 60 * 1000)) {
                const supabase = getSupabase();
                supabase?.auth.getSession().then(({ data: { session } }) => {
                  const token = session?.access_token;
                  if (!token) return;
                  fetch('/api/v1/subscription/sync', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ email }),
                  })
                  .then((res) => res.ok ? res.json() : null)
                  .then((data) => {
                    if (data) {
                      setUser((prev) => {
                        if (!prev || (prev.email || '').toLowerCase() !== (email || '').toLowerCase()) return prev;
                        // Prevent false downgrades if local subscription is active or valid license key exists
                        const isLocallyValid = Boolean(
                          prev.tier !== 'Free' &&
                          (!prev.expiresAt || new Date(prev.expiresAt).getTime() > Date.now())
                        );
                        const isPlatformAdmin = isPlatformAdminEmail(email);
                        const currentLicenseKey = localStorage.getItem('zelsis_license_key');
                        const hasValidLic = Boolean(
                          currentLicenseKey && verifyLicenseKey(currentLicenseKey, email).valid
                        );
                        const isGenuinelyExpired = Boolean(
                          prev.expiresAt && new Date(prev.expiresAt).getTime() <= Date.now()
                        );
                        const shouldDowngrade = data.status === 'canceled' && isGenuinelyExpired && !hasValidLic;

                        let syncTier = prev.tier;
                        if (data.active && (data.tier === 'Pro' || (isPlatformAdmin && data.tier === 'Enterprise'))) {
                          syncTier = data.tier;
                        } else if (shouldDowngrade) {
                          syncTier = 'Free';
                        } else if (isLocallyValid || hasValidLic) {
                          syncTier = prev.tier;
                        }

                        if (!isPlatformAdmin) {
                          if (syncTier === 'Enterprise') syncTier = 'Free';
                        }

                        let updatedExpiresAt = data.expiresAt || prev.expiresAt || (syncTier !== 'Free' ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() : undefined);
                        if (!isPlatformAdmin && updatedExpiresAt?.includes('2099')) {
                          updatedExpiresAt = undefined;
                          syncTier = 'Free';
                        }

                        const updated: UserProfile = {
                          ...prev,
                          tier: syncTier,
                          expiresAt: updatedExpiresAt,
                          status: data.status || (syncTier !== 'Free' ? 'active' : 'canceled'),
                          gracePeriodUntil: data.gracePeriodUntil,
                          lastVerifiedAt: Date.now(),
                        };
                        localStorage.setItem('zelsis_user', JSON.stringify(updated));
                        return updated;
                      });
                    }
                  })
                  .catch(() => {});
                }).catch(() => {});
              }
            }
          } catch (jsonErr) {
            console.warn('[Zelsis Storage] Corrupted user session in localStorage; clearing.', jsonErr);
            localStorage.removeItem('zelsis_user');
            localStorage.removeItem('shipguard_user');
            setUser(null);
          }
        }
      } catch (err) {
        console.error('Failed to load persisted projects from localStorage:', err);
      }
    };

    loadProjectsFromStorage();

    // 1. Verify Polar checkout server-side if returning from payment
    const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : searchParams;
    const checkoutId = urlParams.get('checkout_id') || urlParams.get('checkoutId') || urlParams.get('session_id');

    if (checkoutId) {
      const verifyCheckoutReturn = async (cid: string) => {
        try {
          const currentSavedUser = localStorage.getItem('zelsis_user');
          const parsed = currentSavedUser ? JSON.parse(currentSavedUser) : null;
          const userEmail = parsed?.email || null;

          const res = await fetch('/api/v1/verify-checkout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ checkoutId: cid, email: userEmail }),
          });

          if (res.ok) {
            const data = await res.json();
            if (data.verified && (data.tier === 'Pro' || data.tier === 'Enterprise')) {
              const upgradedTier: 'Pro' | 'Enterprise' = data.tier === 'Enterprise' ? 'Enterprise' : 'Pro';
              const activeEmail = data.email || userEmail || 'subscriber@zelsis.com';
              const validExpiry = data.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
              
              setUser((prev) => {
                const updated: UserProfile = {
                  ...(prev || {
                    name: 'Pro Subscriber',
                    email: activeEmail,
                    isLoggedIn: true,
                  }),
                  tier: upgradedTier,
                  isLoggedIn: true,
                  expiresAt: validExpiry,
                  status: 'active',
                  lastVerifiedAt: Date.now(),
                };
                localStorage.setItem('zelsis_user', JSON.stringify(updated));
                return updated;
              });

              const planId = upgradedTier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
              const validLicKey = generateLicenseKey(planId, activeEmail);
              localStorage.setItem('zelsis_license_key', validLicKey);
              localStorage.setItem('shipguard_license_key', validLicKey);

              syncUserProfileToSupabase({
                tier: upgradedTier,
                expiresAt: validExpiry,
                status: 'active',
              }).catch(() => {});
            }
          }
        } catch (err) {
          console.warn('[Zelsis Checkout] Verification call error:', err);
        } finally {
          if (typeof window !== 'undefined') {
            const cleanUrl = new URL(window.location.href);
            cleanUrl.searchParams.delete('checkout_id');
            cleanUrl.searchParams.delete('checkoutId');
            cleanUrl.searchParams.delete('session_id');
            cleanUrl.searchParams.delete('success');
            cleanUrl.searchParams.delete('status');
            cleanUrl.searchParams.delete('restore');
            cleanUrl.searchParams.delete('pro');
            cleanUrl.searchParams.delete('user');
            window.history.replaceState({}, '', cleanUrl.toString());
          }
        }
      };
      verifyCheckoutReturn(checkoutId);
    }

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'zelsis_user' || e.key === 'shipguard_user') {
        // Never trust another tab's cached profile: re-verify against Supabase
        syncSupabaseSession();
      }
      if (
        !e.key ||
        e.key === 'zelsis_projects' ||
        e.key === 'zelsis_selected_project_id' ||
        e.key === 'shipguard_projects' ||
        e.key === 'shipguard_selected_project_id'
      ) {
        loadProjectsFromStorage();
      }
    };

    window.addEventListener('storage', handleStorageChange);

    // 2. Sync active Supabase OAuth session with automatic Subscription Sync
    // Restores the account's saved repositories / live sites from the cloud database
    const mergeCloudProjects = async (accountEmail: string) => {
      const cloudProjects = await fetchCloudProjects();
      if (cloudProjects.length === 0) return;
      const normalize = (url?: string) => (url || '').toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '').trim();

      setProjects((prev) => {
        const known = new Set(prev.map((p) => normalize(p.repoUrl)));
        const additions = cloudProjects.filter((cp) => cp.repoUrl && !known.has(normalize(cp.repoUrl)));
        if (additions.length === 0) return prev;
        const next = [...prev.filter((p) => p.id !== MOCK_PROJECTS[0].id), ...additions];
        const serialized = JSON.stringify(next);
        safeSetStorageItem('zelsis_projects', serialized);
        safeSetStorageItem(`zelsis_user_projects_${accountEmail}`, serialized);
        return next;
      });
    };

    const clearUnverifiedSession = () => {
      setUser(null);
      setAuthStatus('unauthenticated');
      localStorage.removeItem('zelsis_user');
      localStorage.removeItem('shipguard_user');
      localStorage.removeItem('zelsis_license_key');
      localStorage.removeItem('shipguard_license_key');
      localStorage.removeItem('zelsis_projects');
      localStorage.removeItem('shipguard_projects');
      setProjects([MOCK_PROJECTS[0]]);
      setSelectedProject(MOCK_PROJECTS[0]);
    };

    const syncSupabaseSession = async () => {
      try {
        const { status: verifiedStatus, user: supabaseUser, session } = await resolveVerifiedSession();
        if (verifiedStatus !== 'authenticated' || !supabaseUser) {
          clearUnverifiedSession();
          return;
        }
        if (supabaseUser) {
          const email = (supabaseUser.email || '').toLowerCase().trim();
          // Platform Administrator Detection (Configured via ADMIN_EMAILS)
          const isPlatformAdmin = isPlatformAdminEmail(email);

          // Strict account isolation: Check if local storage belongs to a different email
          const savedUserStr = localStorage.getItem('zelsis_user');
          if (savedUserStr) {
            try {
              const localParsed = JSON.parse(savedUserStr);
              const localEmail = (localParsed?.email || '').toLowerCase().trim();
              if (localEmail && localEmail !== email) {
                // Foreign account detected: wipe previous account's cache and licenses completely
                localStorage.removeItem('zelsis_user');
                localStorage.removeItem('shipguard_user');
                localStorage.removeItem('zelsis_license_key');
                localStorage.removeItem('shipguard_license_key');
              } else if (!isPlatformAdmin && (localParsed?.expiresAt?.includes('2099') || localParsed?.tier === 'Enterprise')) {
                // Tainted founder records on non-founder account
                localStorage.removeItem('zelsis_user');
                localStorage.removeItem('shipguard_user');
                localStorage.removeItem('zelsis_license_key');
                localStorage.removeItem('shipguard_license_key');
              }
            } catch (cleanupErr) {
              console.warn('[DashboardState] Storage cleanup notice:', cleanupErr);
            }
          }

          let resolvedTier: 'Free' | 'Pro' | 'Enterprise' = isPlatformAdmin ? 'Enterprise' : 'Free';
          let savedExpiresAt: string | undefined = isPlatformAdmin ? '2099-12-31T23:59:59.999Z' : undefined;
          let savedStatus: 'active' | 'past_due' | 'canceled' = isPlatformAdmin ? 'active' : 'canceled';

          if (!isPlatformAdmin) {
            const savedLic = localStorage.getItem('zelsis_license_key');
            if (savedLic && email) {
              const licCheck = verifyLicenseKey(savedLic, email);
              if (licCheck.valid && !licCheck.expiresAt?.includes('2099')) {
                resolvedTier = licCheck.tier;
                savedExpiresAt = licCheck.expiresAt;
                savedStatus = 'active';
              } else {
                localStorage.removeItem('zelsis_license_key');
                localStorage.removeItem('shipguard_license_key');
              }
            }
          }

          // Query subscription sync API to ensure local and remote tiers are synchronized
          if (email && session?.access_token) {
            try {
              const syncRes = await fetch('/api/v1/subscription/sync', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${session.access_token}`
                },
                body: JSON.stringify({ email }),
              });
              if (syncRes.ok) {
                const syncData = await syncRes.json();
                if (syncData.active && (syncData.tier === 'Pro' || syncData.tier === 'Enterprise') && (isPlatformAdmin || !syncData.expiresAt?.includes('2099'))) {
                  resolvedTier = syncData.tier;
                  savedExpiresAt = syncData.expiresAt;
                  savedStatus = syncData.status || 'active';
                } else if (!isPlatformAdmin) {
                  // Polar confirms no active paid subscription: strictly default to Free
                  resolvedTier = 'Free';
                  savedExpiresAt = undefined;
                  savedStatus = 'canceled';
                  localStorage.removeItem('zelsis_license_key');
                  localStorage.removeItem('shipguard_license_key');

                  // Auto-heal Supabase cloud metadata if it was tainted
                  if (supabaseUser.tier !== 'Free' || supabaseUser.expiresAt?.includes('2099')) {
                    syncUserProfileToSupabase({
                      tier: 'Free',
                      expiresAt: undefined,
                      status: 'canceled'
                    }).catch(() => {});
                  }
                }
              }
            } catch (err) {
              void err;
            }
          }

          if (resolvedTier !== 'Free' && isPlatformAdmin) {
            if (!savedExpiresAt) {
              savedExpiresAt = '2099-12-31T23:59:59.999Z';
            }
          } else if (resolvedTier === 'Free') {
            savedExpiresAt = undefined;
          }

          const mergedUser: UserProfile = {
            ...supabaseUser,
            tier: resolvedTier,
            expiresAt: savedExpiresAt,
            status: savedStatus,
            gracePeriodUntil: undefined,
            lastVerifiedAt: Date.now(),
          };

          setUser(mergedUser);
          setAuthStatus('authenticated');
          localStorage.setItem('zelsis_user', JSON.stringify(mergedUser));
          localStorage.removeItem('shipguard_user');

          if (resolvedTier !== 'Free' && supabaseUser.tier === 'Free' && isPlatformAdmin) {
            syncUserProfileToSupabase(mergedUser).catch(() => {});
          }

          mergeCloudProjects(email).catch(() => {});
        }
      } catch (err) {
        console.warn('[Zelsis Auth] Session sync notice:', err);
        clearUnverifiedSession();
      }
    };
    syncSupabaseSession();

    // 3. Supabase Auth State Listener with Pro Tier Protection
    const supabase = getSupabase();
    let authSubscription: { unsubscribe: () => void } | null = null;
    if (supabase) {
      const { data } = supabase.auth.onAuthStateChange(async (event, session) => {
        try {
          if (session && session.user) {
            const profile = mapSupabaseUserToProfile(session.user);
            const email = (profile.email || session.user.email || '').toLowerCase().trim();
            // Platform Administrator Detection (Configured via ADMIN_EMAILS)
            const isPlatformAdmin = isPlatformAdminEmail(email);

            // Strict account isolation: Check if local storage belongs to a different email or contains tainted metadata
            const savedUserStr = localStorage.getItem('zelsis_user');
            if (savedUserStr) {
              try {
                const localParsed = JSON.parse(savedUserStr);
                const localEmail = (localParsed?.email || '').toLowerCase().trim();
                if (localEmail && localEmail !== email) {
                  // Foreign account detected: wipe previous account's cache and licenses completely
                  localStorage.removeItem('zelsis_user');
                  localStorage.removeItem('shipguard_user');
                  localStorage.removeItem('zelsis_license_key');
                  localStorage.removeItem('shipguard_license_key');
                } else if (!isPlatformAdmin && (localParsed?.expiresAt?.includes('2099') || localParsed?.tier === 'Enterprise')) {
                  // Tainted metadata detected in local storage for non-founder: purge immediately
                  localStorage.removeItem('zelsis_user');
                  localStorage.removeItem('shipguard_user');
                  localStorage.removeItem('zelsis_license_key');
                  localStorage.removeItem('shipguard_license_key');
                }
              } catch (parseErr) {
                console.warn('[DashboardState] Local parsing notice:', parseErr);
              }
            }

            let resolvedTier: 'Free' | 'Pro' | 'Enterprise' = isPlatformAdmin ? 'Enterprise' : (profile.tier || 'Free');
            let savedExpiresAt: string | undefined = isPlatformAdmin ? '2099-12-31T23:59:59.999Z' : profile.expiresAt;
            let savedStatus: 'active' | 'past_due' | 'canceled' = (profile.status as 'active' | 'past_due' | 'canceled') || 'active';

            if (!isPlatformAdmin) {
              if (savedExpiresAt?.includes('2099') || resolvedTier === 'Enterprise') {
                resolvedTier = 'Free';
                savedExpiresAt = undefined;
                savedStatus = 'canceled';
              }
            }

            const freshSavedUserStr = localStorage.getItem('zelsis_user');
            if (freshSavedUserStr) {
              try {
                const localParsed = JSON.parse(freshSavedUserStr);
                const localEmail = (localParsed?.email || '').toLowerCase().trim();
                // Strict account isolation: only adopt local session if email matches exactly
                if (localParsed && localEmail && localEmail === email) {
                  const isTainted = !isPlatformAdmin && (localParsed.expiresAt?.includes('2099') || localParsed.tier === 'Enterprise');
                  if (!isTainted && (localParsed?.tier === 'Pro' || (isPlatformAdmin && localParsed?.tier === 'Enterprise'))) {
                    const localExpiry = localParsed?.expiresAt ? new Date(localParsed.expiresAt).getTime() : 0;
                    if (localExpiry > Date.now() || !localParsed.expiresAt) {
                      resolvedTier = localParsed.tier;
                      if (!savedExpiresAt) savedExpiresAt = localParsed.expiresAt;
                      savedStatus = localParsed.status || 'active';
                    }
                  }
                }
              } catch (err) {
                void err;
              }
            }

            const savedLic = localStorage.getItem('zelsis_license_key');
            if (savedLic) {
              const licCheck = verifyLicenseKey(savedLic, email);
              if (licCheck.valid && (isPlatformAdmin || licCheck.tier === 'Pro') && (isPlatformAdmin || !licCheck.expiresAt?.includes('2099'))) {
                resolvedTier = licCheck.tier;
                if (!savedExpiresAt) savedExpiresAt = licCheck.expiresAt;
                savedStatus = 'active';
              } else {
                localStorage.removeItem('zelsis_license_key');
                localStorage.removeItem('shipguard_license_key');
              }
            }

            // Query subscription sync API to ensure local and remote tiers are synchronized
            if (email && session?.access_token) {
              try {
                const syncRes = await fetch('/api/v1/subscription/sync', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${session.access_token}`
                  },
                  body: JSON.stringify({ email }),
                });
                if (syncRes.ok) {
                  const syncData = await syncRes.json();
                  if (syncData.active && (syncData.tier === 'Pro' || (isPlatformAdmin && syncData.tier === 'Enterprise')) && (isPlatformAdmin || !syncData.expiresAt?.includes('2099'))) {
                    resolvedTier = syncData.tier;
                    savedExpiresAt = syncData.expiresAt;
                    savedStatus = syncData.status || 'active';
                  } else if (!isPlatformAdmin) {
                    // Polar confirms no active paid subscription: strictly default to Free
                    resolvedTier = 'Free';
                    savedExpiresAt = undefined;
                    savedStatus = 'canceled';
                    localStorage.removeItem('zelsis_license_key');
                    localStorage.removeItem('shipguard_license_key');

                    // Auto-heal Supabase cloud metadata if it was tainted
                    if (profile.tier !== 'Free' || profile.expiresAt?.includes('2099')) {
                      syncUserProfileToSupabase({
                        tier: 'Free',
                        expiresAt: undefined,
                        status: 'canceled'
                      }).catch(() => {});
                    }
                  }
                }
              } catch (err) {
                void err;
              }
            }

            if (resolvedTier !== 'Free' && isPlatformAdmin) {
              if (!savedExpiresAt) {
                savedExpiresAt = '2099-12-31T23:59:59.999Z';
              }
            } else if (resolvedTier === 'Free') {
              savedExpiresAt = undefined;
              savedStatus = 'canceled';
              localStorage.removeItem('zelsis_license_key');
              localStorage.removeItem('shipguard_license_key');
            } else if (resolvedTier === 'Pro' && !savedExpiresAt) {
              savedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            }

            const mergedProfile: UserProfile = {
              ...profile,
              name: profile.name || (email ? email.split('@')[0] : 'User'),
              tier: resolvedTier,
              expiresAt: savedExpiresAt,
              status: savedStatus,
              gracePeriodUntil: undefined,
              lastVerifiedAt: Date.now(),
            };

            setUser(mergedProfile);
            setAuthStatus('authenticated');
            localStorage.setItem('zelsis_user', JSON.stringify(mergedProfile));
            localStorage.removeItem('shipguard_user');

            if (resolvedTier !== 'Free' && profile.tier === 'Free' && isPlatformAdmin) {
              syncUserProfileToSupabase(mergedProfile).catch(() => {});
            }

            if (event === 'SIGNED_IN') {
              mergeCloudProjects(email).catch(() => {});
            }
          } else if (event === 'SIGNED_OUT') {
            clearUnverifiedSession();
          }
        } catch (listenerErr) {
          console.warn('[Zelsis Auth] State change listener notice:', listenerErr);
        }
      });
      authSubscription = data?.subscription || null;
    }

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      if (authSubscription) {
        authSubscription.unsubscribe();
      }
    };
  }, []);

  const persistProjectsList = (updated: Project[]) => {
    try {
      const sanitized = canAccessLocalAudit()
        ? updated
        : updated.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self');
      const lightweight = sanitized.map((p) => {
        const { githubToken, ...safeProject } = p;
        return {
          ...safeProject,
          findings: (p.findings ?? []).slice(0, 60).map((f) => ({
            ...f,
            snippet: typeof f.snippet === 'string' && f.snippet.length > 150 ? f.snippet.slice(0, 150) + '...' : f.snippet,
            reproductionSteps: Array.isArray(f.reproductionSteps) ? f.reproductionSteps.slice(0, 1) : []
          }))
        };
      });
      safeSetStorageItem('zelsis_projects', JSON.stringify(lightweight), selectedProject.id);

      if (user?.isLoggedIn && user?.email) {
        const userProjectsKey = `zelsis_user_projects_${(user.email || '').toLowerCase().trim()}`;
        safeSetStorageItem(userProjectsKey, JSON.stringify(lightweight), selectedProject.id);
      }
    } catch (primaryQuotaErr) {
      void primaryQuotaErr;
      try {
        const sanitized = canAccessLocalAudit()
          ? updated
          : updated.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self');
        const ultraCompact = sanitized.map((p) => {
          const { githubToken, ...safeProject } = p;
          return {
            ...safeProject,
            findings: (p.findings ?? []).slice(0, 20).map((f) => ({
              id: f.id,
              ruleId: f.ruleId,
              type: f.type,
              title: f.title,
              severity: f.severity,
              filePath: f.filePath,
              status: f.status
            }))
          };
        });
        safeSetStorageItem('zelsis_projects', JSON.stringify(ultraCompact), selectedProject.id);

        if (user?.isLoggedIn && user?.email) {
          const userProjectsKey = `zelsis_user_projects_${(user.email || '').toLowerCase().trim()}`;
          safeSetStorageItem(userProjectsKey, JSON.stringify(ultraCompact), selectedProject.id);
        }
      } catch (fallbackQuotaErr) {
        console.warn('[Zelsis Storage] Silent localStorage quota limit handled gracefully:', fallbackQuotaErr);
      }
    }
  };

  const handleSelectProject = (p?: Project | null) => {
    if (!p || typeof p !== 'object' || ('nativeEvent' in p) || !('id' in p) || !p.id) {
      setSelectedProject(MOCK_PROJECTS[0]);
      safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
      return;
    }
    if (!canAccessLocalAudit() && (p.repoUrl === 'local' || p.id === 'proj-zelsis-self' || p.id === 'proj-shipguard-self')) {
      setSelectedProject(MOCK_PROJECTS[0]);
      safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
      return;
    }
    const cleanRepoUrl = typeof p.repoUrl === 'string' && p.repoUrl.trim() && p.repoUrl !== 'undefined'
      ? p.repoUrl.trim()
      : MOCK_PROJECTS[0].repoUrl;
    const cleanName = typeof p.name === 'string' && p.name.trim() && p.name !== 'undefined'
      ? p.name.trim()
      : (cleanRepoUrl ? cleanRepoUrl.split('/').pop() || 'Target Repository' : MOCK_PROJECTS[0].name);

    const safeP: Project = {
      ...p,
      id: p.id || `proj-${Date.now()}`,
      name: cleanName,
      repoUrl: cleanRepoUrl,
      framework: p.framework || 'Next.js 15',
      providers: Array.isArray(p.providers) ? p.providers : ['GitHub Action', 'Vercel'],
      lastScanAt: p.lastScanAt || 'Never audited',
      readinessScore: typeof p.readinessScore === 'number' ? p.readinessScore : 100,
      gateStatus: p.gateStatus || 'PASSED',
      criticalCount: typeof p.criticalCount === 'number' ? p.criticalCount : 0,
      highCount: typeof p.highCount === 'number' ? p.highCount : 0,
      mediumCount: typeof p.mediumCount === 'number' ? p.mediumCount : 0,
      lowCount: typeof p.lowCount === 'number' ? p.lowCount : 0,
      uiClicheCount: typeof p.uiClicheCount === 'number' ? p.uiClicheCount : 0,
      findings: Array.isArray(p.findings) ? p.findings : [],
    };
    setSelectedProject(safeP);
    safeSetStorageItem('zelsis_selected_project_id', safeP.id);
  };

  const handleDeleteProject = (projectId: string) => {
    setProjects((prevProjects) => {
      const updatedList = prevProjects.filter((p) => p.id !== projectId);
      const fallbackList = updatedList.length > 0 ? updatedList : [MOCK_PROJECTS[0]];
      persistProjectsList(fallbackList);

      if (selectedProject.id === projectId) {
        const nextSelected = fallbackList[0] || MOCK_PROJECTS[0];
        setSelectedProject(nextSelected);
        safeSetStorageItem('zelsis_selected_project_id', nextSelected.id);
      }

      return fallbackList;
    });
  };

  const handleToggleResolveFinding = (findingId: string) => {
    setProjects((prevProjects) => {
      let newlyUpdatedSelectedProj: Project | null = null;
      const updatedList = prevProjects.map((proj) => {
        const hasFinding = (proj.findings ?? []).some((f) => f.id === findingId);
        if (!hasFinding) return proj;

        const updatedFindings = (proj.findings ?? []).map((f) => {
          if (f.id === findingId) {
            const nextStatus: Finding['status'] = f.status === 'RESOLVED' ? 'OPEN' : 'RESOLVED';
            return { ...f, status: nextStatus };
          }
          return f;
        });

        const openCritical = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
        const openHigh = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
        const openMedium = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
        const openLow = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
        const openUiCliches = updatedFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;

        const nextGate: Project['gateStatus'] = calculateGateStatus(updatedFindings);
        const nextScore = calculateReadinessScore(updatedFindings);

        const updatedProj: Project = {
          ...proj,
          findings: updatedFindings,
          gateStatus: nextGate,
          readinessScore: nextScore,
          criticalCount: openCritical,
          highCount: openHigh,
          mediumCount: openMedium,
          lowCount: openLow,
          uiClicheCount: openUiCliches,
        };

        if (proj.id === selectedProject.id) {
          newlyUpdatedSelectedProj = updatedProj;
        }

        return updatedProj;
      });

      if (newlyUpdatedSelectedProj) {
        setSelectedProject(newlyUpdatedSelectedProj);
      }
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  /**
   * F-43 Remediation: Triage finding as False Positive.
   * Updates finding.falsePositive flag, sets status to ACCEPTED_RISK, and recalculates release readiness.
   */
  const handleMarkFalsePositive = (findingId: string) => {
    setProjects((prevProjects) => {
      let newlyUpdatedSelectedProj: Project | null = null;
      const updatedList = prevProjects.map((proj) => {
        const hasFinding = (proj.findings ?? []).some((f) => f.id === findingId);
        if (!hasFinding) return proj;

        const updatedFindings = (proj.findings ?? []).map((f) => {
          if (f.id === findingId) {
            const isCurrentlyFp = Boolean(f.falsePositive);
            return {
              ...f,
              falsePositive: !isCurrentlyFp,
              status: (!isCurrentlyFp ? 'ACCEPTED_RISK' : 'OPEN') as Finding['status']
            };
          }
          return f;
        });

        const openCritical = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
        const openHigh = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
        const openMedium = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
        const openLow = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
        const openUiCliches = updatedFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;

        const nextGate: Project['gateStatus'] = calculateGateStatus(updatedFindings);
        const nextScore = calculateReadinessScore(updatedFindings);

        const updatedProj: Project = {
          ...proj,
          findings: updatedFindings,
          gateStatus: nextGate,
          readinessScore: nextScore,
          criticalCount: openCritical,
          highCount: openHigh,
          mediumCount: openMedium,
          lowCount: openLow,
          uiClicheCount: openUiCliches,
        };

        if (proj.id === selectedProject.id) {
          newlyUpdatedSelectedProj = updatedProj;
        }

        return updatedProj;
      });

      if (newlyUpdatedSelectedProj) {
        setSelectedProject(newlyUpdatedSelectedProj);
      }
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  /**
   * F-43 Remediation: Ignore entire rule across the project.
   */
  const handleIgnoreRule = (ruleId: number) => {
    setProjects((prevProjects) => {
      let newlyUpdatedSelectedProj: Project | null = null;
      const updatedList = prevProjects.map((proj) => {
        const hasRule = (proj.findings ?? []).some((f) => f.ruleId === ruleId);
        if (!hasRule) return proj;

        const updatedFindings = (proj.findings ?? []).map((f) => {
          if (f.ruleId === ruleId) {
            return {
              ...f,
              status: 'ACCEPTED_RISK' as Finding['status']
            };
          }
          return f;
        });

        const openCritical = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
        const openHigh = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
        const openMedium = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
        const openLow = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
        const openUiCliches = updatedFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;

        const nextGate: Project['gateStatus'] = calculateGateStatus(updatedFindings);
        const nextScore = calculateReadinessScore(updatedFindings);

        const updatedProj: Project = {
          ...proj,
          findings: updatedFindings,
          gateStatus: nextGate,
          readinessScore: nextScore,
          criticalCount: openCritical,
          highCount: openHigh,
          mediumCount: openMedium,
          lowCount: openLow,
          uiClicheCount: openUiCliches,
        };

        if (proj.id === selectedProject.id) {
          newlyUpdatedSelectedProj = updatedProj;
        }

        return updatedProj;
      });

      if (newlyUpdatedSelectedProj) {
        setSelectedProject(newlyUpdatedSelectedProj);
      }
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  const handleAuthSubmit = async (mode: 'signin' | 'signup', email: string, pass: string, name?: string) => {
    if (mode === 'signup') {
      const res = await supabaseSignUp(email, pass, name || '');
      if (res.error) throw new Error(res.error);
      const derivedName = name?.trim() || res.user?.name || (email ? email.split('@')[0].replace(/[._-]/g, ' ') : '') || 'User';

      let resolvedSignUpTier: 'Free' | 'Pro' | 'Enterprise' = res.user?.tier || 'Free';
      let resolvedSignUpExpiresAt: string | undefined = undefined;

      const savedUserStr = localStorage.getItem('zelsis_user');
      if (savedUserStr) {
        try {
          const parsed = JSON.parse(savedUserStr);
          if (parsed && (parsed.tier === 'Pro' || parsed.tier === 'Enterprise')) {
            const isNotExpired = !parsed.expiresAt || new Date(parsed.expiresAt).getTime() > Date.now();
            if (isNotExpired) {
              resolvedSignUpTier = parsed.tier;
              resolvedSignUpExpiresAt = parsed.expiresAt;
            }
          }
        } catch (signUpParseErr) {
          console.warn('[DashboardState] SignUp user parse notice:', signUpParseErr);
        }
      }

      const savedLic = localStorage.getItem('zelsis_license_key');
      if (savedLic) {
        const lic = verifyLicenseKey(savedLic, email.trim());
        if (lic.valid && (lic.tier === 'Pro' || lic.tier === 'Enterprise')) {
          resolvedSignUpTier = lic.tier;
          resolvedSignUpExpiresAt = lic.expiresAt;
        }
      }

      if (resolvedSignUpTier !== 'Free' && !resolvedSignUpExpiresAt) {
        resolvedSignUpExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      }

      const newUser: UserProfile = {
        name: derivedName,
        email: email.trim(),
        avatarUrl: res.user?.avatarUrl || undefined,
        tier: resolvedSignUpTier,
        isLoggedIn: true,
        emailVerified: res.user?.emailVerified ?? false,
        expiresAt: resolvedSignUpExpiresAt,
        status: 'active',
        lastVerifiedAt: Date.now(),
      };
      setUser(newUser);
      safeSetStorageItem('zelsis_user', JSON.stringify(newUser));
      localStorage.removeItem('shipguard_user');
      if (typeof document !== 'undefined') {
        document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
      }
      if (resolvedSignUpTier !== 'Free') {
        const planId = resolvedSignUpTier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
        const validKey = generateLicenseKey(planId, email.trim());
        localStorage.setItem('zelsis_license_key', validKey);
        localStorage.setItem('shipguard_license_key', validKey);
        syncUserProfileToSupabase(newUser).catch(() => {});
      }
    } else {
      const res = await supabaseSignIn(email, pass);
      if (res.error) throw new Error(res.error);
      const derivedName = res.user?.name || (email ? email.split('@')[0].replace(/[._-]/g, ' ') : '') || 'User';
      
      let resolvedTier = res.user?.tier || 'Free';
      let resolvedExpiresAt = res.user?.expiresAt;
      if (resolvedTier === 'Free') {
        const saved = localStorage.getItem('zelsis_user');
        if (saved) {
          try {
            const p = JSON.parse(saved);
            if ((p?.tier === 'Pro' || p?.tier === 'Enterprise') && (p.email || '').toLowerCase() === (email || '').toLowerCase()) {
              const isNotExpired = !p.expiresAt || new Date(p.expiresAt).getTime() > Date.now();
              if (isNotExpired) {
                resolvedTier = p.tier;
                resolvedExpiresAt = p.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
              }
            }
          } catch (signInParseErr) {
            console.warn('[DashboardState] SignIn user parse notice:', signInParseErr);
          }
        }
      }

      if (resolvedTier !== 'Free' && !resolvedExpiresAt) {
        resolvedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      }

      const loggedInUser: UserProfile = {
        name: derivedName,
        email: email.trim(),
        avatarUrl: res.user?.avatarUrl || undefined,
        tier: resolvedTier,
        isLoggedIn: true,
        emailVerified: res.user?.emailVerified ?? true,
        expiresAt: resolvedExpiresAt,
        status: resolvedTier !== 'Free' ? 'active' : 'active',
        lastVerifiedAt: Date.now(),
      };
      setUser(loggedInUser);
      safeSetStorageItem('zelsis_user', JSON.stringify(loggedInUser));
      localStorage.removeItem('shipguard_user');
      if (typeof document !== 'undefined') {
        document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
      }

      if (resolvedTier !== 'Free') {
        const planId = resolvedTier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
        const validKey = generateLicenseKey(planId, email.trim());
        localStorage.setItem('zelsis_license_key', validKey);
        localStorage.setItem('shipguard_license_key', validKey);
        syncUserProfileToSupabase(loggedInUser).catch(() => {});
      }
    }

    if (email) {
      try {
        const userProjectsKey = `zelsis_user_projects_${(email || '').toLowerCase().trim()}`;
        const savedUserProjectsStr = localStorage.getItem(userProjectsKey);
        if (savedUserProjectsStr) {
          const parsed = JSON.parse(savedUserProjectsStr);
          if (Array.isArray(parsed) && parsed.length > 0) {
            const allowedLocal = canAccessLocalAudit();
            const projectList = parsed as Project[];
            const filtered = (allowedLocal
              ? projectList
              : projectList.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self')
            ).map((p) => {
              const { githubToken, ...safeP } = p;
              return safeP;
            });
            setProjects(filtered);
            setSelectedProject(filtered[0]);
            safeSetStorageItem('zelsis_projects', JSON.stringify(filtered));
            safeSetStorageItem('zelsis_selected_project_id', filtered[0].id);
          }
        }
      } catch (authProjErr) {
        console.warn('[Zelsis Auth] Failed to restore user projects upon auth submit:', authProjErr);
      }
    }
  };

  const handleUpdateUserProfile = (fields: Partial<UserProfile>) => {
    setUser((prev) => {
      if (!prev) {
        return null;
      }
      const isUpgradingTier = fields.tier && (fields.tier === 'Pro' || fields.tier === 'Enterprise');
      const guaranteedExpiresAt = fields.expiresAt || (isUpgradingTier ? (prev.expiresAt && new Date(prev.expiresAt).getTime() > Date.now() ? prev.expiresAt : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()) : prev.expiresAt);

      const updated: UserProfile = {
        ...prev,
        ...fields,
        expiresAt: guaranteedExpiresAt,
        status: fields.status || (fields.tier && fields.tier !== 'Free' ? 'active' : prev.status || 'active'),
        lastVerifiedAt: Date.now(),
      };
      safeSetStorageItem('zelsis_user', JSON.stringify(updated));
      localStorage.removeItem('shipguard_user');

      if (isUpgradingTier) {
        const planId = fields.tier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
        const validKey = generateLicenseKey(planId, updated.email || 'customer@zelsis.dev');
        localStorage.setItem('zelsis_license_key', validKey);
        localStorage.setItem('shipguard_license_key', validKey);
      }

      syncUserProfileToSupabase(updated).catch(() => {});

      return updated;
    });
  };

  const handleSignOut = async () => {
    // 1. Back up authenticated user's projects before clearing active session
    if (user?.email && projects && projects.length > 0) {
      try {
        const userProjectsKey = `zelsis_user_projects_${(user.email || '').toLowerCase().trim()}`;
        safeSetStorageItem(userProjectsKey, JSON.stringify(projects));
      } catch (backupErr) {
        console.warn('[Zelsis Auth] Failed to backup user projects on sign out:', backupErr);
      }
    }

    await supabaseSignOut().catch(() => {});
    setUser(null);
    setAuthStatus('unauthenticated');

    // 2. Reset in-memory projects and selected project to clean demo showcase
    const cleanDemoProjects = [MOCK_PROJECTS[0]];

    setProjects(cleanDemoProjects);
    setSelectedProject(cleanDemoProjects[0]);

    // 3. Purge session projects from localStorage so signed-out visitors never see previous scans
    localStorage.removeItem('zelsis_projects');
    localStorage.removeItem('shipguard_projects');
    localStorage.removeItem('zelsis_selected_project_id');
    localStorage.removeItem('shipguard_selected_project_id');
    localStorage.removeItem('zelsis_license_key');
    localStorage.removeItem('shipguard_license_key');
    localStorage.removeItem('zelsis_user');
    localStorage.removeItem('shipguard_user');

    if (typeof document !== 'undefined') {
      document.cookie = 'zelsis_user=; path=/; max-age=0; SameSite=Lax';
      document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
    }
  };

  return {
    activeNav,
    setActiveNav,
    projects,
    setProjects,
    selectedProject,
    setSelectedProject,
    isScanning,
    setIsScanning,
    inspectingFinding,
    setInspectingFinding,
    user,
    setUser,
    authStatus,
    isAuthModalOpen,
    setIsAuthModalOpen,
    authInitialMode,
    setAuthInitialMode,
    isCheckoutOpen,
    setIsCheckoutOpen,
    persistProjectsList,
    handleSelectProject,
    handleDeleteProject,
    handleToggleResolveFinding,
    handleMarkFalsePositive,
    handleIgnoreRule,
    handleAuthSubmit,
    handleSignOut,
    handleUpdateUserProfile,
    quota,
    setQuota,
    recordScanUsage,
    recordAiPromptUsage,
    requestScanAuthorization,
    completeScanTelemetry,
  };
}
