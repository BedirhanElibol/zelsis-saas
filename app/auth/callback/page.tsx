'use client';

import React, { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { getSupabase, mapSupabaseUserToProfile, syncUserProfileToSupabase, isPlatformAdminEmail } from '@/lib/supabase';
import { verifyLicenseKey } from '@/lib/stripe-checkout';
import { isFounderGrantExpiry } from '@/lib/subscription-utils';
import { Shield, Loader2, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

function CallbackHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState<string>('Verifying authentication credentials...');

  useEffect(() => {
    let isMounted = true;
    let authSubscription: { unsubscribe: () => void } | null = null;
    let timeoutId: NodeJS.Timeout | null = null;
    let isHandled = false;

    const finalizeAuth = (user: any) => {
      if (isHandled || !isMounted) return;
      isHandled = true;

      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }

      if (authSubscription) {
        try {
          authSubscription.unsubscribe();
          authSubscription = null;
        } catch (unsubErr) {
          console.warn('[Zelsis OAuth] Unsubscribe notice:', unsubErr);
        }
      }

      try {
        const profile = mapSupabaseUserToProfile(user);
        const finalProfile = mergeWithExistingSession(profile);

        setStatus('success');
        setMessage(`Welcome, @${finalProfile.name || 'User'}! Redirecting to dashboard...`);

        setTimeout(() => {
          if (isMounted) {
            router.push('/dashboard');
          }
        }, 600);
      } catch (finalizeErr: any) {
        console.error('[Zelsis OAuth] Finalize session error:', finalizeErr);
        setStatus('error');
        setMessage('Failed to complete session setup. Please try again.');
      }
    };

    const mergeWithExistingSession = (rawProfile: any) => {
      const userEmail = (rawProfile.email || '').toLowerCase().trim();
      // Founder & Platform Administrator Detection (Configured via ADMIN_EMAILS)
      const isPlatformAdmin = isPlatformAdminEmail(userEmail);

      // Check if browser has stale cache from another account or tainted founder records
      const savedLocalUserStr = localStorage.getItem('zelsis_user');
      if (savedLocalUserStr) {
        try {
          const parsedLocal = JSON.parse(savedLocalUserStr);
          const localEmail = (parsedLocal?.email || '').toLowerCase().trim();
          if (localEmail && localEmail !== userEmail) {
            // Foreign account detected: wipe previous account's cache and licenses completely
            localStorage.removeItem('zelsis_user');
            localStorage.removeItem('shipguard_user');
            localStorage.removeItem('zelsis_license_key');
            localStorage.removeItem('shipguard_license_key');
          } else if (!isPlatformAdmin && isFounderGrantExpiry(parsedLocal?.expiresAt)) {
            // Tainted founder records on non-founder account
            localStorage.removeItem('zelsis_user');
            localStorage.removeItem('shipguard_user');
            localStorage.removeItem('zelsis_license_key');
            localStorage.removeItem('shipguard_license_key');
          }
        } catch (parseLocalErr) {
          console.warn('[Zelsis OAuth] Stale user parsing notice:', parseLocalErr);
        }
      }

      let effectiveTier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
      let effectiveExpiresAt: string | undefined = undefined;
      let effectiveStatus: 'active' | 'past_due' | 'canceled' = 'canceled';

      if (isPlatformAdmin) {
        effectiveTier = 'Enterprise';
        effectiveExpiresAt = '2099-12-31T23:59:59.999Z';
        effectiveStatus = 'active';
      } else {
        // Non-founder: strictly sanitize and check for legitimate license key
        const savedLic = localStorage.getItem('zelsis_license_key');
        if (savedLic && userEmail) {
          const licResult = verifyLicenseKey(savedLic, userEmail);
          if (licResult.valid && !licResult.expiresAt?.includes('2099')) {
            effectiveTier = licResult.tier;
            effectiveExpiresAt = licResult.expiresAt;
            effectiveStatus = 'active';
          } else {
            localStorage.removeItem('zelsis_license_key');
            localStorage.removeItem('shipguard_license_key');
          }
        }

        // Auto-heal tainted cloud Supabase metadata if previous buggy version saved a founder 2099 grant
        if (isFounderGrantExpiry(rawProfile.expiresAt)) {
          console.info('[Zelsis OAuth] Non-founder profile had tainted metadata. Auto-healing to Free Tier in Supabase.');
          syncUserProfileToSupabase({
            tier: 'Free',
            expiresAt: undefined,
            status: 'canceled'
          }).catch(() => {});
        }
      }

      const merged = {
        ...rawProfile,
        name: rawProfile.name || (userEmail ? userEmail.split('@')[0] : 'User'),
        tier: effectiveTier,
        expiresAt: effectiveExpiresAt,
        status: effectiveStatus,
        lastVerifiedAt: Date.now(),
      };

      try {
        localStorage.setItem('zelsis_user', JSON.stringify(merged));
        localStorage.removeItem('shipguard_user');
        if (typeof document !== 'undefined') {
          const secureFlag = window.location.protocol === 'https:' ? '; Secure' : '';
          document.cookie = `shipguard_user=; path=/; max-age=0; SameSite=Lax${secureFlag}`;
        }
      } catch (storageErr) {
        console.warn('[Zelsis OAuth] Storage write notice:', storageErr);
      }

      return merged;
    };

    async function processAuth() {
      try {
        const errorParam = searchParams.get('error') || searchParams.get('error_description');
        if (errorParam) {
          if (isMounted) {
            setStatus('error');
            setMessage(decodeURIComponent(errorParam));
          }
          return;
        }

        const supabase = getSupabase();
        if (!supabase) {
          if (isMounted) {
            setStatus('error');
            setMessage('Authentication service is currently unavailable.');
          }
          return;
        }

        const code = searchParams.get('code');
        if (code) {
          setMessage('Verifying authorization code...');
          try {
            const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);
            if (exchangeError) {
              console.warn('[Zelsis OAuth] Code exchange notice:', exchangeError.message);
            }
          } catch (codeExErr) {
            console.warn('[Zelsis OAuth] exchangeCodeForSession exception:', codeExErr);
          }
        }

        // 1. Check if session is already available
        const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
        if (!sessionError && sessionData?.session?.user) {
          finalizeAuth(sessionData.session.user);
          return;
        }

        // 2. Set listener for session state changes (handles PKCE or hash-fragment completion)
        const { data: authListener } = supabase.auth.onAuthStateChange((event, newSession) => {
          try {
            if (newSession?.user && isMounted && !isHandled) {
              finalizeAuth(newSession.user);
            }
          } catch (eventErr) {
            console.error('[Zelsis OAuth] Event handler error:', eventErr);
          }
        });
        authSubscription = authListener?.subscription || null;

        // If the listener synchronously fired and finalized, unsubscribe immediately
        if (isHandled) {
          if (authSubscription) {
            try {
              authSubscription.unsubscribe();
              authSubscription = null;
            } catch (unsubErr) {
              console.warn('[Zelsis OAuth] Sync unsubscribe notice:', unsubErr);
            }
          }
          return;
        }

        // 3. Set a safety timeout
        timeoutId = setTimeout(async () => {
          if (!isMounted || isHandled) return;
          try {
            const { data: finalCheck } = await supabase.auth.getSession();
            if (finalCheck?.session?.user) {
              finalizeAuth(finalCheck.session.user);
              return;
            }
          } catch (sessionErr) {
            console.warn('[Zelsis OAuth] Timeout session check notice:', sessionErr);
          }

          if (isMounted && status === 'loading') {
            setStatus('error');
            setMessage('Authentication timed out. Please return to the homepage and try signing in again.');
          }
        }, 7000);

      } catch (err: any) {
        console.error('[Zelsis OAuth] Callback exception:', err);
        if (isMounted) {
          setStatus('error');
          setMessage(err?.message || 'An unexpected error occurred during authentication.');
        }
      }
    }

    processAuth();

    return () => {
      isMounted = false;
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      if (authSubscription) {
        try {
          authSubscription.unsubscribe();
        } catch (unsubErr) {
          console.warn('[Zelsis OAuth] Cleanup unsubscribe notice:', unsubErr);
        }
      }
    };
  }, [router, searchParams]);

  return (
    <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl backdrop-blur-xl text-center">
      <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-neutral-800/80 border border-neutral-700 flex items-center justify-center">
        {status === 'loading' && <Loader2 className="w-8 h-8 text-emerald-400 animate-spin" />}
        {status === 'success' && <CheckCircle2 className="w-8 h-8 text-emerald-400" />}
        {status === 'error' && <AlertTriangle className="w-8 h-8 text-amber-400" />}
      </div>

      <div className="flex items-center justify-center gap-2 mb-3">
        <Shield className="w-5 h-5 text-emerald-400" />
        <span className="text-sm font-mono uppercase tracking-widest text-neutral-400">Zelsis Auth</span>
      </div>

      <h1 className="text-xl font-bold text-white mb-2">
        {status === 'loading' && 'Authenticating with Provider'}
        {status === 'success' && 'Signed in Successfully'}
        {status === 'error' && 'Authentication Failed'}
      </h1>

      <p className="text-sm text-neutral-400 mb-6 font-mono leading-relaxed">{message}</p>

      {status === 'error' && (
        <div className="space-y-3">
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-xl bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white text-sm font-medium transition-colors"
          >
            Return to Dashboard <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/"
            className="inline-block text-xs text-neutral-500 hover:text-neutral-400 underline underline-offset-4"
          >
            Go to Homepage
          </Link>
        </div>
      )}
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <main className="min-h-screen bg-neutral-950 flex flex-col items-center justify-center px-4">
      <Suspense
        fallback={
          <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-2xl p-8 text-center">
            <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mx-auto mb-4" />
            <p className="text-sm text-neutral-400 font-mono">Loading...</p>
          </div>
        }
      >
        <CallbackHandler />
      </Suspense>
    </main>
  );
}
