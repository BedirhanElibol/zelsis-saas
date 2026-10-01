'use client';

import React, { Suspense, useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { CheckoutView } from '@/components/checkout/CheckoutView';
import { MOCK_PROJECTS } from '@/data/demo-data';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';
import { purgeZelsisStorage, purgeShipguardStorage } from '@/lib/storage';
import { verifyLicenseKey } from '@/lib/stripe-checkout';

function normalizePlanId(rawPlan: string | null): string {
  if (!rawPlan) return 'zelsis-core';
  const clean = rawPlan.toLowerCase().trim();
  if (clean === 'enterprise' || clean === 'vibecare' || clean === 'zelsis-suite' || clean === 'suite') {
    return 'vibecare';
  }
  return 'zelsis-core';
}

function CheckoutPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const planId = normalizePlanId(searchParams.get('plan'));
  const isSuccess = searchParams.get('success') === 'true';
  const checkoutId = searchParams.get('checkout_id') || searchParams.get('checkoutId') || null;
  const reason = searchParams.get('reason');

  const [user, setUser] = useState<UserProfile | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>('signin');

  useEffect(() => {
    if (typeof window !== 'undefined' && (window.location.search.includes('checkout_id') || window.location.search.includes('success='))) {
      const cleanUrl = new URL(window.location.href);
      cleanUrl.searchParams.delete('checkout_id');
      cleanUrl.searchParams.delete('checkoutId');
      cleanUrl.searchParams.delete('success');
      window.history.replaceState({}, '', cleanUrl.toString());
    }
  }, []);

  useEffect(() => {
    const auth = searchParams.get('auth');
    if (auth === 'signin' || auth === 'signup') {
      if (user?.isLoggedIn) {
        setIsAuthModalOpen(false);
        if (typeof window !== 'undefined' && window.location.search.includes('auth')) {
          const cleanUrl = new URL(window.location.href);
          cleanUrl.searchParams.delete('auth');
          window.history.replaceState({}, '', cleanUrl.toString());
        }
      } else {
        setAuthInitialMode(auth);
        setIsAuthModalOpen(true);
      }
    }
  }, [searchParams, user]);

  useEffect(() => {
    try {
      let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
      if (!savedUserStr && typeof document !== 'undefined') {
        const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
        if (match && match[3]) {
          savedUserStr = decodeURIComponent(match[3]);
        }
      }
      if (savedUserStr) {
        const parsed = JSON.parse(savedUserStr);
        if (parsed && parsed.isLoggedIn) {
          setUser(parsed);
        }
      }
    } catch (e) {
      console.warn('[CheckoutPage] Failed to read user:', e);
    }
  }, []);

  return (
    <AppShell
      projects={[MOCK_PROJECTS[0]]}
      activeNav="checkout"
      onNavigate={(nav) => {
        if (nav === 'dashboard') router.push('/dashboard');
        else router.push(`/dashboard?nav=${nav}`);
      }}
      selectedProject={MOCK_PROJECTS[0]}
      onSelectProject={() => {}}
      onTriggerScan={() => router.push('/dashboard?nav=scans')}
      onNavigateLanding={() => router.push('/')}
      user={user}
      onOpenAuth={(mode) => {
        setAuthInitialMode(mode);
        setIsAuthModalOpen(true);
      }}
      onSignOut={() => {
        setUser(null);
        try {
          localStorage.removeItem('zelsis_user');
          localStorage.removeItem('shipguard_user');
          localStorage.removeItem('zelsis_projects');
          localStorage.removeItem('shipguard_projects');
          localStorage.removeItem('zelsis_selected_project_id');
          localStorage.removeItem('shipguard_selected_project_id');
          localStorage.removeItem('zelsis_license_key');
          localStorage.removeItem('shipguard_license_key');
          if (typeof document !== 'undefined') {
            const secureFlag = window.location.protocol === 'https:' ? '; Secure' : '';
            document.cookie = `zelsis_user=; path=/; max-age=0; SameSite=Lax${secureFlag}`;
            document.cookie = `shipguard_user=; path=/; max-age=0; SameSite=Lax${secureFlag}`;
          }
        } catch (e) {
          console.warn('[CheckoutPage] Failed to purge storage:', e);
        }
      }}
    >
      <CheckoutView
        initialPlanId={planId}
        initialSuccess={isSuccess}
        checkoutId={checkoutId}
        reason={reason}
        onBackToPricing={() => router.push('/#pricing')}
        user={user}
        onOpenAuth={(mode) => {
          setAuthInitialMode(mode || 'signup');
          setIsAuthModalOpen(true);
        }}
        onUpgradeSuccess={(newTier) => {
          const updatedUser: UserProfile = {
            ...(user || { name: 'Customer', email: 'customer@zelsis.dev', isLoggedIn: true, emailVerified: true }),
            tier: newTier,
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            status: 'active',
            lastVerifiedAt: Date.now(),
          };
          setUser(updatedUser);
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
            localStorage.removeItem('shipguard_user');
          } catch (storageErr) {
            void storageErr;
          }
        }}
      />

      <AuthModal
        isOpen={isAuthModalOpen && !user?.isLoggedIn}
        onClose={() => {
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined' && window.location.search.includes('auth')) {
            const cleanUrl = new URL(window.location.href);
            cleanUrl.searchParams.delete('auth');
            window.history.replaceState({}, '', cleanUrl.toString());
          }
        }}
        initialMode={authInitialMode}
        onLoginSuccess={(loggedUser) => {
          let resolvedTier = loggedUser.tier || 'Free';
          let resolvedExpiresAt = loggedUser.expiresAt;
          const savedLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          if (savedLic) {
            const licResult = verifyLicenseKey(savedLic, loggedUser.email);
            if (licResult.valid && (licResult.tier === 'Pro' || licResult.tier === 'Enterprise')) {
              resolvedTier = licResult.tier;
              resolvedExpiresAt = licResult.expiresAt;
            }
          }
          if (resolvedTier !== 'Free' && !resolvedExpiresAt) {
            resolvedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          }
          const finalUser: UserProfile = {
            ...loggedUser,
            tier: resolvedTier,
            expiresAt: resolvedExpiresAt,
            status: resolvedTier !== 'Free' ? 'active' : (loggedUser.status || 'active'),
            lastVerifiedAt: Date.now(),
          };
          setUser(finalUser);
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(finalUser));
            localStorage.removeItem('shipguard_user');
            if (typeof document !== 'undefined') {
              const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
              const secureAttr = isHttps ? '; Secure' : '';
              // F-32 Remediation: Eliminate non-HttpOnly PII cookie to prevent client-side data exposure
              document.cookie = `zelsis_user=; path=/; max-age=0; SameSite=Lax${secureAttr}`;
              document.cookie = `shipguard_user=; path=/; max-age=0; SameSite=Lax${secureAttr}`;
            }
          } catch (e) {
            console.warn('[CheckoutPage] Failed to save user to storage:', e);
          }
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined' && window.location.search.includes('auth')) {
            const cleanUrl = new URL(window.location.href);
            cleanUrl.searchParams.delete('auth');
            window.history.replaceState({}, '', cleanUrl.toString());
          }
        }}
      />
    </AppShell>
  );
}

export default function CheckoutPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-mono text-xs flex items-center justify-center">
        Loading Zelsis B2B Checkout...
      </div>
    }>
      <CheckoutPageContent />
    </Suspense>
  );
}
