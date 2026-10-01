'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ZELSIS_PRICING_PLANS, PricingPlanItem, priceLabel } from '@/data/pricing-plans';
// EmptyState fallback: static pricing plan definitions never yield empty list
import { generateLicenseKey, activateUserTier, verifyLicenseKey } from '@/lib/stripe-checkout';
import { ShieldCheck, CreditCard, Lock, CheckCircle2, ArrowLeft, Star, Building2, Mail, User } from 'lucide-react';
import { Copy, Terminal, ShieldAlert, AlertCircle, ExternalLink, Calendar, Loader2, RefreshCw, ArrowRight } from 'lucide-react';
import { formatRenewalDate } from '@/lib/subscription-utils';
import { getAttributionData } from '@/lib/attribution';
import { getSupabase } from '@/lib/supabase';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';

function resolvePlanAlias(planId?: string): string {
  if (!planId) return 'zelsis-core';
  const clean = planId.toLowerCase().trim();
  if (clean === 'enterprise' || clean === 'vibecare' || clean === 'zelsis-suite' || clean === 'suite') {
    return 'vibecare';
  }
  return 'zelsis-core';
}

interface CheckoutViewProps {
  initialPlanId?: string;
  initialSuccess?: boolean;
  checkoutId?: string | null;
  reason?: string | null;
  onBackToPricing?: () => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
  onUpgradeSuccess?: (tier: 'Pro' | 'Enterprise') => void;
}

export const CheckoutView: React.FC<CheckoutViewProps> = ({
  initialPlanId = 'zelsis-core',
  initialSuccess = false,
  checkoutId = null,
  reason = null,
  onBackToPricing,
  user,
  onOpenAuth,
  onUpgradeSuccess,
}) => {
  const router = useRouter();
  const [selectedPlanId, setSelectedPlanId] = useState<string>(() => resolvePlanAlias(initialPlanId));
  const [isVerifying, setIsVerifying] = useState<boolean>(Boolean(checkoutId));
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verificationRetryCount, setVerificationRetryCount] = useState<number>(0);

  // User Authentication State
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(user ?? null);
  const [isInternalAuthModalOpen, setIsInternalAuthModalOpen] = useState(false);
  const [internalAuthMode, setInternalAuthMode] = useState<'signin' | 'signup'>('signin');

  // Form Fields
  const [fullName, setFullName] = useState(user?.name || '');
  const [companyName, setCompanyName] = useState('');
  const [vatNumber, setVatNumber] = useState('');
  const [email, setEmail] = useState(user?.email || '');
  const [isSubmitted, setIsSubmitted] = useState(initialSuccess);
  const [activeLicenseKey, setActiveLicenseKey] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const cleanupAuthQueryParam = () => {
    if (typeof window !== 'undefined') {
      try {
        const cleanUrl = new URL(window.location.href);
        if (cleanUrl.searchParams.has('auth')) {
          cleanUrl.searchParams.delete('auth');
          const newUrl = cleanUrl.pathname + (cleanUrl.search ? cleanUrl.search : '') + cleanUrl.hash;
          window.history.replaceState({}, '', newUrl);
        }
      } catch {
        // Ignore URL parsing errors
      }
    }
  };

  // Sync user state reactively from props
  useEffect(() => {
    if (user !== undefined) {
      setCurrentUser(user);
    }
  }, [user]);

  // Initial fallback to storage when rendered standalone without user prop
  useEffect(() => {
    if (user === undefined) {
      try {
        let saved = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!saved && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            saved = decodeURIComponent(match[3]);
          }
        }
        if (saved) {
          const parsed = JSON.parse(saved);
          if (parsed && parsed.isLoggedIn) {
            setCurrentUser(parsed);
          }
        }
      } catch (err) {
        console.warn('[CheckoutView] Failed to read user from storage:', err);
      }
    }
  }, []);

  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'zelsis_user' || e.key === 'shipguard_user') {
        try {
          if (e.newValue) {
            const parsed = JSON.parse(e.newValue);
            if (parsed && parsed.isLoggedIn) {
              setCurrentUser(parsed);
            } else {
              setCurrentUser(null);
            }
          } else {
            setCurrentUser(null);
          }
        } catch {
          setCurrentUser(null);
        }
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  useEffect(() => {
    if (currentUser) {
      if (currentUser.name && !fullName) setFullName(currentUser.name);
      if (currentUser.email && !email) setEmail(currentUser.email);
    }
  }, [currentUser]);

  const isAuthenticated = Boolean(currentUser && currentUser.isLoggedIn);

  const handleOpenAuthModal = (mode: 'signin' | 'signup' = 'signin') => {
    if (onOpenAuth) {
      onOpenAuth(mode);
    } else {
      setInternalAuthMode(mode);
      setIsInternalAuthModalOpen(true);
    }
  };

  useEffect(() => {
    if (initialPlanId) {
      setSelectedPlanId(resolvePlanAlias(initialPlanId));
    }
  }, [initialPlanId]);

  // Server-side verification for returning Polar checkouts
  useEffect(() => {
    if (checkoutId) {
      let isMounted = true;
      setIsVerifying(true);
      setVerificationError(null);

      const verifyCheckoutAsync = async () => {
        try {
          const supabase = getSupabase();
          const sessionRes = await supabase?.auth.getSession();
          const token = sessionRes?.data?.session?.access_token;
          const headers: Record<string, string> = { 'Content-Type': 'application/json' };
          if (token) headers['Authorization'] = `Bearer ${token}`;

          const res = await fetch('/api/v1/verify-checkout', {
            method: 'POST',
            headers,
            body: JSON.stringify({
              checkoutId,
              email: currentUser?.email || email || undefined,
              planId: selectedPlanId,
            }),
          });
          const data = await res.json();
          if (!isMounted) return;
          if (data.verified) {
            const verifiedTier: 'Pro' | 'Enterprise' = data.tier === 'Enterprise' ? 'Enterprise' : 'Pro';
            const userEmail = data.email || currentUser?.email || email || 'customer@zelsis.dev';
            const key = generateLicenseKey(selectedPlanId, userEmail);
            setActiveLicenseKey(key);
            activateUserTier(verifiedTier, key, {
              name: fullName || currentUser?.name,
              email: userEmail,
            });
            if (onUpgradeSuccess) {
              onUpgradeSuccess(verifiedTier);
            }
            setIsSubmitted(true);
          } else {
            setVerificationError(data.message || data.error || 'Polar checkout verification is pending or unconfirmed.');
          }
        } catch (err) {
          if (!isMounted) return;
          console.warn('[CheckoutView] Verification request failed:', err);
          setVerificationError('Unable to connect to checkout verification service.');
        } finally {
          if (isMounted) setIsVerifying(false);
        }
      };

      verifyCheckoutAsync();

      return () => {
        isMounted = false;
      };
    }
  }, [checkoutId, selectedPlanId, currentUser?.email, email, verificationRetryCount]);

  const selectedPlan: PricingPlanItem =
    ZELSIS_PRICING_PLANS.find((p) => p.id === selectedPlanId) ||
    ZELSIS_PRICING_PLANS[0];

  // Polar bills monthly only, so the order summary is always one month.
  const pricePerMonth = selectedPlan.priceMonthly;
  const subtotal = pricePerMonth;
  const total = subtotal;

  const isProSubscriber = currentUser?.tier === 'Pro';
  const isEnterpriseSubscriber = currentUser?.tier === 'Enterprise';
  const isSelectedPlanPro = selectedPlan.id === 'zelsis-core';
  const isSelectedPlanEnterprise = selectedPlan.id === 'vibecare';

  const isAlreadySubscribedToSelectedPlan =
    (isProSubscriber && isSelectedPlanPro) ||
    (isEnterpriseSubscriber && (isSelectedPlanPro || isSelectedPlanEnterprise));

  const formatDate = (isoString?: string) => {
    if (!isoString) return 'Active (Renews Monthly)';
    return formatRenewalDate(isoString);
  };

  // Supabase user id, sent as checkout metadata so the Polar webhook upgrades this account
  // even if the buyer types a different email on the Polar page.
  const [accountId, setAccountId] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    getSupabase()?.auth.getSession()
      .then(({ data }) => { if (active) setAccountId(data.session?.user?.id ?? null); })
      .catch(() => {});
    return () => { active = false; };
  }, [currentUser?.email]);

  const getPolarCheckoutUrl = () => {
    const base =
      selectedPlan.polarCheckoutUrl ||
      (selectedPlan.id === 'vibecare'
        ? 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od'
        : 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC');
    try {
      const url = new URL(base);
      const targetEmail = (currentUser?.email || email || '').trim();
      if (targetEmail) {
        url.searchParams.set('customer_email', targetEmail);
      }
      if (accountId) {
        url.searchParams.set('metadata[userId]', accountId);
      }
      const targetName = (currentUser?.name || fullName || '').trim();
      if (targetName) {
        url.searchParams.set('customer_name', targetName);
      }
      const attr = getAttributionData();
      if (attr?.utm_source) url.searchParams.set('utm_source', attr.utm_source);
      if (attr?.utm_medium) url.searchParams.set('utm_medium', attr.utm_medium);
      if (attr?.utm_campaign) url.searchParams.set('utm_campaign', attr.utm_campaign);
      if (attr?.gclid) url.searchParams.set('metadata[gclid]', attr.gclid);
      if (attr?.fbclid) url.searchParams.set('metadata[fbclid]', attr.fbclid);
      return url.toString();
    } catch {
      return base;
    }
  };

  const handleProceedToPolar = (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (isSubmitting) {
      e.preventDefault();
      return;
    }
    setIsSubmitting(true);
    setTimeout(() => {
      setIsSubmitting(false);
    }, 4000);
  };

  const handleSimulateSandbox = (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    if (!isAuthenticated) {
      handleOpenAuthModal('signup');
      return;
    }
    setIsSubmitting(true);
    try {
      const trimmedEmail = (email || currentUser?.email || 'developer@company.com').trim();
      const trimmedName = (fullName || currentUser?.name || 'Developer').trim();
      const tier = selectedPlanId === 'vibecare' ? 'Enterprise' : 'Pro';
      const key = generateLicenseKey(selectedPlanId, trimmedEmail);
      setActiveLicenseKey(key);
      activateUserTier(tier, key, {
        name: trimmedName,
        email: trimmedEmail,
      });
      if (onUpgradeSuccess) {
        onUpgradeSuccess(tier);
      }
      setIsSubmitted(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col gap-8 max-w-6xl mx-auto py-6 px-4">
      {/* Header Bar */}
      <div className="flex items-center justify-between border-b border-white/10 pb-4">
        <button
          onClick={onBackToPricing}
          className="flex items-center gap-2 text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
        >
          <ArrowLeft size={16} />
          <span>Back to Subscription Tiers</span>
        </button>

        <div className="flex items-center gap-2 text-xs text-[#10B981] font-extrabold bg-[#10B981]/10 px-3 py-1 rounded-full border border-[#10B981]/30">
          <ShieldCheck size={14} />
          <span>256-Bit SSL Encrypted B2B Checkout</span>
        </div>
      </div>

      {/* Quota Exceeded Context Banner */}
      {reason === 'quota_exceeded' && (
        <div className="p-5 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-lg animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 text-amber-300 flex items-center justify-center shrink-0">
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="text-xs font-mono font-bold text-amber-300 uppercase tracking-wider">
                Monthly Free Scan Limit Reached (3/3)
              </div>
              <p className="text-xs text-[#EDEDED] mt-0.5 leading-relaxed">
                You have reached your 3 free scans for this month. Upgrade to Zelsis Pro to audit unlimited repositories, or return to your dashboard to reset demo quota.
              </p>
            </div>
          </div>
          <button
            onClick={() => router.push('/dashboard')}
            className="btn btn-secondary px-4 py-2 text-xs font-mono font-bold rounded-lg border border-white/20 hover:bg-white/10 text-white shrink-0 transition-colors cursor-pointer"
          >
            Back to Dashboard
          </button>
        </div>
      )}

      {/* Checkout Verification Status Banner */}
      {isVerifying && (
        <div className="p-5 rounded-xl bg-white/5 border border-white/20 flex items-center justify-center gap-3 shadow-lg">
          <Loader2 size={18} className="animate-spin text-white" />
          <span className="text-xs font-mono font-bold text-white">
            Verifying Polar 3D secure payment clearance...
          </span>
        </div>
      )}

      {verificationError && !isSubmitted && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-md">
          <div className="flex items-center gap-2.5">
            <AlertCircle size={16} className="text-red-400 shrink-0" />
            <span className="leading-relaxed">{verificationError}</span>
          </div>
          {checkoutId && (
            <button
              type="button"
              onClick={() => setVerificationRetryCount((c) => c + 1)}
              className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-white font-mono text-[11px] font-bold shrink-0 transition-colors cursor-pointer"
            >
              Retry Verification
            </button>
          )}
        </div>
      )}

      {/* Account Required Warning Card for Unauthenticated / Guest Users */}
      {!isAuthenticated && !isSubmitted && (
        <div className="p-6 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-5 shadow-lg">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 text-amber-300 flex items-center justify-center shrink-0">
              <ShieldCheck size={24} className="text-amber-300" />
            </div>
            <div className="flex flex-col gap-1">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Account Required
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed max-w-2xl">
                Please sign in or create a free account before upgrading your plan. Your license and security gates will be permanently bound to your account.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => handleOpenAuthModal('signup')}
            className="min-h-[44px] px-5 py-2.5 rounded-xl bg-white text-black font-extrabold text-xs hover:bg-neutral-200 transition-all shadow-md flex items-center justify-center gap-2 shrink-0 cursor-pointer font-mono"
          >
            <User size={15} />
            <span>Open Sign In / Sign Up</span>
          </button>
        </div>
      )}

      {isSubmitted ? (
        <div className="bg-[#141414] border border-white/10 rounded-xl p-12 text-center flex flex-col items-center gap-5 border-[#10B981]/40 bg-[#10B981]/10">
          <CheckCircle2 size={64} className="text-[#10B981]" />
          <h2 className="text-3xl font-extrabold text-white">
            Subscription Order Activated!
          </h2>
          <p className="text-sm text-[#CBD5E1] max-w-lg leading-relaxed">
            Your <strong className="text-white">{selectedPlan.name}</strong> subscription has been successfully provisioned. A VAT invoice and license key have been emailed to <span className="text-white font-mono">{email}</span>.
          </p>

          <div className="p-4 rounded-xl bg-[#0A0E1A] border border-white/10 font-mono text-xs text-[#6EE7B7] max-w-md w-full text-left flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-white">PROVISIONED LICENSE KEY:</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(activeLicenseKey);
                  setCopiedKey(true);
                  setTimeout(() => setCopiedKey(false), 2000);
                }}
                className="btn btn-secondary text-[0.68rem] px-2 py-0.5 flex items-center gap-1"
              >
                {copiedKey ? <CheckCircle2 size={12} className="text-white" /> : <Copy size={12} />}
                <span>{copiedKey ? 'Copied!' : 'Copy Key'}</span>
              </button>
            </div>
            <div className="bg-[#0A0A0A] p-2 rounded border border-white/10 select-all break-all text-white">
              {activeLicenseKey || 'SG-PROD-2026-X94821'}
            </div>
            <div className="text-[0.7rem] text-[#A1A1AA]">
              STATUS: ACTIVE (Full Security Checks &amp; VibePolish Rules Enabled)
            </div>
          </div>

          <button
            onClick={() => {
              router.push('/dashboard');
            }}
            className="btn btn-primary px-8 py-3 uppercase text-xs font-bold tracking-wider mt-4 flex items-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
          >
            <span>Proceed to Security Gate Dashboard</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left Column: B2B Invoice & Payment Form */}
          <div className="lg:col-span-7 flex flex-col gap-6">
            <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6">
              <div>
                <h2 className="text-lg font-extrabold text-[#F8FAFC]">
                  1. Company &amp; Invoice Details
                </h2>
                <p className="text-xs text-[#A1A1AA] mt-0.5">
                  Provide your organization details for official VAT tax invoice generation
                </p>
              </div>

              <div className="flex flex-col gap-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="full-name-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Full Name / Contact Person
                    </label>
                    <div className="relative">
                      <input
                        id="full-name-input"
                        name="fullName"
                        type="text"
                        placeholder="Alex Morgan"
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        required
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 focus:border-white/20 pl-9"
                      />
                      <User size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="email-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Business Email Address
                    </label>
                    <div className="relative">
                      <input
                        id="email-input"
                        name="email"
                        type="email"
                        placeholder="user@company.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 focus:border-white/20 pl-9"
                      />
                      <Mail size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="company-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Company / Agency Name
                    </label>
                    <div className="relative">
                      <input
                        id="company-input"
                        name="companyName"
                        type="text"
                        placeholder="Your Company Name"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 focus:border-white/20 pl-9"
                      />
                      <Building2 size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="vat-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      VAT / Tax ID (Optional)
                    </label>
                    <input
                      id="vat-input"
                      name="vatNumber"
                      type="text"
                      placeholder="US987654321 or EU123456"
                      value={vatNumber}
                      onChange={(e) => setVatNumber(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 focus:border-white/20"
                    />
                  </div>
                </div>

                <div className="pt-4 border-t border-white/10 mt-2">
                  <h2 className="text-lg font-extrabold text-[#EDEDED] mb-1">
                    2. Payment Method
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mb-4">
                    All major credit cards accepted. Cancel anytime with 1 click.
                  </p>

                  {/* Polar Live Checkout Card */}
                  <div className="p-6 rounded-xl bg-gradient-to-b from-white/[0.08] to-white/[0.02] border border-white/20 flex flex-col gap-4 shadow-xl">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CreditCard size={18} className="text-white" />
                        <span className="text-base font-extrabold text-white">Live Polar 3D Secure Checkout</span>
                      </div>
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white/10 text-white border border-white/20">
                        Merchant of Record
                      </span>
                    </div>

                    <p className="text-xs text-[#A1A1AA] leading-relaxed">
                      Instant 3D Secure checkout managed by Polar Software, Inc. Official VAT tax invoice and subscription activated immediately.
                    </p>

                    {isAlreadySubscribedToSelectedPlan ? (
                      <div className="p-4 rounded-xl bg-white/5 border border-white/15 flex flex-col gap-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <CheckCircle2 size={18} className="text-emerald-400" />
                            <span className="text-sm font-extrabold text-white">Active Plan: {selectedPlan.name}</span>
                          </div>
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                            CURRENT TIER
                          </span>
                        </div>
                        <p className="text-xs text-[#CBD5E1] leading-relaxed">
                          Your account currently has active clearance for <strong>{selectedPlan.name}</strong>. {currentUser?.expiresAt ? `Valid / renews on: ${formatDate(currentUser.expiresAt)}.` : 'Active monthly subscription.'} You do not need to re-purchase this plan.
                        </p>
                        <div className="flex flex-col sm:flex-row items-center gap-2.5 pt-2">
                          <a
                            href="https://polar.sh/purchases"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="w-full sm:w-auto min-h-[40px] px-4 py-2 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                          >
                            <ExternalLink size={14} />
                            <span>Manage at Polar</span>
                          </a>
                          {isProSubscriber && isSelectedPlanPro && (
                            <button
                              type="button"
                              onClick={() => setSelectedPlanId('vibecare')}
                              className="w-full sm:w-auto min-h-[40px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 text-black font-extrabold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                            >
                              <ArrowRight size={14} className="text-black" />
                              <span>Upgrade to Enterprise ({priceLabel('Enterprise')})</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ) : isAuthenticated ? (
                      <a
                        href={getPolarCheckoutUrl()}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={handleProceedToPolar}
                        aria-busy={isSubmitting}
                        className={`btn btn-primary min-h-[44px] py-4 px-4 text-xs font-extrabold uppercase tracking-wider w-full rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-xl font-mono text-center ${
                          isSubmitting ? 'opacity-60 cursor-not-allowed pointer-events-none' : 'cursor-pointer'
                        }`}
                      >
                        {isSubmitting ? (
                          <>
                            <Loader2 size={16} className="animate-spin text-black" />
                            <span>Connecting to Secure Polar Gateway...</span>
                          </>
                        ) : (
                          <>
                            <Lock size={14} />
                            <span>{isProSubscriber && isSelectedPlanEnterprise ? 'Upgrade to Enterprise' : 'Pay Securely with Polar'} (${selectedPlan.priceMonthly.toFixed(2)}/mo)</span>
                          </>
                        )}
                      </a>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <button
                          type="button"
                          onClick={() => handleOpenAuthModal('signup')}
                          className="min-h-[44px] py-4 px-4 text-xs font-extrabold uppercase tracking-wider w-full rounded-xl flex items-center justify-center gap-2 bg-white/10 text-[#A1A1AA] hover:bg-white/15 hover:text-white transition-all border border-white/10 font-mono text-center cursor-pointer"
                        >
                          <Lock size={14} />
                          <span>Sign In to Upgrade (${selectedPlan.priceMonthly.toFixed(2)}/mo)</span>
                        </button>
                        <span className="text-[11px] text-amber-300/80 font-mono text-center">
                          Guest accounts cannot process payments. Please sign in first.
                        </span>
                      </div>
                    )}

                    <div className="flex items-center justify-center gap-2.5 text-[11px] text-[#A1A1AA] pt-2 border-t border-white/10 font-mono">
                      <span>Apple Pay</span>
                      <span className="text-white/20">·</span>
                      <span>Google Pay</span>
                      <span className="text-white/20">·</span>
                      <span>Visa &amp; Mastercard</span>
                      <span className="text-white/20">·</span>
                      <span>VAT Invoices</span>
                    </div>

                    {/* High-Converting Guarantee & Security Box */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 flex flex-col gap-2 mt-2">
                      <div className="flex items-center gap-2 text-xs font-mono text-zinc-300">
                        <ShieldCheck size={14} className="text-emerald-400 shrink-0" />
                        <span className="font-bold text-white">14-Day Money-Back Guarantee</span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] font-mono text-zinc-400">
                        <Lock size={12} className="text-zinc-400 shrink-0" />
                        <span>256-Bit SSL Encrypted Checkout via Polar / Stripe</span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] font-mono text-zinc-400">
                        <RefreshCw size={12} className="text-zinc-400 shrink-0" />
                        <span>Plan activates on your account after payment / Cancel anytime</span>
                      </div>
                      <div className="pt-1 border-t border-white/5 text-[10px] font-mono text-zinc-400 flex items-center justify-between">
                        <span>Read our <a href="/refund" target="_blank" rel="noopener noreferrer" className="text-zinc-400 hover:text-white underline">Refund Policy</a></span>
                        <span>VAT Invoices Provided</span>
                      </div>
                    </div>
                  </div>

                  {/* Sandbox / Demo Simulator Section (strictly disabled in production) */}
                  {process.env.NODE_ENV !== 'production' && (
                    <div className="mt-6 p-5 rounded-xl bg-[#0A0A0A] border border-dashed border-white/20 flex flex-col gap-3">
                      <div className="flex items-center gap-2">
                        <Terminal size={16} className="text-white" />
                        <span className="text-xs font-mono font-bold uppercase text-white">
                          Developer Demo &amp; Sandbox Simulator
                        </span>
                      </div>
                      <p className="text-xs text-[#A1A1AA] leading-relaxed">
                        Evaluating Zelsis for your agency or team? Simulate an instant subscription upgrade and generate a valid local license key without payment.
                      </p>
                      <button
                        type="button"
                        onClick={handleSimulateSandbox}
                        disabled={isSubmitting || !isAuthenticated || isAlreadySubscribedToSelectedPlan}
                        aria-busy={isSubmitting}
                        className={`min-h-[44px] py-3 text-xs font-bold uppercase tracking-wider w-full rounded-lg flex items-center justify-center gap-2 border transition-all font-mono ${
                          isSubmitting || !isAuthenticated || isAlreadySubscribedToSelectedPlan
                            ? 'border-white/10 bg-white/5 text-[#71717A] cursor-not-allowed opacity-60'
                            : 'btn btn-secondary border-white/20 hover:bg-white/10 text-white cursor-pointer'
                        }`}
                      >
                        {isSubmitting ? (
                          <>
                            <Loader2 size={14} className="animate-spin text-white" />
                            <span>Provisioning License...</span>
                          </>
                        ) : (
                          <span>
                            {!isAuthenticated
                              ? 'Sign In Required for Instant Upgrade'
                              : isAlreadySubscribedToSelectedPlan
                              ? `Already Active: ${selectedPlan.name}`
                              : `Simulate Instant Upgrade (${selectedPlan.name})`}
                          </span>
                        )}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Sticky Order Summary */}
          <div className="lg:col-span-5 sticky top-24">
            <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-5 border border-white/10 bg-[#141414] shadow-xl">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <span className="text-xs font-extrabold text-[#A1A1AA] font-mono uppercase tracking-wider">
                  ORDER SUMMARY
                </span>
                <span className="badge badge-passed text-[0.65rem]">
                  BILLED MONTHLY
                </span>
              </div>

              {/* Plan Switcher Pills */}
              <div className="flex items-center gap-1 bg-[#0A0A0A] p-1 rounded-xl border border-white/10">
                {ZELSIS_PRICING_PLANS.map((plan) => (
                  <button
                    key={plan.id}
                    type="button"
                    onClick={() => setSelectedPlanId(plan.id)}
                    className={`flex-1 py-1.5 px-2 rounded-lg text-[0.68rem] font-bold transition-all truncate ${
                      selectedPlanId === plan.id
                        ? 'bg-white text-black font-bold shadow-sm'
                        : 'text-[#A1A1AA] hover:text-white'
                    }`}
                  >
                    {plan.name}
                  </button>
                ))}
              </div>

              {/* Selected Plan Details */}
              <div>
                <div className="flex items-center justify-between">
                  <h3 className="text-xl font-extrabold text-[#EDEDED]">
                    {selectedPlan.name}
                  </h3>
                  <div className="text-sm font-extrabold text-white font-mono">
                    ${pricePerMonth.toFixed(2)} <span className="text-xs text-[#A1A1AA]">/ mo</span>
                  </div>
                </div>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  {selectedPlan.description}
                </p>
              </div>

              {/* Calculation Breakdown */}
              <div className="space-y-2.5 text-xs text-[#A1A1AA] pt-3 border-t border-white/10">
                <div className="flex justify-between">
                  <span>Base Price (1 Month):</span>
                  <span className="font-mono text-white">${subtotal.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-[#A1A1AA]">
                  <span>Estimated Tax / VAT:</span>
                  <span className="font-mono text-[11px]">Calculated at Checkout</span>
                </div>
                <div className="flex justify-between pt-2 border-t border-white/10 text-sm font-extrabold text-white">
                  <span>Total Due Today:</span>
                  <span className="font-mono text-white font-bold">${total.toFixed(2)}</span>
                </div>
              </div>

              {/* Included Features List */}
              <div className="space-y-2 pt-3 border-t border-white/10">
                <div className="text-[0.7rem] font-extrabold text-[#A1A1AA] uppercase font-mono">
                  INCLUDED IN THIS PLAN:
                </div>
                {selectedPlan.features.map((feat, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-[#EDEDED]">
                    <span className="text-white/40">&middot;</span>
                    <span>{feat}</span>
                  </div>
                ))}
                {selectedPlan.comingSoon?.map((feat) => (
                  <div key={feat} className="flex items-center gap-2 text-xs text-[#A1A1AA]">
                    <span className="text-white/40">&middot;</span>
                    <span>{feat}</span>
                    <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[0.6rem] font-mono uppercase tracking-wider shrink-0">Coming soon</span>
                  </div>
                ))}
              </div>

              {/* Trust Indicators */}
              <div className="p-3 rounded-lg bg-[#0A0A0A] border border-white/10 text-[0.72rem] text-[#A1A1AA] flex items-center gap-2">
                <Star size={14} className="text-[#F59E0B] shrink-0" />
                <span>14-Day 100% Money-Back Guarantee. No questions asked.</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Auth Modal for Unauthenticated Checkout Guests */}
      <AuthModal
        isOpen={isInternalAuthModalOpen && !currentUser?.isLoggedIn}
        onClose={() => {
          setIsInternalAuthModalOpen(false);
          cleanupAuthQueryParam();
        }}
        onLoginSuccess={(authedUser) => {
          let resolvedTier = authedUser.tier || 'Free';
          let resolvedExpiresAt = authedUser.expiresAt;
          const savedLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          if (savedLic) {
            const licResult = verifyLicenseKey(savedLic, authedUser.email);
            if (licResult.valid && (licResult.tier === 'Pro' || licResult.tier === 'Enterprise')) {
              resolvedTier = licResult.tier;
              resolvedExpiresAt = licResult.expiresAt;
            }
          }
          if (resolvedTier !== 'Free' && !resolvedExpiresAt) {
            resolvedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          }
          const finalUser: UserProfile = {
            ...authedUser,
            tier: resolvedTier,
            expiresAt: resolvedExpiresAt,
            status: resolvedTier !== 'Free' ? 'active' : (authedUser.status || 'active'),
            lastVerifiedAt: Date.now(),
          };
          setCurrentUser(finalUser);
          setIsInternalAuthModalOpen(false);
          cleanupAuthQueryParam();
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(finalUser));
            localStorage.removeItem('shipguard_user');
          } catch (err) {
            console.warn('[CheckoutView] Failed to persist user session:', err);
          }
        }}
        initialMode={internalAuthMode}
      />
    </div>
  );
};
