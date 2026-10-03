'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  CreditCard,
  CheckCircle2,
  ShieldCheck,
  AlertTriangle,
  Calendar,
  ExternalLink,
  Loader2,
  ArrowRight,
  Check
} from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { getSupabase } from '@/lib/supabase';
import { verifyLicenseKey } from '@/lib/stripe-checkout';
import { getSubscriptionValidity, formatRenewalDate } from '@/lib/subscription-utils';
import { UserProfileSettingsForm } from './UserProfileSettingsForm';
import { priceLabel } from '@/data/pricing-plans';

interface SubscriptionCardProps {
  user?: UserProfile | null;
  onUpdateUser?: (updatedUser: UserProfile) => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
}

export const SubscriptionCard: React.FC<SubscriptionCardProps> = ({
  user,
  onUpdateUser,
  onOpenCheckout,
  onOpenAuth,
}) => {
  const router = useRouter();
  const isAuthenticated = Boolean(user && user.isLoggedIn);
  const validity = getSubscriptionValidity(user);

  const [isSyncingSub, setIsSyncingSub] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<{ status: 'idle' | 'success' | 'error'; message: string }>({
    status: 'idle',
    message: '',
  });


  const handleSyncSubscription = async () => {
    if (!user?.email) return;
    setIsSyncingSub(true);
    setSyncFeedback({ status: 'idle', message: '' });
    try {
      const supabase = getSupabase();
      const sessionRes = await supabase?.auth.getSession();
      const token = sessionRes?.data?.session?.access_token;

      if (!token) {
        setSyncFeedback({
          status: 'error',
          message: 'Active session required to synchronize subscription status. Please sign in.',
        });
        setIsSyncingSub(false);
        return;
      }

      const res = await fetch('/api/v1/subscription/sync', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ email: user.email }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.active && (data.tier === 'Pro' || data.tier === 'Enterprise')) {
          const validExpiresAt = data.expiresAt || user.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          const updatedUser: UserProfile = {
            ...user,
            tier: data.tier,
            expiresAt: validExpiresAt,
            billingCycle: data.billingCycle || user.billingCycle,
            status: 'active',
          };
          if (onUpdateUser) {
            onUpdateUser(updatedUser);
          }
          localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
          const dateStr = formatRenewalDate(validExpiresAt);
          setSyncFeedback({
            status: 'success',
            message: `Active ${data.tier} subscription confirmed! Renews / valid until: ${dateStr}`,
          });
        } else {
          const currentLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          const hasValidLicense = Boolean(currentLic && verifyLicenseKey(currentLic, user.email).valid);
          const isLocallyActive = Boolean(
            user.tier !== 'Free' && (!user.expiresAt || new Date(user.expiresAt).getTime() > Date.now())
          );

          if (isLocallyActive || hasValidLicense) {
            const dateStr = formatRenewalDate(user.expiresAt);
            setSyncFeedback({
              status: 'success',
              message: `Active ${user.tier} plan preserved. Renews / valid until: ${dateStr}`,
            });
          } else {
            const updatedUser: UserProfile = {
              ...user,
              tier: 'Free',
              expiresAt: undefined,
              status: 'canceled',
            };
            if (onUpdateUser) {
              onUpdateUser(updatedUser);
            }
            localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
            setSyncFeedback({
              status: 'error',
              message: `Subscription period ended for ${user.email}. Account reverted to Free Tier.`,
            });
          }
        }
      } else {
        setSyncFeedback({
          status: 'error',
          message: 'Unable to reach subscription verification service.',
        });
      }
    } catch {
      setSyncFeedback({
        status: 'error',
        message: 'Network error checking subscription status.',
      });
    } finally {
      setIsSyncingSub(false);
      setTimeout(() => setSyncFeedback({ status: 'idle', message: '' }), 6000);
    }
  };


  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-white/20" />

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center">
            <CreditCard size={20} />
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-extrabold text-white">Membership &amp; Subscription Management</h2>
            <p className="text-xs text-[#A1A1AA] mt-0.5">Manage your active plan, included audit rules, and user profile preferences.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold border flex items-center gap-1.5 ${validity.badgeColors.bg} ${validity.badgeColors.border} ${validity.badgeColors.text}`}>
            {validity.isActive ? 'Active' : 'Expired'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Plan Overview & Included Features */}
        <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-5 flex flex-col justify-between gap-5">
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div>
                <span className="text-[10px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">Current Plan</span>
                <div className="text-base font-extrabold text-white flex items-center gap-2">
                  <span>{user?.tier === 'Pro' ? 'Pro Plan (Advanced Audit)' : user?.tier === 'Enterprise' ? 'Enterprise Plan' : 'Free Tier'}</span>
                  {user?.tier && user.tier !== 'Free' && (
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${validity.badgeColors.bg} ${validity.badgeColors.text} ${validity.badgeColors.border}`}>
                      {validity.isActive ? 'ACTIVE' : 'EXPIRED'}
                    </span>
                  )}
                </div>
              </div>
              <span className="text-xs font-mono font-bold text-[#EDEDED] bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg tabular-nums">
                {user?.tier === 'Pro' ? priceLabel('Pro') : user?.tier === 'Enterprise' ? priceLabel('Enterprise') : '$0 / Free Tier'}
              </span>
            </div>

            {/* Renewal Widget */}
            {user?.tier && user.tier !== 'Free' ? (
              <div className="p-4 rounded-xl bg-white/[0.03] border border-white/10 flex flex-col gap-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="text-lg font-mono font-extrabold text-white">{validity.countdownLabel}</span>
                  <a
                    href="https://polar.sh/purchases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-zinc-300 hover:text-white font-medium inline-flex items-center gap-1.5 transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded"
                  >
                    <span>Manage at Polar</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
                <div className="flex flex-col gap-1.5">
                  <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${validity.badgeColors.bar}`}
                      style={{ width: `${validity.cycleProgressPercent}%` }}
                      role="progressbar"
                      aria-valuenow={validity.cycleProgressPercent}
                      aria-valuemin={0}
                      aria-valuemax={100}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[#A1A1AA]">
                    <div className="flex items-center gap-1.5">
                      <Calendar size={13} className="text-[#A1A1AA] shrink-0" />
                      <span>{validity.isExpired ? `Expired on ${validity.formattedRenewalDate}` : `Renews on ${validity.formattedRenewalDate}`}</span>
                    </div>
                    <span className="font-mono text-[10px] tabular-nums">{validity.cycleProgressPercent}% Cycle Completed</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-xs text-[#A1A1AA]">
                <Calendar size={13} className="text-emerald-400 shrink-0" />
                <span>Free Tier &bull; Standard Access</span>
              </div>
            )}

            {/* Included Features */}
            <div className="flex flex-col gap-2.5">
              <span className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">Included Features:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-[#EDEDED]">
                <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                  <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                  <span className="font-medium">OWASP Security Pre-flight Checks</span>
                </div>
                <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                  <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                  <span className="font-medium">VibePolish UI &amp; Design System Rules</span>
                </div>
                <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                  <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                  <span className="font-medium">Unlimited Static Analysis</span>
                </div>
                <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                  <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                  <span className="font-medium">100% Local Privacy</span>
                </div>
              </div>
            </div>
          </div>

          {/* Upgrade Buttons */}
          <div className="pt-3 border-t border-white/10 flex items-center justify-between flex-wrap gap-3">
            <span className="text-xs text-[#A1A1AA]">Purchased on Polar or need to verify your active plan?</span>
            <div className="flex items-center gap-2">
              {isAuthenticated && (
                <button
                  type="button"
                  onClick={handleSyncSubscription}
                  disabled={isSyncingSub}
                  className="min-h-[44px] px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                >
                  {isSyncingSub ? (
                    <>
                      <Loader2 size={13} className="animate-spin text-emerald-400" />
                      <span>Checking...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={14} className="text-emerald-400" />
                      <span>Sync Subscription</span>
                    </>
                  )}
                </button>
              )}
              {user?.tier === 'Pro' ? (
                <>
                  <a
                    href="https://polar.sh/purchases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="min-h-[44px] px-3.5 py-2 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                  >
                    <ExternalLink size={13} />
                    <span>Manage at Polar</span>
                  </a>
                  <button
                    type="button"
                    onClick={() => {
                      if (onOpenCheckout) onOpenCheckout('Enterprise');
                      else router.push('/checkout?plan=enterprise');
                    }}
                    className="min-h-[44px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                  >
                    <ArrowRight size={14} />
                    <span>Upgrade to Enterprise ({priceLabel('Enterprise')})</span>
                  </button>
                </>
              ) : user?.tier === 'Enterprise' ? (
                <a
                  href="https://polar.sh/purchases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="min-h-[44px] px-3.5 py-2 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                >
                  <ExternalLink size={13} />
                  <span>Manage Subscription at Polar</span>
                </a>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    if (onOpenCheckout) onOpenCheckout('Pro');
                    else router.push('/checkout?plan=pro');
                  }}
                  className="min-h-[44px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                >
                  <ArrowRight size={14} />
                  <span>Upgrade to Pro ({priceLabel('Pro')})</span>
                </button>
              )}
            </div>
          </div>
          {syncFeedback.message && (
            <div className={`text-xs font-mono p-3 rounded-xl border ${syncFeedback.status === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'}`}>
              {syncFeedback.message}
            </div>
          )}
        </div>

        {/* Profile Details & Avatar Preview Form */}
        <UserProfileSettingsForm
          user={user}
          onUpdateUser={onUpdateUser}
          onOpenAuth={onOpenAuth}
        />
      </div>

    </div>
  );
};
