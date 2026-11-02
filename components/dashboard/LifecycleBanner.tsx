'use client';

import React, { useState } from 'react';
import { X } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { getSubscriptionValidity } from '@/lib/subscription-utils';

interface LifecycleBannerProps {
  user?: UserProfile | null;
}

export const LifecycleBanner: React.FC<LifecycleBannerProps> = ({ user }) => {
  const [isDismissed, setIsDismissed] = useState(false);

  if (!user || !user.isLoggedIn || isDismissed) {
    return null;
  }

  // 1. Dunning / Grace Period Banner (Payment Failed)
  if (user.status === 'past_due') {
    let graceDateStr = 'in 3 days';
    if (user.gracePeriodUntil && typeof user.gracePeriodUntil === 'string') {
      try {
        const d = new Date(user.gracePeriodUntil.trim());
        if (!isNaN(d.getTime())) {
          graceDateStr = d.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            timeZone: 'UTC',
          });
        }
      } catch {
        graceDateStr = 'in 3 days';
      }
    }

    return (
      <div className="w-full bg-gradient-to-r from-amber-500/15 via-rose-500/10 to-amber-500/15 border border-amber-500/30 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-start gap-3">
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-300">
                Payment Action Required &bull; Grace Period Active
              </span>
            </div>
            <p className="text-xs text-[#EDEDED] leading-relaxed">
              Your latest subscription payment could not be processed. Your {user.tier} access is preserved under a 3-day grace period until <strong className="text-white font-mono">{graceDateStr}</strong>. Please update your payment card to avoid service disruption.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto justify-end">
          <a
            href="https://polar.sh/purchases"
            target="_blank"
            rel="noopener noreferrer"
            className="min-h-[36px] px-3.5 py-1.5 rounded-lg bg-amber-400 hover:bg-amber-300 text-black text-xs font-extrabold flex items-center gap-1.5 transition-all shadow cursor-pointer font-mono"
          >
            <span>Update Card at Polar</span>
          </a>
        </div>
      </div>
    );
  }

  // 2. Renewal Notice Banner (3 days or less before expiration)
  if (user.tier !== 'Free') {
    const validity = getSubscriptionValidity(user);

    if (validity.daysRemaining !== null && validity.daysRemaining <= 3 && validity.daysRemaining >= 0 && !validity.isExpired) {
      const timingText = validity.daysRemaining === 0 ? 'today' : validity.daysRemaining === 1 ? 'tomorrow' : `in ${validity.daysRemaining} days`;

      return (
        <div className="w-full bg-[#141414] border border-white/15 rounded-xl p-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-md">
          <div className="flex items-center gap-3">
            <div className="text-xs text-[#CBD5E1]">
              <span className="font-bold text-white">Subscription Renewal: </span>
              Your <span className="font-semibold text-white">{validity.tier} Plan</span> will renew automatically on{' '}
              <strong className="text-white font-mono">{validity.formattedRenewalDate}</strong> ({timingText}).
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
            <a
              href="https://polar.sh/purchases"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[11px] font-mono font-bold text-[#A1A1AA] hover:text-white flex items-center gap-1 transition-colors px-2 py-1 rounded hover:bg-white/5"
            >
              <span>Manage at Polar</span>
            </a>
            <button
              type="button"
              onClick={() => setIsDismissed(true)}
              className="p-1 rounded text-[#71717A] hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
              title="Dismiss Notice"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      );
    }
  }

  return null;
};
