'use client';

import React, { useState } from 'react';
import { Shield, ArrowUpRight, Lock, CheckCircle2, ExternalLink } from 'lucide-react';
import { UserTier, PlanUsageQuota } from '@/data/schema';
import { TierDetailsModal } from '@/components/pricing/TierDetailsModal';
import { priceLabel } from '@/data/pricing-plans';

interface UsageGaugeProps {
  tier: UserTier;
  quota: PlanUsageQuota;
  projectsCount: number;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const UsageGauge: React.FC<UsageGaugeProps> = ({
  tier = 'Free',
  quota,
  projectsCount,
  onOpenCheckout
}) => {
  const [isDetailsOpen, setIsDetailsOpen] = useState(false);

  const isFree = tier === 'Free';
  const isPro = tier === 'Pro';
  const isEnterprise = tier === 'Enterprise';

  const scansUsed = quota?.scansUsed || 0;
  const scansLimit = isFree ? 3 : Infinity;
  const scansRemaining = isFree ? Math.max(0, 3 - scansUsed) : Infinity;
  const scanPercentage = isFree ? Math.min(100, Math.round((scansUsed / 3) * 100)) : 100;

  const aiPromptsUsed = quota?.aiPromptsUsed || 0;
  const aiPromptsLimit = isFree ? 1 : Infinity;

  return (
    <>
      <div className="rounded-xl border border-white/10 bg-[#141418] p-4 flex flex-col gap-3.5 font-mono shadow-lg">
        {/* Tier Header Bar */}
        <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2.5">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-zinc-300" />
            <span className="text-xs font-extrabold uppercase tracking-wider text-white">
              {tier} Plan
            </span>
          </div>
          <span
            className={`px-2 py-0.5 rounded text-[11px] font-bold tracking-widest uppercase border ${
              isFree
                ? 'bg-white/5 text-zinc-400 border-white/10'
                : 'bg-white/10 text-white border-white/20'
            }`}
          >
            {isFree ? 'Starter' : isPro ? 'Verified Pro' : 'Dedicated'}
          </span>
        </div>

        {isFree ? (
          <div className="flex flex-col gap-3">
            {/* Scans Progress Box */}
            <div className="flex flex-col gap-1.5 bg-[#0A0A0E] p-2.5 rounded-lg border border-white/10">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-400 font-medium">Monthly Audits</span>
                <span className={`font-bold tabular-nums ${scansUsed >= 3 ? 'text-rose-400' : 'text-white'}`}>
                  {scansUsed} / 3 Used
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    scansUsed >= 3
                      ? 'bg-rose-500'
                      : scansUsed === 2
                      ? 'bg-amber-500'
                      : 'bg-white'
                  }`}
                  style={{ width: `${scanPercentage}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[10px] text-zinc-400 pt-0.5">
                <span>{scansRemaining} audits left this cycle</span>
                {scansUsed >= 3 && (
                  <span className="text-rose-400 font-bold">Quota Full</span>
                )}
              </div>
            </div>

            {/* Linear Clean Feature Quotas (Single Row Each, No Colliding Columns) */}
            <div className="flex flex-col gap-2 text-[11px] text-zinc-400">
              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>Connected Repos</span>
                <span className={`font-bold tabular-nums ${projectsCount > 1 ? 'text-amber-400' : 'text-white'}`}>
                  {projectsCount} / 1 Project
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>AI Fix Prompts</span>
                <span className="font-bold text-white tabular-nums">
                  {aiPromptsUsed} / {aiPromptsLimit} Trial
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span className="flex items-center gap-1.5">
                  <Lock size={11} className="text-zinc-400" />
                  <span>Private Repos</span>
                </span>
                <span className="text-[11px] text-amber-400/90 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                  Pro Feature
                </span>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="flex items-center gap-1.5">
                  <Lock size={11} className="text-zinc-400" />
                  <span>PDF Certificates</span>
                </span>
                <span className="text-[11px] text-amber-400/90 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                  Pro Feature
                </span>
              </div>
            </div>

            {/* Upgrade Action Button */}
            <button
              type="button"
              onClick={() => onOpenCheckout?.('Pro')}
              className="w-full py-2.5 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 transition-all font-extrabold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md mt-1"
            >
              <span>Upgrade to Pro ({priceLabel('Pro')})</span>
              <ArrowUpRight size={13} />
            </button>

            {/* Compare All Tiers link */}
            <button
              type="button"
              onClick={() => setIsDetailsOpen(true)}
              className="text-[10px] text-zinc-400 hover:text-white transition-colors text-center flex items-center justify-center gap-1 py-0.5 cursor-pointer"
            >
              <span>Compare All Plan Limits &amp; Features</span>
              <ExternalLink size={10} />
            </button>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2 text-xs text-white font-bold bg-white/5 p-2.5 rounded-lg border border-white/10">
              <CheckCircle2 size={14} className="shrink-0 text-zinc-400" />
              <span>Unlimited Production Clearance</span>
            </div>

            <div className="flex flex-col gap-2 text-[11px] text-zinc-400">
              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>Monthly Scans</span>
                <span className="font-bold text-white">Unlimited</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>Connected Repositories</span>
                <span className="font-bold text-white">Unlimited</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>Private Codebase Audits</span>
                <span className="font-bold text-white">Unlocked</span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span>PDF Release Certificate</span>
                <span className="font-bold text-white">Included</span>
              </div>
            </div>

            {isPro && (
              <button
                type="button"
                onClick={() => onOpenCheckout?.('Enterprise')}
                className="w-full mt-1 py-2 px-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] font-bold text-zinc-300 hover:text-white flex items-center justify-center gap-1 transition-colors cursor-pointer"
              >
                <span>Need priority support? View Enterprise ({priceLabel('Enterprise')})</span>
                <ArrowUpRight size={11} />
              </button>
            )}

            <button
              type="button"
              onClick={() => setIsDetailsOpen(true)}
              className="text-[10px] text-zinc-400 hover:text-white transition-colors text-center flex items-center justify-center gap-1 py-0.5 cursor-pointer"
            >
              <span>View Full Feature Matrix</span>
              <ExternalLink size={10} />
            </button>
          </div>
        )}
      </div>

      <TierDetailsModal
        isOpen={isDetailsOpen}
        onClose={() => setIsDetailsOpen(false)}
        currentTier={tier}
        onSelectPlan={(plan) => {
          setIsDetailsOpen(false);
          onOpenCheckout?.(plan);
        }}
      />
    </>
  );
};
