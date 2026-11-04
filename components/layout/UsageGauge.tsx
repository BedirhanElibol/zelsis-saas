'use client';

import React, { useState } from 'react';
import { UserTier, PlanUsageQuota } from '@/data/schema';
import { TierDetailsModal } from '@/components/pricing/TierDetailsModal';
import { priceLabel } from '@/data/pricing-plans';
import { TIER_CONFIGS } from '@/lib/quota-manager';

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

  // Limits come from the plan config the quota checks use, so this panel cannot disagree with them
  const plan = TIER_CONFIGS[tier] ?? TIER_CONFIGS.Free;
  const limitOf = (v: number | 'Unlimited') => (v === 'Unlimited' ? Infinity : v);
  const scansUsed = quota?.scansUsed || 0;
  const scansLimit = limitOf(plan.scanLimit);
  const scansRemaining = Math.max(0, scansLimit - scansUsed);
  const scanPercentage = Number.isFinite(scansLimit) ? Math.min(100, Math.round((scansUsed / scansLimit) * 100)) : 0;
  const scansFull = scansRemaining === 0;
  const projectLimit = limitOf(plan.projectLimit);

  const aiPromptsUsed = quota?.aiPromptsUsed || 0;
  const aiPromptsLimit = limitOf(plan.aiPromptLimit);
  const aiPromptsLeft = Math.max(0, aiPromptsLimit - aiPromptsUsed);

  return (
    <>
      <div className="rounded-xl border border-white/10 bg-[#141418] p-4 flex flex-col gap-3.5 font-mono shadow-lg">
        {/* Tier Header Bar */}
        <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2.5">
          <div className="flex items-center gap-2">
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
                <span className={`font-bold tabular-nums ${scansFull ? 'text-rose-400' : 'text-white'}`}>
                  {Number.isFinite(scansLimit) ? `${scansUsed} / ${scansLimit} used` : `${scansUsed} run, unlimited`}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    scansFull
                      ? 'bg-rose-500'
                      : scanPercentage >= 66
                      ? 'bg-amber-500'
                      : 'bg-white'
                  }`}
                  style={{ width: `${scanPercentage}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[10px] text-zinc-400 pt-0.5">
                <span>
                  {Number.isFinite(scansRemaining)
                    ? `${scansRemaining} ${scansRemaining === 1 ? 'audit' : 'audits'} left this cycle`
                    : 'No audit limit on this plan'}
                </span>
                {scansFull && (
                  <span className="text-rose-400 font-bold">Quota Full</span>
                )}
              </div>
            </div>

            {/* Linear Clean Feature Quotas (Single Row Each, No Colliding Columns) */}
            <div className="flex flex-col gap-2 text-[11px] text-zinc-400">
              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>Connected Repos</span>
                <span className={`font-bold tabular-nums ${projectsCount >= projectLimit ? 'text-amber-400' : 'text-white'}`}>
                  {projectsCount} / {projectLimit} {projectLimit === 1 ? 'project' : 'projects'}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span>AI Fix Prompts</span>
                <span className="font-bold text-white tabular-nums">
                  {aiPromptsLeft} of {aiPromptsLimit} left
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-white/5">
                <span className="flex items-center gap-1.5">
                  <span>Private Repos</span>
                </span>
                {plan.privateRepoAccess ? (
                  <span className="text-[11px] text-white font-bold">Included</span>
                ) : (
                  <span className="text-[11px] text-amber-400/90 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                    Pro Feature
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="flex items-center gap-1.5">
                  <span>PDF Certificates</span>
                </span>
                {plan.pdfExportAccess ? (
                  <span className="text-[11px] text-white font-bold">Included</span>
                ) : (
                  <span className="text-[11px] text-amber-400/90 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                    Pro Feature
                  </span>
                )}
              </div>
            </div>

            {/* Upgrade Action Button */}
            <button
              type="button"
              onClick={() => onOpenCheckout?.('Pro')}
              className="w-full py-2.5 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 transition-all font-extrabold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md mt-1"
            >
              <span>Upgrade to Pro ({priceLabel('Pro')})</span>
            </button>

            {/* Compare All Tiers link */}
            <button
              type="button"
              onClick={() => setIsDetailsOpen(true)}
              className="text-[10px] text-zinc-400 hover:text-white transition-colors text-center flex items-center justify-center gap-1 py-0.5 cursor-pointer"
            >
              <span>Compare All Plan Limits &amp; Features</span>
            </button>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2 text-xs text-white font-bold bg-white/5 p-2.5 rounded-lg border border-white/10">
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
              </button>
            )}

            <button
              type="button"
              onClick={() => setIsDetailsOpen(true)}
              className="text-[10px] text-zinc-400 hover:text-white transition-colors text-center flex items-center justify-center gap-1 py-0.5 cursor-pointer"
            >
              <span>View Full Feature Matrix</span>
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
