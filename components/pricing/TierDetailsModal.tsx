'use client';

import React from 'react';
import { X, Check, Lock, Shield, ArrowRight, Zap, ExternalLink } from 'lucide-react';
import { UserTier } from '@/data/schema';
import { formatCount, RULE_COUNTS } from '@/lib/rule-status';
import { ENTERPRISE_SEAT_LIMIT, PLAN_PRICES, SUPPORT_TERMS } from '@/data/pricing-plans';

interface TierDetailsModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentTier?: UserTier;
  onSelectPlan: (plan: 'Pro' | 'Enterprise') => void;
}

export const TierDetailsModal: React.FC<TierDetailsModalProps> = ({
  isOpen,
  onClose,
  currentTier = 'Free',
  onSelectPlan
}) => {
  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const features = [
    {
      category: 'Scan Volume & Code Access',
      items: [
        { label: 'Monthly Live Audits', free: '3 Scans / mo', pro: 'Unlimited', enterprise: 'Unlimited' },
        { label: 'Private Repositories', free: 'Public repos only', pro: 'Included (GitHub token)', enterprise: 'Included (GitHub token)' },
        { label: 'Connected Projects', free: '1 Active Repo', pro: 'Unlimited Repos', enterprise: 'Unlimited Repos' }
      ]
    },
    {
      category: 'Rule Engine & Analysis Depth',
      items: [
        { label: 'Security & Bug Inventory', free: `All ${formatCount(RULE_COUNTS.gating)} active rules`, pro: `All ${formatCount(RULE_COUNTS.gating)} active rules`, enterprise: `All ${formatCount(RULE_COUNTS.gating)} active rules` },
        { label: 'Secret Detection & RLS', free: 'Same rules on every plan', pro: 'Same rules on every plan', enterprise: 'Same rules on every plan' },
        { label: 'Large Repositories', free: 'Same engine on every plan', pro: 'Same engine on every plan', enterprise: 'Same engine on every plan' }
      ]
    },
    {
      category: 'AI Remediation & Patching',
      items: [
        { label: '1-Click AI Fix Prompts', free: '1 Trial Prompt', pro: 'Unlimited 1-Click Fix Prompts', enterprise: 'Unlimited 1-Click Fix Prompts' },
        { label: 'Unified Git Diff Patches', free: 'Locked', pro: 'Instant Unified Diffs', enterprise: 'Instant Unified Diffs' }
      ]
    },
    {
      category: 'Executive Reports & Compliance',
      items: [
        { label: 'PDF Readiness Report', free: 'Locked', pro: 'Included (Instant Download)', enterprise: 'Included (Instant Download)' },
        { label: 'Jira Markdown & HTML Export', free: 'Locked', pro: 'Included', enterprise: 'Included' },
        { label: 'White-label SOC 2 Report', free: 'Not Included', pro: 'Not Included', enterprise: 'Included' }
      ]
    },
    {
      category: 'Support & Operations',
      items: [
        { label: 'Support', free: SUPPORT_TERMS.Free, pro: SUPPORT_TERMS.Pro, enterprise: SUPPORT_TERMS.Enterprise },
        { label: 'Team Workspace & Roles', free: 'Not Included', pro: 'Not Included', enterprise: `${ENTERPRISE_SEAT_LIMIT} seats, members get Pro` },
        { label: 'Organization Gate Policy', free: 'Not Included', pro: 'Not Included', enterprise: 'Included' },
        { label: 'GitHub Actions / CI/CD Gate', free: 'Locked', pro: 'Gate API + generated CI workflows', enterprise: 'Gate API + generated CI workflows' }
      ]
    }
  ];

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto animate-in fade-in duration-150"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-[#121216] border border-white/15 rounded-2xl w-full max-w-4xl p-5 sm:p-8 flex flex-col gap-6 shadow-2xl relative my-auto max-h-[90vh] overflow-y-auto font-mono text-[#EDEDED]">
        {/* Modal Header */}
        <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield size={18} className="text-white" />
              <h2 className="text-lg sm:text-xl font-extrabold text-white">
                Tier Comparison &amp; Feature Matrix
              </h2>
            </div>
            <p className="text-xs text-zinc-400">
              Clear breakdown of quotas, operational paywalls, and feature availability across Free, Pro, and Enterprise tiers.
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-lg text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Pricing Cards Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Free Tier */}
          <div className="p-4 rounded-xl border border-white/10 bg-[#0E0E12] flex flex-col justify-between gap-3">
            <div>
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Free Starter</span>
              <div className="text-2xl font-extrabold text-white mt-1 tabular-nums">$0</div>
              <p className="text-[11px] text-zinc-400 mt-1">For testing public repositories and open source projects.</p>
            </div>
            <div className="text-[11px] text-zinc-400 font-bold border-t border-white/5 pt-2">
              {currentTier === 'Free' ? 'Current Plan' : 'Free Baseline'}
            </div>
          </div>

            {/* Pro Tier */}
            <div className={`p-4 rounded-xl flex flex-col justify-between gap-3 relative shadow-lg ${
              currentTier === 'Pro' ? 'border-2 border-white/40 bg-white/[0.04]' : 'border border-white/10 bg-white/[0.02]'
            }`}>
              <div className="absolute -top-2.5 right-4 flex items-center gap-1">
                {currentTier === 'Pro' ? (
                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-white text-black uppercase tracking-wider flex items-center gap-1 shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-black" />
                    Active Plan
                  </span>
                ) : currentTier === 'Free' ? (
                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-white/20 text-white border border-white/30 uppercase tracking-wider">
                    Recommended
                  </span>
                ) : null}
              </div>
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-white">Pro Developer</span>
                <div className="text-2xl font-extrabold text-white mt-1 tabular-nums">${PLAN_PRICES.Pro} <span className="text-xs text-zinc-400 font-normal">/ month</span></div>
                <p className="text-[11px] text-zinc-300 mt-1">Unlimited scans, private repos, 1-click AI fixes &amp; PDF reports.</p>
              </div>
              {currentTier === 'Pro' ? (
                <a
                  href="https://polar.sh/purchases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full py-2 px-3 rounded-lg bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer text-center"
                >
                  <span>Manage at Polar</span>
                  <ExternalLink size={13} />
                </a>
              ) : currentTier === 'Enterprise' ? (
                <div className="w-full py-2 px-3 rounded-lg bg-white/5 border border-white/10 text-zinc-400 font-medium text-xs text-center">
                  Included in Enterprise
                </div>
              ) : (
                <button
                  onClick={() => { onClose(); onSelectPlan('Pro'); }}
                  className="w-full py-2 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                >
                  <span>Upgrade to Pro (${PLAN_PRICES.Pro})</span>
                  <ArrowRight size={13} />
                </button>
              )}
            </div>

            {/* Enterprise Tier */}
            <div className={`p-4 rounded-xl flex flex-col justify-between gap-3 relative shadow-lg ${
              currentTier === 'Enterprise' ? 'border-2 border-white/40 bg-white/[0.04]' : 'border border-white/10 bg-white/[0.02]'
            }`}>
              {currentTier === 'Enterprise' && (
                <span className="absolute -top-2.5 right-4 px-2 py-0.5 rounded text-[11px] font-bold bg-white text-black uppercase tracking-wider flex items-center gap-1 shadow-sm">
                  <span className="w-1.5 h-1.5 rounded-full bg-black" />
                  Active Plan
                </span>
              )}
              <div>
                <span className="text-[10px] font-bold text-white uppercase tracking-wider">Enterprise Team</span>
                <div className="text-2xl font-extrabold text-white mt-1 tabular-nums">${PLAN_PRICES.Enterprise} <span className="text-xs text-zinc-400 font-normal">/ month</span></div>
                <p className="text-[11px] text-zinc-400 mt-1">Pro for the whole team: shared workspace, org gate policy &amp; SOC 2 reports.</p>
              </div>
              {currentTier === 'Enterprise' ? (
                <a
                  href="https://polar.sh/purchases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full py-2 px-3 rounded-lg bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer text-center"
                >
                  <span>Manage at Polar</span>
                  <ExternalLink size={13} />
                </a>
              ) : (
                <button
                  onClick={() => { onClose(); onSelectPlan('Enterprise'); }}
                  className="w-full py-2 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                >
                  <span>Upgrade to Enterprise (${PLAN_PRICES.Enterprise})</span>
                  <ArrowRight size={13} />
                </button>
              )}
            </div>
        </div>

        {/* Feature Comparison Matrix Table */}
        <div className="space-y-6 pt-2">
          {features.length === 0 ? (
            <div className="p-8 text-center bg-[#0A0A0A] rounded-xl border border-white/10 text-xs text-zinc-400 font-mono">
              No comparison data available.
            </div>
          ) : (
            features.map((cat, idx) => (
              <div key={idx} className="space-y-2">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider border-b border-white/10 pb-1 text-zinc-300">
                  {cat.category}
                </h3>
                <div className="divide-y divide-white/5 text-xs">
                  {cat.items.length === 0 ? (
                    <div className="py-2 text-zinc-400 text-[11px] font-mono">No items in this category.</div>
                  ) : (
                    cat.items.map((item, itemIdx) => (
                      <div key={itemIdx} className="grid grid-cols-1 md:grid-cols-4 py-2 gap-1 items-center">
                        <span className="text-zinc-300 font-medium md:col-span-1">{item.label}</span>
                        <span className="text-zinc-400 text-[11px] md:col-span-1 md:text-center">{item.free}</span>
                        <span className="text-zinc-200 font-bold text-[11px] md:col-span-1 md:text-center">{item.pro}</span>
                        <span className="text-white font-bold text-[11px] md:col-span-1 md:text-center">{item.enterprise}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
