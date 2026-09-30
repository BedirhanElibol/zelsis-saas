'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Lock, ArrowRight, ShieldCheck, ExternalLink } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { UserTier } from '@/data/schema';

interface UpgradePaywallModalProps {
  isOpen: boolean;
  onClose: () => void;
  featureTitle?: string;
  featureDescription?: string;
  requiredTier?: 'Pro' | 'Enterprise';
  currentTier?: UserTier;
}

export const UpgradePaywallModal: React.FC<UpgradePaywallModalProps> = ({
  isOpen,
  onClose,
  featureTitle = 'Automated Claude PR & Webhook Integration',
  featureDescription = 'Upgrade your plan to unlock automated Claude AI code fixes, unlimited security scans, and CI/CD webhook triggers.',
  requiredTier = 'Pro',
  currentTier
}) => {
  const router = useRouter();
  const [activeTier, setActiveTier] = React.useState<UserTier>(currentTier || 'Free');

  React.useEffect(() => {
    if (currentTier) {
      setActiveTier(currentTier);
      return;
    }
    try {
      let saved = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
      if (!saved && typeof document !== 'undefined') {
        const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
        if (match && match[3]) saved = decodeURIComponent(match[3]);
      }
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed?.tier) setActiveTier(parsed.tier);
      }
    } catch (err: unknown) {
      console.warn('[UI-106] Handled error retrieving user session in UpgradePaywallModal:', err instanceof Error ? err.message : String(err));
    }
  }, [currentTier, isOpen]);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-4"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="max-w-xl w-full max-h-[85vh] overflow-y-auto p-6 sm:p-8 bg-[#141414] border border-white/10 rounded-2xl relative shadow-2xl flex flex-col gap-6"
        >
          {/* Close Button */}
          <button
            onClick={onClose}
            aria-label="Close upgrade modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
          >
            <X size={20} />
          </button>

          {/* Header */}
          <div className="flex flex-col gap-3">
            <div className="px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-white text-xs font-mono font-bold uppercase tracking-wider w-fit">
              <span>{requiredTier} Tier Required</span>
            </div>

            <h2 className="text-2xl sm:text-3xl font-extrabold text-[#EDEDED]">
              {featureTitle}
            </h2>

            <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed">
              {featureDescription}
            </p>
          </div>

          {/* Plan Comparison Box */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Pro Plan Card */}
            <div className={`p-4 rounded-xl bg-[#0A0A0A] flex flex-col justify-between gap-4 ${
              activeTier === 'Pro' ? 'border-2 border-emerald-500/50' : 'border border-white/20'
            }`}>
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-mono font-extrabold uppercase text-[#EDEDED]">Pro Plan</span>
                    {activeTier === 'Pro' && (
                      <span className="text-[11px] font-bold bg-emerald-500 text-black uppercase tracking-wider px-1.5 py-0.5 rounded flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-black" />
                        Active
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono font-bold text-white">$19/mo</span>
                </div>
                <ul className="mt-3 space-y-2 text-[0.75rem] text-[#A1A1AA]">
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>5 Active Repositories</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Unlimited Manual Scans</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>1-Click AI Fix Prompts</span>
                  </li>
                </ul>
              </div>

              <div className="flex flex-col gap-2">
                {activeTier === 'Pro' ? (
                  <a
                    href="https://polar.sh/purchases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-primary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 transition-all shadow-sm font-mono cursor-pointer text-center"
                  >
                    <span>Manage at Polar</span>
                    <ExternalLink size={13} />
                  </a>
                ) : activeTier === 'Enterprise' ? (
                  <div className="w-full py-2.5 text-xs font-mono font-medium rounded-lg bg-white/5 border border-white/10 text-zinc-400 text-center">
                    Included in Enterprise
                  </div>
                ) : (
                  <>
                    <a
                      href="https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-primary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm font-mono cursor-pointer text-center"
                    >
                      <span>Pay with Polar ($19/mo)</span>
                      <ArrowRight size={13} />
                    </a>
                    <button
                      onClick={() => {
                        onClose();
                        router.push('/checkout?plan=zelsis-core&billing=annual');
                      }}
                      className="text-[10px] text-[#A1A1AA] hover:text-white text-center py-1 transition-colors"
                    >
                      View Checkout &amp; Invoicing &rarr;
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Enterprise Plan Card */}
            <div className={`p-4 rounded-xl bg-[#0A0A0A] flex flex-col justify-between gap-4 ${
              activeTier === 'Enterprise' ? 'border-2 border-emerald-500/50' : 'border border-white/10'
            }`}>
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-mono font-extrabold uppercase text-[#EDEDED]">Enterprise</span>
                    {activeTier === 'Enterprise' && (
                      <span className="text-[11px] font-bold bg-emerald-500 text-black uppercase tracking-wider px-1.5 py-0.5 rounded flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-black" />
                        Active
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono font-bold text-white">$99/mo</span>
                </div>
                <ul className="mt-3 space-y-2 text-[0.75rem] text-[#A1A1AA]">
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Unlimited Repositories</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>CI/CD Webhook Triggers</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Red Team Attack Payload</span>
                  </li>
                </ul>
              </div>

              <div className="flex flex-col gap-2">
                {activeTier === 'Enterprise' ? (
                  <a
                    href="https://polar.sh/purchases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-secondary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 transition-all shadow-sm font-mono cursor-pointer text-center"
                  >
                    <span>Manage at Polar</span>
                    <ExternalLink size={13} />
                  </a>
                ) : (
                  <>
                    <a
                      href="https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-secondary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 border border-white/20 text-[#EDEDED] hover:bg-white/5 transition-all shadow-sm font-mono cursor-pointer text-center"
                    >
                      <span>Pay with Polar ($99/mo)</span>
                      <ShieldCheck size={13} />
                    </a>
                    <button
                      onClick={() => {
                        onClose();
                        router.push('/checkout?plan=vibecare&billing=annual');
                      }}
                      className="text-[10px] text-[#A1A1AA] hover:text-white text-center py-1 transition-colors"
                    >
                      View Checkout &amp; Invoicing &rarr;
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="pt-2 text-center text-[0.7rem] text-[#A1A1AA]">
            Annual plans include 20% discount &amp; instant license activation key. Cancel anytime.
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
