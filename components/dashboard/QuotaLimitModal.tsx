'use client';

import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldAlert, Zap, ArrowRight } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { priceLabel } from '@/data/pricing-plans';

interface QuotaLimitModalProps {
  isOpen: boolean;
  onClose: () => void;
  scansUsed: number;
  scansLimit: number;
}

export const QuotaLimitModal: React.FC<QuotaLimitModalProps> = ({
  isOpen,
  onClose,
  scansUsed,
  scansLimit,
}) => {
  const router = useRouter();

  useEffect(() => {
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
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
        className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="quota-modal-title"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 8 }}
          className="max-w-lg w-full bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 shadow-2xl relative flex flex-col gap-6"
        >
          {/* Close Trigger */}
          <button
            onClick={onClose}
            aria-label="Close quota limit dialog"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-zinc-400 hover:text-white rounded-xl hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X size={20} />
          </button>

          {/* Header Badge & Icon */}
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
              <ShieldAlert size={24} />
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded w-fit mb-1">
                Free Tier Quota Limit
              </span>
              <h2 id="quota-modal-title" className="text-lg sm:text-xl font-extrabold text-white">
                Monthly Scan Limit Reached ({scansUsed} / {scansLimit})
              </h2>
            </div>
          </div>

          {/* Message */}
          <p className="text-xs sm:text-sm text-zinc-300 leading-relaxed">
            You have used all <strong className="text-white font-mono">{scansUsed} free deployment readiness audits</strong> included in your Free plan for this billing cycle.
          </p>

          {/* Pro Benefits Highlights */}
          <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 flex flex-col gap-2.5 text-xs font-mono">
            <div className="flex items-center gap-2 text-white font-bold">
              <Zap size={14} className="text-amber-400" />
              <span>Upgrade to Zelsis Pro ({priceLabel('Pro')}) unlocks:</span>
            </div>
            <ul className="space-y-1.5 text-zinc-400 text-[11px] pl-5 list-disc">
              <li><strong className="text-zinc-200">Unlimited</strong> manual &amp; automated repository audits</li>
              <li><strong className="text-zinc-200">Fix prompts and patches</strong> for every finding</li>
              <li><strong className="text-zinc-200">Automated GitHub Actions PR Bot</strong> &amp; CI/CD release gate</li>
              <li><strong className="text-zinc-200">Private repository</strong> inspection with your GitHub PAT</li>
            </ul>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
            <button
              onClick={() => {
                onClose();
                router.push('/checkout?plan=pro&reason=quota_exceeded');
              }}
              className="btn btn-primary w-full py-2.5 px-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400 transition-all flex items-center justify-center gap-2 shadow-lg cursor-pointer"
            >
              <span>Upgrade to Pro ({priceLabel('Pro')})</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
