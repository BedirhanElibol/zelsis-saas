'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Sliders, CheckCircle2, ShieldCheck, Zap, AlertTriangle, Lock } from 'lucide-react';
import { UserTier } from '@/data/schema';
import { isCustomRulesAllowed } from '@/lib/quota-manager';

interface RuleConfiguratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName: string;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const RuleConfiguratorModal: React.FC<RuleConfiguratorModalProps> = ({
  isOpen,
  onClose,
  projectName,
  userTier,
  onOpenCheckout,
}) => {
  const isAllowed = isCustomRulesAllowed(userTier);
  const [rules, setRules] = useState([
    { id: 1, name: 'SEC-01: Exposed API Keys & Tokens', category: 'SECURITY', severity: 'CRITICAL', enabled: true },
    { id: 3, name: 'SEC-03: Permissive Row Level Security (RLS)', category: 'SECURITY', severity: 'CRITICAL', enabled: true },
    { id: 8, name: 'SEC-08: Wildcard CORS Configuration (*)', category: 'SECURITY', severity: 'HIGH', enabled: true },
    { id: 16, name: 'SEC-16: Unsanitized innerHTML DOM Mutation', category: 'SECURITY', severity: 'HIGH', enabled: true },
    { id: 101, name: 'SEC-WEB-01: Missing Content-Security-Policy', category: 'SECURITY', severity: 'CRITICAL', enabled: true },
    { id: 102, name: 'SEC-WEB-02: Missing HSTS Security Header', category: 'SECURITY', severity: 'HIGH', enabled: true },
    { id: 26, name: 'UI-01: Generic Neon Gradient Cliché', category: 'VIBEPOLISH', severity: 'MEDIUM', enabled: true },
    { id: 27, name: 'UI-03: Sparkle Icon Overuse (Replace with Action Micro-Copy)', category: 'VIBEPOLISH', severity: 'LOW', enabled: true },
    { id: 28, name: 'UI-04: Absence of Empty State Component Fallback', category: 'VIBEPOLISH', severity: 'MEDIUM', enabled: true },
    { id: 29, name: 'UI-07: Conversational Chat-Wrapper Lock-In Trap', category: 'VIBEPOLISH', severity: 'HIGH', enabled: true }
  ]);

  const [savedStatus, setSavedStatus] = useState(false);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const toggleRule = (index: number) => {
    setRules((prev) =>
      prev.map((r, i) => (i === index ? { ...r, enabled: !r.enabled } : r))
    );
  };

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Sliders size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Release Gate Rule Engine Configurator
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Customize OWASP &amp; VibePolish UI clearance rules for {projectName}
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {!isAllowed ? (
            <div className="flex flex-col items-center justify-center gap-6 py-12 px-6 bg-[#0A0A0A] border border-white/10 rounded-2xl text-center my-2">
              <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Lock size={26} className="text-zinc-400" />
              </div>
              <div className="max-w-md">
                <h3 className="text-base font-extrabold text-[#EDEDED] mb-2">
                  Custom Rule Engine is an Enterprise Feature
                </h3>
                <p className="text-xs text-[#A1A1AA] leading-relaxed">
                  Tailor OWASP clearance thresholds, custom security rule matrices, and organization-wide compliance policies.
                  Available exclusively on the <span className="text-white font-semibold">Enterprise</span> plan.
                </p>
              </div>
              <div className="flex items-center gap-3 w-full max-w-xs">
                <button
                  type="button"
                  onClick={onClose}
                  className="btn btn-secondary text-xs px-4 py-2.5 flex-1 min-h-[44px]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => onOpenCheckout?.('Enterprise')}
                  className="btn btn-primary text-xs px-5 py-2.5 font-bold rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm flex-1 min-h-[44px]"
                >
                  <Lock size={13} />
                  <span>Upgrade to Enterprise</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Rules List */}
              <div className="max-h-[20rem] overflow-y-auto space-y-2 pr-1">
                {rules.length === 0 ? (
                  <div className="p-8 text-center bg-[#0A0A0A] rounded-xl border border-white/10 text-xs text-[#94A3B8]">
                    No rules active in custom configuration. Reset to default OWASP &amp; VibePolish rule matrix.
                  </div>
                ) : (
                  rules.map((rule, idx) => (
                    <div
                      key={idx}
                      className="bg-[#0A0A0A] p-3.5 rounded-xl border border-white/10 flex items-center justify-between gap-3 hover:border-white/20 transition-all"
                    >
                      <div className="flex items-center gap-3">
                        <input
                          id={`rule-toggle-${idx}`}
                          name={`ruleEnabled_${idx}`}
                          aria-label={`Toggle rule ${rule.name}`}
                          type="checkbox"
                          checked={rule.enabled}
                          onChange={() => toggleRule(idx)}
                          className="w-4 h-4 rounded accent-white cursor-pointer"
                        />
                        <div>
                          <div className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
                            <span>{rule.name}</span>
                            <span
                              className="text-[0.62rem] font-bold px-2 py-0.5 rounded-full bg-white/5 text-white border border-white/10"
                            >
                              {rule.category}
                            </span>
                          </div>
                        </div>
                      </div>

                      <span
                        className={`text-[0.65rem] font-extrabold uppercase px-2 py-0.5 rounded ${
                          rule.severity === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-400'
                            : rule.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'bg-[#10B981]/20 text-[#10B981]'
                        }`}
                      >
                        {rule.severity}
                      </span>
                    </div>
                  ))
                )}
              </div>
              {/* Saved Status */}
              {savedStatus && (
                <div className="p-3 rounded-xl bg-white/5 border border-white/10 text-white text-xs font-mono flex items-center gap-2">
                  <CheckCircle2 size={16} />
                  <span>Rule Configuration Saved! Rule matrix updated for {projectName}.</span>
                </div>
              )}

              {/* Footer Actions */}
              <div className="flex items-center justify-between pt-2 border-t border-white/10">
                <div className="text-xs text-[#94A3B8] font-mono">
                  {rules.filter((r) => r.enabled).length} of {rules.length} Rules Active
                </div>

                <div className="flex items-center gap-2">
                  <button className="btn btn-secondary text-xs px-4 py-2" onClick={onClose}>
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm min-h-[44px]"
                    onClick={() => {
                      setSavedStatus(true);
                      setTimeout(onClose, 1200);
                    }}
                  >
                    Save Rule Matrix
                  </button>
                </div>
              </div>
            </>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
