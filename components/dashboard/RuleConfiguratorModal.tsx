'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Sliders, CheckCircle2, Copy } from 'lucide-react';
import { UserTier } from '@/data/schema';

interface RuleConfiguratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName: string;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

/** Commonly tuned rules; ids match the engine so the generated .zelsisrc.json suppresses exactly these. */
const TUNABLE_RULES = [
  { id: 1, name: 'Exposed hardcoded secret API key', category: 'SECURITY', severity: 'CRITICAL' },
  { id: 3, name: 'Permissive row level security policy (USING true)', category: 'SECURITY', severity: 'CRITICAL' },
  { id: 14, name: 'Hardcoded fallback for session / JWT secret', category: 'SECURITY', severity: 'CRITICAL' },
  { id: 8, name: 'Wildcard CORS (Access-Control-Allow-Origin: *)', category: 'SECURITY', severity: 'HIGH' },
  { id: 16, name: 'Unsanitized innerHTML mutation (XSS risk)', category: 'SECURITY', severity: 'HIGH' },
  { id: 101, name: 'Missing Content-Security-Policy header', category: 'SECURITY', severity: 'CRITICAL' },
  { id: 102, name: 'Missing HSTS header', category: 'SECURITY', severity: 'MEDIUM' },
  { id: 28602, name: 'Icon-only button or link without an accessible name', category: 'VIBEPOLISH', severity: 'MEDIUM' },
  { id: 28601, name: 'Image without alt text', category: 'VIBEPOLISH', severity: 'MEDIUM' },
  { id: 1244, name: 'Viewport blocks zoom (user-scalable=no)', category: 'VIBEPOLISH', severity: 'HIGH' }
] as const;

export const RuleConfiguratorModal: React.FC<RuleConfiguratorModalProps> = ({
  isOpen,
  onClose,
  projectName,
}) => {
  const [rules, setRules] = useState(() => TUNABLE_RULES.map((r) => ({ ...r, enabled: true })));

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

  const rcJson = JSON.stringify({ ignoreRules: rules.filter((r) => !r.enabled).map((r) => String(r.id)) }, null, 2);

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
                  Rule Configuration
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Generate a .zelsisrc.json for {projectName}. Commit it to the repository root; the next scan applies it.
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

          <>
              {/* Rules List */}
              <div className="max-h-[20rem] overflow-y-auto space-y-2 pr-1">
                {rules.length === 0 ? (
                  <div className="p-8 text-center bg-[#0A0A0A] rounded-xl border border-white/10 text-xs text-[#94A3B8]">
                    No rules listed.
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
              <pre className="p-3 rounded-xl bg-[#0A0A0A] border border-white/10 text-[11px] font-mono text-zinc-300 overflow-x-auto">{rcJson}</pre>
              {savedStatus && (
                <div className="p-3 rounded-xl bg-white/5 border border-white/10 text-white text-xs font-mono flex items-center gap-2">
                  <CheckCircle2 size={16} />
                  <span>Copied. Save it as .zelsisrc.json in the repository root of {projectName}.</span>
                </div>
              )}

              {/* Footer Actions */}
              <div className="flex items-center justify-between pt-2 border-t border-white/10">
                <div className="text-xs text-[#94A3B8] font-mono">
                  {rules.filter((r) => !r.enabled).length} rule(s) suppressed
                </div>

                <div className="flex items-center gap-2">
                  <button className="btn btn-secondary text-xs px-4 py-2" onClick={onClose}>
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm min-h-[44px]"
                    onClick={() => {
                      navigator.clipboard.writeText(rcJson).then(() => setSavedStatus(true)).catch(() => setSavedStatus(false));
                    }}
                  >
                    <Copy size={12} className="inline mr-1.5" aria-hidden="true" />
                    Copy .zelsisrc.json
                  </button>
                </div>
              </div>
          </>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
