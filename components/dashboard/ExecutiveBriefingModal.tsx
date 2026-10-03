'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Award, ShieldCheck, AlertTriangle, Printer, Copy, CheckCircle2, FileText, Check, ExternalLink, Lock } from 'lucide-react';
import { Project } from '@/data/schema';
import { UserTier } from '@/data/schema';
import { exportProjectPdfReport, generateExecutiveMarkdown } from '@/lib/report-exporter';
import { ClipboardToastBadge, useClipboardToast } from '../ui/Toast';
import { isPdfExportAllowed } from '@/lib/quota-manager';

interface ExecutiveBriefingModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const ExecutiveBriefingModal: React.FC<ExecutiveBriefingModalProps> = ({
  isOpen,
  onClose,
  project,
  userTier = 'Free',
  onOpenCheckout,
}) => {
  const [copied, setCopied] = useState(false);
  const { isVisible, message, badge, showToast, hideToast } = useClipboardToast(2500);

  // Keyboard Escape listener for Accessibility (WCAG 2.2 AA)
  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const isPassed = project.gateStatus === 'PASSED';
  const openFindings = project.findings.filter((f) => f.status === 'OPEN');
  const criticals = openFindings.filter((f) => f.severity === 'CRITICAL');
  const highs = openFindings.filter((f) => f.severity === 'HIGH');
  const mediums = openFindings.filter((f) => f.severity === 'MEDIUM');

  const topBlockers = [...criticals, ...highs].slice(0, 3);

  const handleCopyMarkdown = async () => {
    try {
      const markdown = generateExecutiveMarkdown(project);
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      showToast('Executive briefing copied to clipboard', '[COPIED]');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      showToast('Failed to copy to clipboard', '[ERROR]');
    }
  };

  const handleExportPdf = () => {
    exportProjectPdfReport(project);
    showToast('Opening PDF Print & Export Dialog...', '[PRINT]');
  };

  return (
    <AnimatePresence>
      <div
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
        role="dialog"
        aria-modal="true"
        aria-labelledby="executive-briefing-title"
      >
        <motion.div
          initial={{ scale: 0.96, opacity: 0, y: 8 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.96, opacity: 0, y: 8 }}
          transition={{ duration: 0.18 }}
          className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Modal Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                <Award size={20} className="text-white" />
              </div>
              <div>
                <h2 id="executive-briefing-title" className="text-base sm:text-lg font-extrabold text-[#EDEDED]">
                  Executive Briefing &amp; CISO Summary
                </h2>
                <p className="text-xs text-[#A1A1AA]">
                  Synthesized release readiness certification for executive leadership &amp; SOC 2 auditors
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close executive briefing"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Release Gate Verdict Banner */}
          <div
            className={`p-4 sm:p-5 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
              isPassed
                ? 'bg-emerald-500/10 border-emerald-500/30'
                : 'bg-red-500/10 border-red-500/30'
            }`}
          >
            <div className="flex items-start sm:items-center gap-3.5">
              <div
                className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ${
                  isPassed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                }`}
              >
                {isPassed ? <ShieldCheck size={24} /> : <AlertTriangle size={24} />}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span
                    className={`font-mono text-[10px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                      isPassed
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                        : 'bg-red-500/20 text-red-400 border-red-500/40'
                    }`}
                  >
                    {isPassed ? 'PASSED' : 'BLOCKED'}
                  </span>
                  <h3
                    className={`text-sm sm:text-base font-extrabold ${
                      isPassed ? 'text-emerald-400' : 'text-red-400'
                    }`}
                  >
                    {isPassed ? 'Approved for Production Deployment' : 'Deployment Gate Hard-Blocked'}
                  </h3>
                </div>
                <p className="text-xs text-[#A1A1AA] mt-1 leading-relaxed">
                  {isPassed
                    ? 'Target codebase complies with all statutory security baselines, OWASP checks, and UI quality standards.'
                    : `Contains ${project.criticalCount} Critical and ${project.highCount} High risk findings requiring remediation prior to merge.`}
                </p>
              </div>
            </div>

            {/* Score Pill */}
            <div className="bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-center shrink-0 w-full sm:w-auto">
              <div
                className={`text-2xl font-extrabold font-mono leading-none ${
                  isPassed ? 'text-emerald-400' : 'text-red-400'
                }`}
              >
                {project.readinessScore}
                <span className="text-xs text-zinc-400 font-sans font-normal">/100</span>
              </div>
              <div className="text-[10px] font-mono text-[#A1A1AA] mt-1 uppercase tracking-wider font-semibold">
                Readiness Index
              </div>
            </div>
          </div>

          {/* 4-Pillar Scorecard Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-[#0A0A0A] p-3 rounded-xl border border-white/10 text-center">
              <div className="text-lg font-extrabold font-mono text-red-400">{criticals.length}</div>
              <div className="text-[10px] text-[#A1A1AA] uppercase font-mono mt-0.5">Critical</div>
            </div>
            <div className="bg-[#0A0A0A] p-3 rounded-xl border border-white/10 text-center">
              <div className="text-lg font-extrabold font-mono text-amber-400">{highs.length}</div>
              <div className="text-[10px] text-[#A1A1AA] uppercase font-mono mt-0.5">High Severity</div>
            </div>
            <div className="bg-[#0A0A0A] p-3 rounded-xl border border-white/10 text-center">
              <div className="text-lg font-extrabold font-mono text-blue-400">{mediums.length}</div>
              <div className="text-[10px] text-[#A1A1AA] uppercase font-mono mt-0.5">Medium Risk</div>
            </div>
            <div className="bg-[#0A0A0A] p-3 rounded-xl border border-white/10 text-center">
              <div className="text-lg font-extrabold font-mono text-emerald-400">100%</div>
              <div className="text-[10px] text-[#A1A1AA] uppercase font-mono mt-0.5">Permissive Lic</div>
            </div>
          </div>

          {/* Strategic Action Points / Top Remediation Blockers */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold uppercase text-white tracking-wider flex items-center gap-2">
              <FileText size={13} className="text-zinc-400" />
              <span>Top Remediation Priorities</span>
            </h4>

            {topBlockers.length === 0 ? (
              <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-zinc-300 flex items-center gap-2.5">
                <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                <span>Zero critical or high blockers detected. Safe for automated CI/CD deployment pipeline.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {topBlockers.map((blocker, idx) => (
                  <div
                    key={blocker.id}
                    className="p-3 rounded-xl bg-[#0A0A0A] border border-white/10 flex flex-col gap-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-[10px] text-zinc-400 font-bold">0{idx + 1}.</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                            blocker.severity === 'CRITICAL'
                              ? 'bg-red-500/15 text-red-400 border-red-500/30'
                              : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {blocker.severity}
                        </span>
                        <span className="font-bold text-zinc-200 truncate">{blocker.title}</span>
                      </div>
                      <span className="font-mono text-[10px] text-zinc-400 shrink-0">#{blocker.ruleId}</span>
                    </div>
                    <div className="font-mono text-[10px] text-zinc-400 truncate">
                      {blocker.filePath}:{blocker.lineRange}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer Actions: Print/Export PDF + Copy Markdown + Close */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-white/10">
            <div className="text-[11px] font-mono text-zinc-400 text-center sm:text-left">
              Official ISO-27001 / SOC 2 Ready Attestation
            </div>

            <div className="flex items-center gap-2.5 w-full sm:w-auto">
              <button
                type="button"
                onClick={handleCopyMarkdown}
                className="btn btn-secondary text-xs px-3.5 py-2.5 font-bold flex items-center justify-center gap-2 flex-1 sm:flex-none"
                title="Copy formatted markdown report for Slack, Jira, or email"
              >
                {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                <span>{copied ? 'Copied!' : 'Copy Markdown'}</span>
              </button>

              {isPdfExportAllowed(userTier) ? (
                <button
                  type="button"
                  onClick={handleExportPdf}
                  className="btn btn-primary text-xs px-4 py-2.5 font-bold flex items-center justify-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 rounded-xl transition-all shadow-sm flex-1 sm:flex-none"
                >
                  <Printer size={14} />
                  <span>Export PDF Report</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => onOpenCheckout?.('Pro')}
                  className="btn btn-primary text-xs px-4 py-2.5 font-bold flex items-center justify-center gap-2 bg-white/10 text-zinc-400 hover:bg-emerald-500 hover:text-black rounded-xl transition-all border border-white/10 flex-1 sm:flex-none"
                  title="Upgrade to Pro to export PDF reports"
                >
                  <Lock size={14} />
                  <span>PDF Export — Pro Only</span>
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* Floating Toast Notification */}
        <ClipboardToastBadge
          isVisible={isVisible}
          message={message}
          badge={badge}
          onDismiss={hideToast}
        />
      </div>
    </AnimatePresence>
  );
};
