'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Finding, PlanUsageQuota } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { X, Copy, CheckCircle2, AlertTriangle, Code, ShieldCheck, User, GitCommit, FileText, Split, AlignJustify, Lock } from 'lucide-react';
import { formatFindingForJira } from '@/lib/export-utils';
import { checkAiPromptQuota } from '@/lib/quota-manager';

export interface FindingDetailModalProps {
  isOpen: boolean;
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve?: (id: string) => void;
  onMarkFalsePositive?: (id: string) => void;
  onIgnoreRule?: (ruleId: number) => void;
  user?: UserProfile | null;
  quota?: PlanUsageQuota;
  onRecordAiPrompt?: () => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

/**
 * Defang raw dangerous HTML tags and scripts to prevent client-side XSS injection
 */
function sanitizeContent(text: string): string {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRUBBED_SCRIPT]')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '[SCRUBBED_IFRAME]')
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '[SCRUBBED_OBJECT]')
    .replace(/javascript\s*:/gi, 'blocked-javascript:');
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  isOpen,
  finding,
  onClose,
  onToggleResolve,
  onMarkFalsePositive,
  onIgnoreRule,
  user,
  quota,
  onRecordAiPrompt,
  onOpenCheckout,
}) => {
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [copiedJira, setCopiedJira] = useState(false);
  const [activeTab, setActiveTab] = useState<'diff' | 'prompt' | 'jira'>('diff');
  const [diffViewMode, setDiffViewMode] = useState<'split' | 'unified'>('split');

  const userTier = user?.tier || 'Free';
  const aiPromptCheck = quota ? checkAiPromptQuota(quota, userTier) : { allowed: true, remaining: Infinity };

  // Keyboard accessibility: Close on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !finding) return null;

  const cleanSnippet = sanitizeContent(finding.snippet);
  const cleanPrompt = sanitizeContent(finding.remediationPrompt);
  const cleanTitle = sanitizeContent(finding.title);
  const cleanSteps = (finding.reproductionSteps || []).map(sanitizeContent);

  const diffText =
    finding.diffPatch ||
    `--- a/${finding.filePath}\n+++ b/${finding.filePath}\n@@ -${finding.lineRange} @@\n- ${cleanSnippet}\n+ // REMEDIATION: ${cleanPrompt}`;

  const copyDiff = () => {
    if (!aiPromptCheck.allowed) {
      onOpenCheckout?.('Pro');
      return;
    }
    navigator.clipboard.writeText(diffText);
    setCopiedDiff(true);
    onRecordAiPrompt?.();
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  const copyPrompt = () => {
    if (!aiPromptCheck.allowed) {
      onOpenCheckout?.('Pro');
      return;
    }
    navigator.clipboard.writeText(cleanPrompt);
    setCopiedPrompt(true);
    onRecordAiPrompt?.();
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  const copyJira = () => {
    const jiraMarkdown = formatFindingForJira(finding);
    navigator.clipboard.writeText(jiraMarkdown);
    setCopiedJira(true);
    setTimeout(() => setCopiedJira(false), 2000);
  };

  const severityBadgeClass =
    finding.severity === 'CRITICAL'
      ? 'bg-red-500/15 text-red-400 border border-red-500/30'
      : finding.severity === 'HIGH'
      ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
      : finding.severity === 'MEDIUM'
      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
      : 'bg-zinc-800 text-zinc-300 border border-zinc-700';

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm overflow-hidden"
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
        role="presentation"
      >
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 28, stiffness: 280 }}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-label={`Detailed Audit Finding: ${cleanTitle}`}
          className="w-full max-w-3xl h-full bg-[#0E0E10] border-l border-white/10 shadow-2xl flex flex-col overflow-hidden"
        >
          {/* Drawer Top Navigation Bar */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#121214] shrink-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-extrabold uppercase ${severityBadgeClass}`}>
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-zinc-400 font-bold px-2 py-0.5 rounded bg-white/5 border border-white/10">
                {finding.ruleId || finding.id}
              </span>
              <span className="text-xs font-mono text-zinc-400 font-medium">
                {finding.category}
              </span>
            </div>

            <div className="flex items-center gap-2">
              {onMarkFalsePositive && (
                <button
                  type="button"
                  onClick={() => onMarkFalsePositive(finding.id)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-bold font-mono transition-all cursor-pointer flex items-center gap-1.5 ${
                    finding.falsePositive
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30'
                      : 'bg-white/5 text-zinc-300 border border-white/10 hover:bg-white/10 hover:text-white'
                  }`}
                  title="Triage finding as False Positive (Accepted Risk)"
                >
                  <ShieldCheck size={13} className={finding.falsePositive ? 'text-amber-400' : 'text-zinc-400'} />
                  <span>{finding.falsePositive ? 'False Positive (Muted)' : 'False Positive'}</span>
                </button>
              )}
              {onToggleResolve && (
                <button
                  type="button"
                  onClick={() => onToggleResolve(finding.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all cursor-pointer ${
                    finding.status === 'RESOLVED'
                      ? 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700'
                      : 'bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300'
                  }`}
                >
                  {finding.status === 'RESOLVED' ? 'Reopen' : 'Mark Resolved'}
                </button>
              )}
              <button
                type="button"
                onClick={onClose}
                aria-label="Close drawer"
                className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-white/20"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Scrollable Drawer Content */}
          <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
            {/* Finding Title & File Path Banner */}
            <div className="flex flex-col gap-1.5">
              <h2 className="text-lg sm:text-xl font-extrabold text-[#EDEDED] leading-snug">
                {cleanTitle}
              </h2>
              <div className="text-xs font-mono text-emerald-400/90 flex items-center gap-2 flex-wrap">
                <span className="text-zinc-300 font-bold">{finding.filePath}</span>
                <span className="text-zinc-400">·</span>
                <span className="bg-white/5 px-2 py-0.5 rounded text-zinc-300 font-bold border border-white/10">
                  Line {finding.lineRange}
                </span>
                <span className="text-zinc-400">·</span>
                <span className="text-zinc-400 capitalize">{(finding.status || 'OPEN').toLowerCase()}</span>
              </div>
            </div>

            {/* Interactive Remediation Workstation */}
            <div className="bg-[#141416] border border-white/10 rounded-xl p-4 sm:p-5 flex flex-col gap-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
                <div className="flex items-center gap-2 text-xs font-mono font-extrabold text-zinc-200">
                  <ShieldCheck size={16} className="text-emerald-400" />
                  <span>Surgical Fix Workstation</span>
                </div>

                {/* Main Tabs */}
                <div className="flex items-center gap-1 bg-[#0A0A0A] p-1 rounded-lg border border-white/10 self-start sm:self-auto">
                  <button
                    type="button"
                    onClick={() => setActiveTab('diff')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded text-[0.7rem] font-mono font-bold transition-all cursor-pointer ${
                      activeTab === 'diff'
                        ? 'bg-white text-black font-extrabold shadow-sm'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    <GitCommit size={12} />
                    <span>Diff Patch</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('prompt')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded text-[0.7rem] font-mono font-bold transition-all cursor-pointer ${
                      activeTab === 'prompt'
                        ? 'bg-white text-black font-extrabold shadow-sm'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    <Code size={12} />
                    <span>AI Fix Prompt</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('jira')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded text-[0.7rem] font-mono font-bold transition-all cursor-pointer ${
                      activeTab === 'jira'
                        ? 'bg-white text-black font-extrabold shadow-sm'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    <FileText size={12} />
                    <span>Jira / Linear</span>
                  </button>
                </div>
              </div>

              {/* Sub-bar for Diff View Controls */}
              {activeTab === 'diff' && (
                <div className="flex items-center justify-between gap-2">
                  {/* Split vs Unified Toggle */}
                  <div className="flex items-center gap-1 bg-[#0A0A0A] p-0.5 rounded-lg border border-white/10 text-xs">
                    <button
                      type="button"
                      onClick={() => setDiffViewMode('split')}
                      className={`px-2 py-0.5 rounded text-[0.68rem] font-mono flex items-center gap-1 transition-all cursor-pointer ${
                        diffViewMode === 'split' ? 'bg-white/15 text-white font-bold' : 'text-zinc-400 hover:text-zinc-300'
                      }`}
                    >
                      <Split size={11} />
                      <span>Side-by-Side</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setDiffViewMode('unified')}
                      className={`px-2 py-0.5 rounded text-[0.68rem] font-mono flex items-center gap-1 transition-all cursor-pointer ${
                        diffViewMode === 'unified' ? 'bg-white/15 text-white font-bold' : 'text-zinc-400 hover:text-zinc-300'
                      }`}
                    >
                      <AlignJustify size={11} />
                      <span>Unified</span>
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={copyDiff}
                    className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 border border-white/15 text-white text-xs font-bold font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                  >
                    {!aiPromptCheck.allowed ? (
                      <>
                        <Lock size={12} className="text-amber-400" />
                        <span>Copy Diff (Pro)</span>
                      </>
                    ) : copiedDiff ? (
                      <>
                        <CheckCircle2 size={13} className="text-emerald-400" />
                        <span>Diff Copied!</span>
                      </>
                    ) : (
                      <>
                        <Code size={13} />
                        <span>Copy Diff Patch</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* Tab 1: Code Diff View (Split or Unified) */}
              {activeTab === 'diff' && (
                diffViewMode === 'split' ? (
                  /* Side-by-Side Split View */
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                    {/* Left: Vulnerable Code (Red) */}
                    <div className="bg-[#0A0A0C] border border-red-500/20 rounded-xl p-3 flex flex-col gap-2">
                      <div className="flex items-center justify-between text-[0.68rem] font-bold text-red-400 uppercase tracking-wider border-b border-red-500/10 pb-1.5">
                        <span>Current Vulnerable Code</span>
                        <span className="text-zinc-400">Line {finding.lineRange}</span>
                      </div>
                      <pre className="m-0 text-[0.72rem] text-red-200/90 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                        {cleanSnippet}
                      </pre>
                    </div>

                    {/* Right: Remediated Fix (Green) */}
                    <div className="bg-[#0A0A0C] border border-emerald-500/25 rounded-xl p-3 flex flex-col gap-2">
                      <div className="flex items-center justify-between text-[0.68rem] font-bold text-emerald-400 uppercase tracking-wider border-b border-emerald-500/10 pb-1.5">
                        <span>Zelsis Remediated Fix</span>
                        <span className="text-emerald-500">Patched</span>
                      </div>
                      <pre className="m-0 text-[0.72rem] text-emerald-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                        {cleanPrompt}
                      </pre>
                    </div>
                  </div>
                ) : (
                  /* Unified Diff View */
                  <div className="bg-[#0A0A0C] border border-white/10 rounded-xl overflow-hidden font-mono text-xs">
                    <div className="p-3 space-y-1 overflow-x-auto text-[0.72rem] leading-relaxed">
                      {finding.diffPatch ? (
                        finding.diffPatch.split('\n').map((dLine: string, idx: number) => {
                          const isAdd = dLine.startsWith('+') && !dLine.startsWith('+++');
                          const isDel = dLine.startsWith('-') && !dLine.startsWith('---');
                          const isHdr = dLine.startsWith('@@') || dLine.startsWith('---') || dLine.startsWith('+++');
                          return (
                            <div
                              key={`patch-${idx}`}
                              className={`px-2 py-0.5 rounded font-mono ${
                                isAdd
                                  ? 'bg-emerald-500/15 text-emerald-300 border-l-2 border-emerald-500'
                                  : isDel
                                  ? 'bg-red-500/15 text-red-300 border-l-2 border-red-500'
                                  : isHdr
                                  ? 'text-zinc-400 font-bold select-none'
                                  : 'text-zinc-300'
                              }`}
                            >
                              <span className="whitespace-pre">{dLine}</span>
                            </div>
                          );
                        })
                      ) : (
                        <>
                          <div className="text-zinc-400 select-none">--- a/{finding.filePath}</div>
                          <div className="text-zinc-400 select-none">+++ b/{finding.filePath}</div>
                          <div className="text-zinc-600 select-none">@@ -{finding.lineRange} +{finding.lineRange} @@</div>
                          {cleanSnippet.split('\n').map((line: string, idx: number) => (
                            <div
                              key={`del-${idx}`}
                              className="bg-red-500/15 text-red-300 px-2 py-0.5 rounded border-l-2 border-red-500 flex items-start gap-2 font-mono"
                            >
                              <span className="text-red-400 select-none">-</span>
                              <span className="whitespace-pre">{line}</span>
                            </div>
                          ))}
                          <div className="bg-emerald-500/15 text-emerald-300 px-2 py-0.5 rounded border-l-2 border-emerald-500 flex items-start gap-2 font-mono">
                            <span className="text-emerald-400 select-none">+</span>
                            <span className="whitespace-pre">{cleanPrompt}</span>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )
              )}

              {/* Tab 2: AI Fix Prompt */}
              {activeTab === 'prompt' && (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[0.68rem] font-mono text-zinc-400 uppercase">
                      Paste into Claude / Cursor / GitHub Copilot:
                    </span>
                    {aiPromptCheck.allowed ? (
                      <button
                        type="button"
                        onClick={copyPrompt}
                        className="px-3 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-bold font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                      >
                        {copiedPrompt ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                        <span>{copiedPrompt ? 'Prompt Copied!' : 'Copy Fix Prompt'}</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onOpenCheckout?.('Pro')}
                        className="px-3 py-1 rounded bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-bold font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                      >
                        <Lock size={12} />
                        <span>Upgrade to Pro</span>
                      </button>
                    )}
                  </div>

                  {!aiPromptCheck.allowed ? (
                    <div className="bg-[#0A0A0C] p-6 rounded-xl border border-amber-500/30 flex flex-col items-center text-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                        <Lock size={20} />
                      </div>
                      <div>
                        <div className="text-sm font-bold text-white mb-1 font-mono">
                          Trial AI Remediation Limit Reached (1/1)
                        </div>
                        <p className="text-xs text-zinc-400 max-w-md mx-auto leading-relaxed">
                          You have used your 1 free AI fix prompt. Upgrade to Zelsis Pro ($19/mo) to unlock unlimited 1-click Claude, Cursor, and Copilot remediation prompts and automated diff patches.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => onOpenCheckout?.('Pro')}
                        className="btn btn-primary px-5 py-2.5 text-xs font-bold font-mono uppercase tracking-wider rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black transition-all cursor-pointer flex items-center gap-2"
                      >
                        <Lock size={13} />
                        <span>Unlock Unlimited AI Fixes ($19/mo)</span>
                      </button>
                    </div>
                  ) : (
                    <div className="bg-[#0A0A0C] p-4 rounded-xl border border-white/10 font-mono text-xs text-zinc-200 leading-relaxed select-text">
                      {cleanPrompt}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Jira / Linear Ticket Format */}
              {activeTab === 'jira' && (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[0.68rem] font-mono text-zinc-400 uppercase">
                      Markdown for Linear / Jira / GitHub Issue:
                    </span>
                    <button
                      type="button"
                      onClick={copyJira}
                      className="px-3 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-bold font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      {copiedJira ? <CheckCircle2 size={13} className="text-emerald-400" /> : <Copy size={13} />}
                      <span>{copiedJira ? 'Ticket Copied!' : 'Copy Markdown'}</span>
                    </button>
                  </div>
                  <div className="bg-[#0A0A0C] p-4 rounded-xl border border-white/10 font-mono text-xs text-zinc-200 leading-relaxed select-text whitespace-pre-wrap max-h-[300px] overflow-y-auto">
                    {formatFindingForJira(finding)}
                  </div>
                </div>
              )}
            </div>

            {/* Reproduction & Audit Steps */}
            <div>
              <div className="flex items-center gap-2 text-xs font-bold text-zinc-300 mb-2 font-mono">
                <AlertTriangle size={14} className="text-amber-400" />
                <span>Verification &amp; Reproduction Evidence:</span>
              </div>
              {cleanSteps.length === 0 ? (
                <p className="text-xs text-zinc-400 bg-[#141416] border border-white/5 rounded-xl p-3.5">
                  Automated AST rule trigger. No manual reproduction steps required.
                </p>
              ) : (
                <ol className="list-decimal list-inside space-y-1.5 text-xs text-zinc-400 bg-[#141416] border border-white/5 rounded-xl p-3.5">
                  {cleanSteps.map((step: string, idx: number) => (
                    <li key={idx} className="leading-relaxed">
                      {step}
                    </li>
                  ))}
                </ol>
              )}
            </div>

            {/* Category Specific Advisory Badge */}
            {finding.type === 'LEGAL_COMPLIANCE' ? (
              <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-amber-400 shrink-0 mt-1.5" />
                <div className="leading-relaxed">
                  <span className="font-bold text-amber-400">Legal &amp; Privacy Release Gate:</span>{' '}
                  This finding flags non-compliance with statutory privacy or payment standards (GDPR, CCPA, PCI-DSS). Remediate before production deploy.
                </div>
              </div>
            ) : finding.type === 'INFRA_DATABASE' ? (
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-cyan-400 shrink-0 mt-1.5" />
                <div className="leading-relaxed">
                  <span className="font-bold text-cyan-400">Infrastructure &amp; Database Gate:</span>{' '}
                  This finding detects cloud configuration or database exposure (database configurations, connection pools, SQL security, RLS policies, or cloud data stores). Apply the unified patch to secure your release.
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 mt-1.5" />
                <div className="leading-relaxed">
                  <span className="font-bold text-emerald-400">Security Clearance Gate:</span>{' '}
                  Evaluated in-memory via deterministic AST rules. Review and merge the recommended patch before promoting to production.
                </div>
              </div>
            )}
          </div>

          {/* Sticky Drawer Footer */}
          <div className="px-6 py-4 border-t border-white/10 bg-[#121214] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
              <User size={13} />
              <span>Owner: {finding.owner || 'Unassigned'}</span>
            </div>

            <div className="flex items-center gap-2.5">
              {onIgnoreRule && (
                <button
                  type="button"
                  onClick={() => onIgnoreRule(finding.ruleId)}
                  className="px-3 py-2 rounded-lg text-xs font-bold font-mono text-zinc-400 bg-white/5 border border-white/10 hover:bg-white/10 hover:text-white transition-all cursor-pointer"
                  title={`Mute rule #${finding.ruleId} across project`}
                >
                  Mute Rule #{finding.ruleId}
                </button>
              )}
              <button
                type="button"
                onClick={onClose}
                className="px-5 py-2 rounded-lg bg-white text-black font-bold text-xs hover:bg-neutral-200 transition-all cursor-pointer font-mono uppercase"
              >
                Done
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
