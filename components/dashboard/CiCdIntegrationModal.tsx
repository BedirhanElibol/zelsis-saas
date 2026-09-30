'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, GitPullRequest, Copy, Check, Terminal, ExternalLink, ShieldCheck, AlertTriangle, Code, ArrowRight, Lock } from 'lucide-react';
import { Project, UserTier } from '@/data/schema';
import { isCicdIntegrationAllowed } from '@/lib/quota-manager';
import { ClipboardToastBadge, useClipboardToast } from '../ui/Toast';

interface CiCdIntegrationModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const CiCdIntegrationModal: React.FC<CiCdIntegrationModalProps> = ({
  isOpen,
  onClose,
  project,
  userTier,
  onOpenCheckout,
}) => {
  const isAllowed = isCicdIntegrationAllowed(userTier);
  const [copiedType, setCopiedType] = useState<'yaml' | 'curl' | null>(null);
  const { isVisible, message, badge, showToast, hideToast } = useClipboardToast(2500);

  // Keyboard Escape listener
  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const appUrl = typeof window !== 'undefined' ? window.location.origin : 'https://zelsis-saas.vercel.app';
  const targetRepo = project.repoUrl || 'https://github.com/your-org/your-repo';

  const githubWorkflowYaml = `name: Zelsis Deployment Release Gate

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  zelsis-gate:
    name: Evaluate Release Readiness
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      - name: Trigger Zelsis Audit Gate
        id: zelsis
        run: |
          RESPONSE=$(curl -s -X POST "${appUrl}/api/v1/gate-check" \\
            -H "Content-Type: application/json" \\
            -d '{"repoUrl": "${targetRepo}"}')
          
          echo "GATE_STATUS=$(echo $RESPONSE | jq -r .gateStatus)" >> $GITHUB_ENV
          echo "SCORE=$(echo $RESPONSE | jq -r .readinessScore)" >> $GITHUB_ENV
          echo "CRITICAL_COUNT=$(echo $RESPONSE | jq -r .criticalCount)" >> $GITHUB_ENV

      - name: Post PR Gate Status Comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            const status = process.env.GATE_STATUS;
            const score = process.env.SCORE;
            const criticals = process.env.CRITICAL_COUNT;
            const isPassed = status === 'PASSED';
            
            const body = [
              '### ' + (isPassed ? '🛡️ Zelsis Release Gate: APPROVED ✅' : '🚨 Zelsis Release Gate: BLOCKED ❌'),
              '',
              '| Metric | Evaluated Value | Threshold | Status |',
              '| :--- | :--- | :--- | :--- |',
              '| **Readiness Score** | \`' + score + '/100\` | \`>= 80/100\` | ' + (Number(score) >= 80 ? '✅ Pass' : '❌ Fail') + ' |',
              '| **Critical Blockers** | \`' + criticals + '\` | \`0\` | ' + (criticals === '0' ? '✅ Pass' : '❌ Block') + ' |',
              '| **Overall Gate** | **' + status + '** | **PASSED** | ' + (isPassed ? '✅ Clear' : '❌ Blocked') + ' |',
              '',
              '> [View Full Certified Telemetry & Remediation Diff](${appUrl})'
            ].join('\\n');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Enforce Zero-Vulnerability Release Gate
        run: |
          if [ "$GATE_STATUS" != "PASSED" ]; then
            echo "❌ Zelsis Release Gate Failed: Critical vulnerabilities detected."
            exit 1
          fi
          echo "✅ Zelsis Release Gate Passed: Cleared for production deployment."
`;

  const curlSnippet = `curl -X POST "${appUrl}/api/v1/gate-check" \\
  -H "Content-Type: application/json" \\
  -d '{"repoUrl": "${targetRepo}"}'`;

  const copyToClipboard = async (text: string, type: 'yaml' | 'curl') => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedType(type);
      showToast(
        type === 'yaml' ? 'GitHub Actions workflow YAML copied!' : 'cURL command copied!',
        '[COPIED]'
      );
      setTimeout(() => setCopiedType(null), 2000);
    } catch {
      showToast('Failed to copy to clipboard', '[ERROR]');
    }
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
        aria-labelledby="cicd-modal-title"
      >
        <motion.div
          initial={{ scale: 0.96, opacity: 0, y: 8 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.96, opacity: 0, y: 8 }}
          transition={{ duration: 0.18 }}
          className="w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                <GitPullRequest size={20} className="text-white" />
              </div>
              <div>
                <h2 id="cicd-modal-title" className="text-base sm:text-lg font-extrabold text-[#EDEDED]">
                  CI/CD &amp; GitHub PR Release Gate
                </h2>
                <p className="text-xs text-[#A1A1AA]">
                  Enforce automated pre-merge AST security gates on every Pull Request
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close CI/CD integration modal"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors"
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
                  CI/CD Integration is a Pro Feature
                </h3>
                <p className="text-xs text-[#A1A1AA] leading-relaxed">
                  Enforce automated pre-merge AST security gates on every Pull Request with GitHub Actions, GitLab CI, and CLI integration.
                  Available on <span className="text-white font-semibold">Pro</span> and <span className="text-white font-semibold">Enterprise</span> plans.
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
                  onClick={() => onOpenCheckout?.('Pro')}
                  className="btn btn-primary text-xs px-5 py-2.5 font-bold rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm flex-1 min-h-[44px]"
                >
                  <Lock size={13} />
                  <span>Upgrade to Pro</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Value Prop Banner */}
              <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-zinc-300 shrink-0">
                    <ShieldCheck size={18} />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white">Block Vulnerabilities Before They Ship</div>
                    <div className="text-[11px] text-[#A1A1AA]">
                      Automatically fails PRs containing Critical OWASP risks or license copyleft violations.
                    </div>
                  </div>
                </div>
                <span className="font-mono text-[10px] text-zinc-300 bg-white/5 px-2 py-1 rounded border border-white/10 shrink-0">
                  Sub-3.5s Scan
                </span>
              </div>

              {/* Step 1: GitHub Actions YAML */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Code size={13} className="text-zinc-400" />
                    <span>1. Add Workflow: .github/workflows/zelsis-gate.yml</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(githubWorkflowYaml, 'yaml')}
                    className="btn btn-secondary text-xs px-2.5 py-1 flex items-center gap-1.5"
                  >
                    {copiedType === 'yaml' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    <span>{copiedType === 'yaml' ? 'Copied YAML!' : 'Copy Workflow'}</span>
                  </button>
                </div>

                <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-3 min-h-[120px] max-h-[40vh] overflow-y-auto font-mono text-[11px] text-zinc-300">
                  <pre className="whitespace-pre">{githubWorkflowYaml}</pre>
                </div>
              </div>

              {/* Step 2: PR Comment Visual Preview */}
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Terminal size={13} className="text-zinc-400" />
                  <span>2. Automated Pull Request Comment Preview</span>
                </span>

                <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 text-xs font-sans space-y-2">
                  <div className="flex items-center gap-2 border-b border-white/5 pb-2">
                    <div className="w-5 h-5 rounded-full bg-white/10 text-white font-mono text-[10px] font-bold flex items-center justify-center">
                      Z
                    </div>
                    <strong className="text-zinc-200">zelsis-bot</strong>
                    <span className="text-[10px] px-1 rounded bg-white/10 text-zinc-400 font-mono">bot</span>
                    <span className="text-zinc-400 text-[10px] ml-auto">Just now</span>
                  </div>

                  <div className="space-y-1.5 pt-1">
                    <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                      <ShieldCheck size={15} />
                      <span>Zelsis Release Gate: APPROVED</span>
                    </div>
                    <div className="text-[11px] text-zinc-400">
                      Readiness Score: <strong className="text-white">96/100</strong> / 0 Critical Blockers / Zero AGPL Copyleft Risks
                    </div>
                    <div className="text-[10px] text-blue-400 underline pt-1 cursor-pointer">
                      View Full Certified Telemetry &amp; Remediation Diff →
                    </div>
                  </div>
                </div>
              </div>

              {/* Step 3: Fast cURL Terminal Trigger */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Terminal size={13} className="text-zinc-400" />
                    <span>3. Or Run via cURL in Custom CI/CD (GitLab, Bitbucket, CircleCI)</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(curlSnippet, 'curl')}
                    className="btn btn-secondary text-xs px-2.5 py-1 flex items-center gap-1.5"
                  >
                    {copiedType === 'curl' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    <span>{copiedType === 'curl' ? 'Copied cURL!' : 'Copy cURL'}</span>
                  </button>
                </div>

                <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-3 font-mono text-[11px] text-zinc-300">
                  <code>{curlSnippet}</code>
                </div>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between pt-4 border-t border-white/10">
                <div className="text-[11px] font-mono text-zinc-400">
                  Endpoint: <span className="text-zinc-400">POST /api/v1/gate-check</span>
                </div>
                <button
                  onClick={onClose}
                  className="btn btn-primary text-xs px-5 py-2 font-bold bg-white text-black hover:bg-neutral-200 rounded-lg transition-all min-h-[44px]"
                >
                  Done
                </button>
              </div>
            </>
          )}
        </motion.div>

        {/* Floating Toast */}
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
