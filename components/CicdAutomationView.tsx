'use client';

import React, { useState } from 'react';
import Image from 'next/image';
import { Terminal, GitPullRequest, ShieldCheck, Copy, CheckCircle2, Download, Settings2, Sliders, CheckSquare, AlertTriangle, Lock, ArrowRight, FileCode } from 'lucide-react';
import { Project, UserTier } from '@/data/schema';
import { getPublicAppUrl } from '@/lib/app-url';
import { isCicdViewAllowed } from '@/lib/quota-manager';
import { exportProjectSarifReport } from '@/lib/report-exporter';

interface CicdAutomationViewProps {
  projectName?: string;
  project?: Project;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const CicdAutomationView: React.FC<CicdAutomationViewProps> = ({
  projectName = 'Next.js 15 SaaS Starter',
  project,
  userTier = 'Free',
  onOpenCheckout
}) => {
  const [failThreshold, setFailThreshold] = useState<'smart' | 'strict' | 'advisory'>('smart');
  const [copiedWorkflow, setCopiedWorkflow] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [enabledGates, setEnabledGates] = useState({
    security: true,
    compliance: true,
    infra: true,
    vibepolish: true,
    vibecare: true
  });
  const [minScore, setMinScore] = useState(85);

  const generateGithubWorkflow = () => {
    const appUrl = getPublicAppUrl();
    const failCheck =
      failThreshold === 'smart'
        ? `if [ "$STATUS" = "FAILED" ]; then echo "::error::Zelsis gate FAILED (score $SCORE/100)"; exit 1; fi`
        : failThreshold === 'strict'
        ? `if [ "$STATUS" != "PASSED" ] || [ "$SCORE" -lt ${minScore} ]; then echo "::error::Zelsis gate $STATUS (score $SCORE/100, minimum ${minScore})"; exit 1; fi`
        : `echo "Advisory mode: gate $STATUS (score $SCORE/100) does not block."`;

    return `name: Zelsis Pre-Flight Release Gate

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  zelsis-gate:
    name: Zelsis Release Gate (${projectName})
    runs-on: ubuntu-latest
    steps:
      - name: Run Zelsis gate check
        env:
          ZELSIS_API_KEY: \${{ secrets.ZELSIS_API_KEY }}
        run: |
          RESPONSE=$(curl -s -X POST "${appUrl}/api/v1/gate-check" \\
            -H "Content-Type: application/json" \\
            -H "x-api-key: $ZELSIS_API_KEY" \\
            -d '{"repoUrl": "\${{ github.server_url }}/\${{ github.repository }}"}')
          echo "$RESPONSE" > zelsis-report.json
          STATUS=$(jq -r '.gateStatus // "ERROR"' zelsis-report.json)
          SCORE=$(jq -r '.readinessScore // 0' zelsis-report.json)
          echo "Gate: $STATUS, score: $SCORE/100" >> $GITHUB_STEP_SUMMARY
          ${failCheck}

      - name: Upload gate report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: zelsis-release-report
          path: zelsis-report.json
`;
  };

  const generateZelsisConfig = () => {
    return JSON.stringify(
      {
        $schema: 'https://zelsis.com/schemas/v1/zelsisrc.json',
        projectName,
        minScoreThreshold: minScore,
        failStrategy: failThreshold,
        gates: {
          security: { enabled: enabledGates.security, blockOnOwasp: true },
          legalCompliance: { enabled: enabledGates.compliance, enforceGdprCookieCheck: true, pciCheck: true },
          infraDatabase: { enabled: enabledGates.infra, enforceSupabaseRls: true, blockRootContainers: true },
          designVibePolish: { enabled: enabledGates.vibepolish, banAiCliches: true },
          vibeCareHealth: { enabled: enabledGates.vibecare, enforceWcagFocus: true, enforceCwImage: true }
        },
        ignoreRules: ['UI-201']
      },
      null,
      2
    );
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const downloadFile = (filename: string, content: string) => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Tier paywall gate — Free users cannot access CI/CD */}
      {!isCicdViewAllowed(userTier) && (
        <div className="flex flex-col items-center justify-center gap-6 py-16 px-6 bg-[#141414] border border-white/10 rounded-2xl text-center">
          <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
            <Lock size={30} className="text-zinc-400" />
          </div>
          <div className="max-w-md">
            <h2 className="text-lg font-extrabold text-[#EDEDED] mb-2">CI/CD Integration is a Pro Feature</h2>
            <p className="text-sm text-[#A1A1AA] leading-relaxed">
              Automate your release gate with GitHub Actions, Policy-as-Code enforcement, and CLI integration.
              Available on <span className="text-white font-semibold">Pro</span> and <span className="text-white font-semibold">Enterprise</span> plans.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3 w-full max-w-xs">
            <button
              onClick={() => onOpenCheckout?.('Pro')}
              className="flex-1 flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white text-black text-sm font-extrabold hover:bg-neutral-200 transition-colors"
            >
              <ArrowRight size={15} />
              Upgrade to Pro
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 w-full max-w-lg mt-2">
            {['GitHub Actions Workflow', 'Policy-as-Code Config', 'HTTP Gate API', 'Job Summary', 'SARIF Export', 'Zero-Config Setup'].map((feat) => (
              <div key={feat} className="flex items-center gap-2 p-3 rounded-xl bg-[#0A0A0A] border border-white/10 text-left">
                <ShieldCheck size={13} className="text-emerald-400 shrink-0" />
                <span className="text-[11px] text-[#A1A1AA] font-mono">{feat}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Full CI/CD content — Pro+ only */}
      {isCicdViewAllowed(userTier) && (
      <>      {/* Header Info */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
              <Terminal size={22} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] m-0">
                Zelsis CI/CD &amp; CLI Automation Hub
              </h1>
              <span className="text-[11px] font-mono font-bold text-zinc-400 uppercase tracking-widest">
                GitHub Actions · Git Hooks · Policy-as-Code · Automated PR Bot
              </span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            Shift deployment gates left into your active developer pipeline. Automatically enforce security, privacy compliance, and infrastructure checks on every Pull Request before code merges to production.
          </p>
        </div>

        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-zinc-200 text-xs font-mono font-bold">
          <GitPullRequest size={16} className="text-zinc-400" />
          <span>CI/CD Gate: READY</span>
        </div>
      </div>

      {/* Fail Strategy Threshold Control */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6">
        <h2 className="text-sm font-bold text-[#EDEDED] tracking-tight mb-4">
          Smart Fail Threshold Strategy
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <button
            onClick={() => setFailThreshold('smart')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'smart'
                ? 'bg-white/[0.08] border-white/30 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-white">Smart Mode (Recommended)</span>
              <span className="text-[10px] font-mono bg-white/10 text-zinc-300 px-2 py-0.5 rounded">High Velocity</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Strictly blocks PR merge on <strong className="text-white">CRITICAL</strong> Security, Legal, or Database violations. Posts informational markdown checklists for VibePolish warnings without breaking builds.
            </p>
          </button>

          <button
            onClick={() => setFailThreshold('strict')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'strict'
                ? 'bg-amber-500/10 border-amber-500/40 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-amber-400">Strict Enforcement</span>
              <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded">Zero Tolerance</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Fails the PR build if overall readiness score drops below <strong className="text-white">{minScore}/100</strong> or if any High/Medium issues remain unaccepted.
            </p>
          </button>

          <button
            onClick={() => setFailThreshold('advisory')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'advisory'
                ? 'bg-blue-500/10 border-blue-500/40 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-blue-400">Advisory / Audit Only</span>
              <span className="text-[10px] font-mono bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">Observation</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Never fails PR builds. Runs complete static AST audits and publishes an official Release Scorecard report directly as a PR comment.
            </p>
          </button>
        </div>

        {failThreshold === 'strict' && (
          <div className="bg-black/40 border border-white/5 rounded-xl p-4 flex items-center justify-between gap-4">
            <div className="text-xs text-zinc-400">
              <span className="font-bold text-white block mb-0.5">Minimum Required Score Threshold:</span>
              <span>PRs with score lower than {minScore}/100 will fail the CI check.</span>
            </div>
            <div className="flex items-center gap-3">
              <input
                id="min-score-slider"
                name="minScore"
                type="range"
                min="60"
                max="95"
                value={minScore}
                aria-label="Minimum Required Score Threshold"
                onChange={(e) => setMinScore(Number(e.target.value))}
                className="w-32 accent-white cursor-pointer focus-visible:ring-1 focus-visible:ring-white/20"
              />
              <span className="font-mono font-bold text-white text-sm">{minScore} / 100</span>
            </div>
          </div>
        )}
      </div>

      {/* GitHub Actions Workflow Block */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-sm font-mono font-bold text-[#EDEDED] m-0">
              .github/workflows/zelsis.yml
            </h2>
            <span className="text-xs text-[#A1A1AA]">
              Drop this file into your repository to enforce pre-flight PR gates automatically.
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => copyToClipboard(generateGithubWorkflow(), setCopiedWorkflow)}
              className="btn btn-secondary btn-sm flex items-center gap-1.5"
            >
              {copiedWorkflow ? <CheckCircle2 size={13} className="text-emerald-400" /> : <Copy size={13} />}
              <span>{copiedWorkflow ? 'Copied' : 'Copy Workflow'}</span>
            </button>
            <button
              onClick={() => downloadFile('zelsis.yml', generateGithubWorkflow())}
              className="btn btn-secondary btn-sm flex items-center gap-1.5"
            >
              <Download size={13} />
              <span>Download</span>
            </button>
            {project && (
              <button
                onClick={() => exportProjectSarifReport(project)}
                className="btn btn-secondary btn-sm flex items-center gap-1.5"
                title="Download standard OASIS SARIF v2.1.0 for GitHub Code Scanning"
              >
                <FileCode size={13} className="text-cyan-400" />
                <span>Export SARIF</span>
              </button>
            )}
          </div>
        </div>

        <div className="bg-black/80 border border-white/5 rounded-xl p-4 overflow-x-auto font-mono text-xs">
          <pre className="text-zinc-200 leading-relaxed m-0">{generateGithubWorkflow()}</pre>
        </div>
      </div>

      {/* GitHub App & PR Bot Integration (New for Step 5) */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <h2 className="text-base font-bold text-[#EDEDED] m-0">
              Zelsis GitHub App & Automated PR Bot
            </h2>
            <span className="text-[10px] font-mono bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">Native App</span>
          </div>
          <p className="text-xs text-[#A1A1AA] leading-relaxed max-w-xl">
            Skip the YAML. Install the official Zelsis GitHub App to automatically comment on pull requests, block merges on critical vulnerabilities, and provide inline code suggestions without touching your repository's workflow files.
          </p>
        </div>
        <div className="shrink-0 flex flex-col gap-2 w-full md:w-auto">
          <button className="btn bg-white text-black hover:bg-neutral-200 text-sm font-bold flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl transition-colors">
            <GitPullRequest size={16} />
            Install GitHub App
          </button>
          <p className="text-[10px] text-zinc-400 text-center font-mono">Requires Repo Admin rights</p>
        </div>
      </div>

      {/* Shareable Reports & README Badges */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6">
        <h2 className="text-sm font-bold text-[#EDEDED] tracking-tight mb-4">
          Shareable Report Links & README Badges
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-black/40 border border-white/5 rounded-xl p-4">
            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block mb-2">
              Public Dashboard Link
            </span>
            <p className="text-xs text-zinc-400 mb-3">Share a read-only view of your project's security and quality posture with clients, auditors, or the public.</p>
            <div className="flex items-center gap-2">
              <input 
                type="text" 
                readOnly 
                aria-label="Public Dashboard Link"
                value={`https://zelsis.com/report/${project?.id || 'demo'}`} 
                className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-300 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
              />
              <button 
                onClick={() => copyToClipboard(`https://zelsis.com/report/${project?.id || 'demo'}`, () => {})}
                className="btn btn-secondary p-2 rounded-lg"
                aria-label="Copy public dashboard link"
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
          <div className="bg-black/40 border border-white/5 rounded-xl p-4">
            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block mb-2">
              Markdown Badge (README.md)
            </span>
            <div className="mb-3">
              <Image src={`https://img.shields.io/badge/Zelsis_Score-${minScore}%25-emerald?style=flat-square`} alt="Zelsis Score" width={100} height={20} className="h-5 w-auto" unoptimized />
            </div>
            <div className="flex items-center gap-2">
              <input 
                type="text" 
                readOnly 
                aria-label="Markdown Badge"
                value={`[![Zelsis Score](https://img.shields.io/badge/Zelsis_Score-${minScore}%25-emerald?style=flat-square)](https://zelsis.com/report/${project?.id || 'demo'})`} 
                className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-300 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
              />
              <button 
                onClick={() => copyToClipboard(`[![Zelsis Score](https://img.shields.io/badge/Zelsis_Score-${minScore}%25-emerald?style=flat-square)](https://zelsis.com/report/${project?.id || 'demo'})`, () => {})}
                className="btn btn-secondary p-2 rounded-lg"
                aria-label="Copy markdown badge"
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Section: Policy as Code & Local CLI */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Policy as Code .zelsisrc.json */}
        <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-3 mb-3">
              <h2 className="text-sm font-mono font-bold text-[#EDEDED] m-0">
                Policy as Code (.zelsisrc.json)
              </h2>
              <button
                onClick={() => copyToClipboard(generateZelsisConfig(), setCopiedConfig)}
                className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-[#EDEDED] text-xs font-mono transition-colors flex items-center gap-1"
              >
                {copiedConfig ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Copy size={12} />}
                <span>{copiedConfig ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <p className="text-xs text-[#A1A1AA] mb-4 leading-relaxed">
              Standardize governance across your engineering team by checking in your custom gate requirements.
            </p>
            <div className="bg-black/60 border border-white/5 rounded-xl p-3.5 overflow-x-auto font-mono text-xs mb-4">
              <pre className="text-zinc-200 leading-relaxed m-0">{generateZelsisConfig()}</pre>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 pt-3 border-t border-white/5">
            {Object.keys(enabledGates).length === 0 ? (
              <p className="text-xs text-zinc-400">No gates configured.</p>
            ) : (
              Object.keys(enabledGates).map((gateKey) => {
                const k = gateKey as keyof typeof enabledGates;
                return (
                  <label key={k} htmlFor={`gate-toggle-${k}`} className="flex items-center gap-2 cursor-pointer text-xs font-mono text-zinc-300">
                    <input
                      id={`gate-toggle-${k}`}
                      name={`gate-${k}`}
                      type="checkbox"
                      checked={enabledGates[k]}
                      aria-label={`Toggle ${k} gate`}
                      onChange={(e) => setEnabledGates({ ...enabledGates, [k]: e.target.checked })}
                      className="rounded accent-white cursor-pointer focus-visible:ring-1 focus-visible:ring-white/20"
                    />
                    <span className="capitalize">{k}</span>
                  </label>
                );
              })
            )}
          </div>
        </div>

        {/* Local CLI Command & Pre-commit Hooks */}
        <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-[#EDEDED] tracking-tight mb-3">
              Advanced CLI Tools &amp; Local Hooks
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-4 leading-relaxed">
              Scan locally in any language environment (Node, Python, Go, Ruby).
            </p>

            <div className="bg-black/60 border border-white/5 rounded-xl p-4 mb-4">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block mb-2">
                1. Multi-Language Local Audit
              </span>
              <div className="flex items-center justify-between gap-2 font-mono text-xs text-zinc-300">
                <code className="text-white">zelsis audit --lang=auto --strict</code>
                <button
                  onClick={() => copyToClipboard('zelsis audit --lang=auto --strict', setCopiedCli)}
                  className="p-1 hover:text-white transition-colors"
                  title="Copy CLI command"
                >
                  {copiedCli ? <CheckCircle2 size={14} className="text-emerald-400" /> : <Copy size={14} />}
                </button>
              </div>
            </div>

            <div className="bg-black/60 border border-white/5 rounded-xl p-4">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block mb-2">
                2. Install Git Pre-Commit Hook
              </span>
              <pre className="font-mono text-xs text-zinc-300 leading-relaxed m-0 overflow-x-auto">
{`zelsis install-hook pre-commit`}
              </pre>
            </div>
          </div>

          <div className="text-xs font-mono text-zinc-400 pt-4 mt-4 border-t border-white/5 flex items-center gap-2">
            <ShieldCheck size={14} className="text-emerald-400 shrink-0" />
            <span>Works with Python (pip), Node (npm), Go, and Ruby (gem).</span>
          </div>
        </div>
      </div>
    </> /* end Pro+ content */
    )}
  </div>
  );
};
