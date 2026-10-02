'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  GitPullRequest, 
  ShieldAlert, 
  FileCheck, 
  ArrowRight, 
  Cpu, 
  Lock, 
  ExternalLink 
} from 'lucide-react';
import { getConfiguredAppUrl } from '@/lib/app-url';

export const WorkflowSteps: React.FC = () => {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      number: '01',
      badge: 'CONNECT & PRIVACY',
      title: 'Connect a Repository, Scanned In Memory',
      description:
        'Paste a public GitHub repository, or connect private ones with a read-only GitHub token. Files are fetched into worker memory, scanned, and released: we keep the findings, never your source.',
      codeSnippet: `# From the dashboard, or from any CI runner with one HTTP call
$ curl -X POST ${getConfiguredAppUrl()}/api/v1/gate-check \\
    -H "Content-Type: application/json" \\
    -d '{"repoUrl": "your-org/your-app"}'
{"gateStatus": "PASSED", "readinessScore": 94, ...}`,
      features: [
        'Source code is never stored: only findings with short snippets',
        'Public repositories instantly, private ones with a read-only token',
        'GitHub Actions, GitLab CI and pre-commit configs generated for you'
      ]
    },
    {
      number: '02',
      badge: 'DEEP RELEASE AUDIT',
      title: 'Real-Time Evaluation Across Security & Architecture Vectors',
      description:
        'Deterministic release rules inspect your application layers simultaneously, isolating regressions before staging or production builds.',
      codeSnippet: `[EVALUATING PRODUCTION RELEASE GATES]
  [PASS] SEC-01: No hardcoded client secrets detected ......... PASSED
  [PASS] SEC-03: PostgreSQL Row Level Security enforces auth .. PASSED
  [FAIL] UI-15: Non-semantic clickable container in SearchBox . FAILED
  [PASS] INFRA-02: Container runs as dedicated non-root user .. PASSED
[SCORE] 94/100 PRODUCTION READINESS ACHIEVED`,
      features: [
        'OWASP Top 10, SSRF, injection, leaked secrets and Supabase RLS checks',
        'Known-vulnerable dependencies looked up in OSV.dev from your lockfiles',
        'WCAG 2.2 accessibility, Docker and Kubernetes misconfiguration checks'
      ]
    },
    {
      number: '03',
      badge: 'RELEASE CLEARANCE',
      title: 'Gate the Release & Fix in One Click',
      description:
        'Fail the CI job when the gate fails, export the result for change-control records, and copy a ready-made fix prompt for any AI coding assistant.',
      codeSnippet: `# .github/workflows/zelsis.yml (generated in the dashboard)
- name: Zelsis release gate
  run: |
    STATUS=$(curl -s -X POST "$ZELSIS_URL/api/v1/gate-check" \\
      -d '{"repoUrl":"\${{ github.repository }}"}' | jq -r .gateStatus)
    [ "$STATUS" != "FAILED" ] || exit 1`,
      features: [
        'Export results as PDF, JSON, CSV, SARIF or Markdown',
        'Fix prompts with file, line and context for each finding',
        'Live README badge that shows your current gate status'
      ]
    }
  ];

  if (steps.length === 0) return null;

  return (
    <section id="workflow" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center text-xs font-mono uppercase tracking-widest text-emerald-400">
            <span>How it works</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            From repository to release decision
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed">
            Connect a repo, get findings in seconds, and let the gate fail the build when something critical slips in. Your reviewers still decide; Zelsis makes sure they see the risks.
          </p>
        </div>

        {/* Step Selector Pills */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {steps.map((step, idx) => (
            <button
              key={step.badge}
              onClick={() => setActiveStep(idx)}
              aria-pressed={activeStep === idx}
              className={`p-6 rounded-xl text-left border transition-all flex flex-col justify-between gap-4 cursor-pointer ${
                activeStep === idx
                  ? 'bg-[#141414] border-white/30 shadow-xl'
                  : 'bg-[#0E0E10] border-white/5 hover:border-white/15 opacity-75 hover:opacity-100'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className="text-2xl font-extrabold font-mono text-zinc-400">{step.number}</span>
                <span className={`text-xs font-mono uppercase tracking-wider px-2 py-0.5 rounded border transition-colors ${
                  activeStep === idx 
                    ? 'bg-white/10 text-white border-white/20 font-bold' 
                    : 'bg-white/[0.04] text-zinc-400 border-white/5'
                }`}>
                  {step.badge}
                </span>
              </div>
              <div>
                <h3 className="text-base font-bold text-white">
                  {step.title}
                </h3>
              </div>
            </button>
          ))}
        </div>

        {/* Active Step Detailed Showcase Panel */}
        <div className="rounded-2xl border border-white/15 bg-[#121212] p-6 sm:p-10 shadow-2xl grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Left Column: Technical Context & Highlights (6 cols) */}
          <div className="lg:col-span-6 flex flex-col gap-6">
            <div className="text-xs font-mono uppercase tracking-wider text-zinc-400">
              <span>{steps[activeStep].badge}</span>
            </div>

            <h3 className="text-2xl sm:text-3xl font-extrabold text-white leading-tight">
              {steps[activeStep].title}
            </h3>

            <p className="text-sm text-zinc-400 leading-relaxed font-sans">
              {steps[activeStep].description}
            </p>

            <ul className="flex flex-col gap-3 pt-4 border-t border-white/10">
              {steps[activeStep].features.map((feat, i) => (
                <li key={i} className="flex items-start gap-3 text-xs sm:text-sm text-zinc-300">
                  <span className="text-zinc-400 font-mono text-xs select-none shrink-0 mt-0.5">—</span>
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Right Column: Code Terminal Simulation (6 cols) */}
          <div className="lg:col-span-6 rounded-xl border border-white/10 bg-[#0A0A0A] overflow-hidden shadow-inner">
            <div className="flex items-center justify-between px-4 py-3 bg-[#141414] border-b border-white/10 text-xs font-mono text-zinc-400">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-zinc-300 font-semibold">terminal://runtime-eval</span>
              </div>
              <span className="text-[10px] text-zinc-400">BASH / JSON</span>
            </div>
            <pre className="p-4 sm:p-6 text-[11px] sm:text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed whitespace-pre font-normal selection:bg-white/20">
              {steps[activeStep].codeSnippet}
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
};
