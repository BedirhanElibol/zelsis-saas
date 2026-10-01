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

export const WorkflowSteps: React.FC = () => {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      number: '01',
      badge: 'INGESTION & PRIVACY',
      title: 'Target Ingestion & Zero-Retention Memory Stream',
      description:
        'Connect any public or private GitHub repository, pull request branch, or direct code snippet. Our engine inspects syntax tokens & structural rules in ephemeral serverless memory.',
      codeSnippet: `// 1. Ingest via CLI, GitHub Action or Web Dashboard
$ zelsis evaluate --repo github.com/enterprise/payment-gateway
[INFO] Ephemeral security stream opened. 
[PRIVACY] Zero-retention enabled: In-memory evaluation only. No code written to disk.`,
      features: [
        'Zero-retention architecture (code is never permanently stored)',
        'Full monorepo & multi-platform support (Web, Cloud, iOS, Android)',
        'Native GitHub Action & pre-commit hook integration'
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
        'OWASP Top 10, CWE-22, SSRF, and RLS vulnerability detection',
        'WCAG 2.2 AA keyboard accessibility & Core Web Vitals profiling',
        'Docker root user, Kubernetes QoS, and connection pool defense'
      ]
    },
    {
      number: '03',
      badge: 'RELEASE CLEARANCE',
      title: 'Signed Manifest Clearance & 1-Click Fixes',
      description:
        'Generate an exportable cryptographic release manifest for SOC 2 readiness/evidence support, and retrieve surgical 1-click AI prompt patches ready for any AI coding assistant.',
      codeSnippet: `// Cryptographically Signed Deployment Manifest
{
  "manifestId": "MANIFEST-PROD-2026-X99",
  "readinessScore": 94,
  "gateStatus": "PASSED",
  "auditChecksum": "sha256-e3b0c44298fc1c149afbf4c8996fb924",
  "compliance": ["SOC2_READINESS", "ISO27001_A12"],
  "signature": "SIGNED_BY_ZELSIS_RELEASE_AUTHORITY"
}`,
      features: [
        'Exportable release manifest (JSON / CSV) for change control records',
        'Pre-formatted AI remediation prompts for instant PR fixes',
        'Embeddable dynamic Markdown badges for repository READMEs'
      ]
    }
  ];

  if (steps.length === 0) return null;

  return (
    <section id="workflow" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center text-xs font-mono uppercase tracking-widest text-zinc-400">
            <span>OPERATIONAL ARCHITECTURE</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            How Zelsis Protects Production
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed">
            Eliminate human oversight. Our deterministic pipeline delivers comprehensive release gate verification in the time it takes to review a single pull request line.
          </p>
        </div>

        {/* Step Selector Pills */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {steps.map((step, idx) => (
            <button
              key={step.badge}
              onClick={() => setActiveStep(idx)}
              className={`p-6 rounded-xl text-left border transition-all flex flex-col justify-between gap-4 cursor-pointer ${
                activeStep === idx
                  ? 'bg-[#141414] border-white/30 shadow-xl'
                  : 'bg-[#0E0E10] border-white/5 hover:border-white/15 opacity-75 hover:opacity-100'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border transition-colors ${
                  activeStep === idx 
                    ? 'bg-white/10 text-white border-white/20 font-bold' 
                    : 'bg-white/[0.04] text-zinc-400 border-white/5'
                }`}>
                  {step.badge}
                </span>
              </div>
              <div>
                <h3 className="text-sm font-bold text-white mb-1">
                  {step.title}
                </h3>
                <p className="text-xs text-zinc-400 line-clamp-2 leading-relaxed">
                  {step.description}
                </p>
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
