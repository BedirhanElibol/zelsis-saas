'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, 
  ArrowRight, 
  Terminal, 
  Play, 
  CheckCircle2, 
  ExternalLink,
  Lock,
  Loader2
} from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { normalizeRepoUrl } from '@/lib/github-api';
import { ScanPreviewCard, ScanPreviewResult } from '@/components/saas/ScanPreviewCard';

interface SaasHeroProps {
  onOpenDashboard?: (repoUrl?: string) => void;
}

export const SaasHero: React.FC<SaasHeroProps> = ({ onOpenDashboard }) => {
  const router = useRouter();
  const [repoInput, setRepoInput] = useState('expressjs/express');
  const [isScanning, setIsScanning] = useState(false);

  const sampleRepos = [
    { label: 'Express.js (Node)', value: 'expressjs/express' },
    { label: 'FastAPI (Python)', value: 'tiangolo/fastapi' },
    { label: 'Spring Boot (Java)', value: 'spring-projects/spring-boot' },
    { label: 'Gin (Go)', value: 'gin-gonic/gin' },
    { label: 'React Native', value: 'facebook/react-native' }
  ];

  const [preview, setPreview] = useState<ScanPreviewResult | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  // Signup-free teaser: summary only; full report needs an account
  const runPreview = async (val: string) => {
    const clean = val.trim();
    if (!clean || isScanning) return;
    setIsScanning(true);
    setPreview(null);
    setPreviewError(null);
    try {
      const res = await fetch('/api/v1/scans/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: normalizeRepoUrl(clean) }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data) {
        setPreviewError(data?.error || 'Preview scan failed. Please try again.');
        return;
      }
      setPreview(data as ScanPreviewResult);
    } catch {
      setPreviewError('Network error. Check your connection and try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectAndScan = (val: string) => {
    setRepoInput(val);
    runPreview(val);
  };

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    runPreview(repoInput);
  };

  const handleUnlockFullReport = () => {
    const repoUrl = preview?.repoUrl || normalizeRepoUrl(repoInput.trim());
    try {
      // Survives the OAuth round-trip, which drops query params
      sessionStorage.setItem('zelsis_pending_repo', repoUrl);
    } catch {
      // sessionStorage unavailable; the query param still carries the repo
    }
    router.push(`/dashboard?auth=signup&repo=${encodeURIComponent(repoUrl)}&scan=true`);
  };

  return (
    <section className="relative min-h-[90vh] flex flex-col justify-start pt-28 sm:pt-36 pb-20 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="relative z-10 max-w-6xl mx-auto w-full flex flex-col items-center text-center">
        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-[#EDEDED] tracking-tight leading-[1.06] max-w-5xl mb-6"
        >
          The Pre-Flight Release Gate for <br className="hidden sm:inline" />
          <span className="text-white">Modern Web &amp; Cloud Applications.</span>
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="text-base sm:text-lg lg:text-xl text-[#A1A1AA] max-w-3xl mx-auto leading-relaxed mt-6 mb-10 font-sans font-normal"
        >
          Stop fatal production regressions before they merge. Zelsis automatically evaluates critical OWASP security vulnerabilities, database RLS leaks, UI/UX accessibility, and cloud container configurations in memory before code reaches production.
        </motion.p>

        {/* Direct Repository Scan Command Bar */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="w-full max-w-2xl mb-6"
        >
          <form 
            onSubmit={handleStartScan}
            className="flex flex-col sm:flex-row items-stretch gap-2 p-1.5 rounded-xl bg-[#141414] border border-white/10 shadow-2xl focus-within:border-white/30 transition-all"
          >
            <div className="flex items-center gap-2.5 px-3 py-2 flex-1 min-w-0">
              <Terminal size={16} className="text-zinc-400 shrink-0" />
              <span className="text-xs font-mono text-zinc-400 hidden sm:inline">github.com/</span>
              <input
                id="hero-repo-input"
                name="repository"
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                placeholder="owner/repository or public git URL"
                className="w-full bg-transparent text-xs font-mono text-[#EDEDED] placeholder-zinc-500 focus:outline-none focus-visible:ring-1 focus-visible:ring-white/20 rounded px-1"
                aria-label="GitHub Repository to Scan"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning}
              className="px-5 py-2.5 rounded-lg text-xs font-bold font-mono uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 shrink-0 shadow-sm active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isScanning ? <Loader2 size={13} className="animate-spin" /> : null}
              <span>{isScanning ? 'Scanning…' : 'Scan Repository'}</span>
              {!isScanning && <ArrowRight size={13} />}
            </button>
          </form>

          {/* Minimal 1-Click Preset Chips */}
          <div className="flex flex-wrap items-center justify-center gap-2 mt-3.5 text-xs">
            <span className="text-zinc-400 text-[11px] font-mono uppercase tracking-wider">Presets:</span>
            {sampleRepos.map((r) => (
              <button
                key={r.value}
                type="button"
                onClick={() => handleSelectAndScan(r.value)}
                title={`Run instant audit on ${r.value}`}
                className={`text-[11px] font-mono px-2.5 py-1 rounded-md border transition-all cursor-pointer flex items-center gap-1.5 ${
                  repoInput === r.value
                    ? 'border-white/40 bg-white/10 text-white'
                    : 'border-white/10 bg-[#121212] text-zinc-400 hover:text-white hover:border-white/25'
                }`}
              >
                <span>{r.label}</span>
              </button>
            ))}
          </div>

          {previewError && (
            <p role="alert" className="mt-3 text-xs font-mono text-red-400">{previewError}</p>
          )}
        </motion.div>

        {preview && <ScanPreviewCard result={preview} onUnlock={handleUnlockFullReport} />}

        {/* Minimal Engineering Telemetry Ribbon */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.25 }}
          className="flex flex-wrap items-center justify-center gap-6 sm:gap-8 mb-12 text-xs text-zinc-400 font-mono"
        >
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-white/40" />
            <span>Zero-Retention (Ephemeral In-Memory Analysis)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-white/40" />
            <span>Multi-Database (Postgres · MySQL · Mongo · Redis)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-white/40" />
            <span>OASIS SARIF v2.1.0 Native</span>
          </div>
        </motion.div>

        {/* Hero Showcase: Clean Industrial Application Preview Frame */}
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.3 }}
          className="w-full max-w-5xl relative rounded-xl border border-white/10 bg-[#121212] shadow-2xl overflow-hidden text-left"
        >
          {/* Browser Window Chrome Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#0E0E10] border-b border-white/10">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-white/20" />
              <span className="w-2.5 h-2.5 rounded-full bg-white/20" />
              <span className="w-2.5 h-2.5 rounded-full bg-white/20" />
              <div className="ml-3 px-3 py-1 rounded bg-white/[0.04] border border-white/5 text-[11px] font-mono text-zinc-400 flex items-center gap-1.5">
                <Lock size={10} className="text-zinc-400" />
                <span>zelsis.com/dashboard/eval/production-gate</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-medium uppercase bg-white/[0.04] text-zinc-300 border border-white/10">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Gate Status: PASSED (94/100)
              </span>
              <button
                onClick={() => {
                  if (onOpenDashboard) onOpenDashboard();
                  else router.push('/dashboard');
                }}
                className="text-xs font-mono text-zinc-300 hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span>Launch Console</span>
                <ExternalLink size={11} />
              </button>
            </div>
          </div>

          {/* Screenshot Container */}
          <div className="relative aspect-[16/10] sm:aspect-[16/9] w-full bg-[#0A0A0A] overflow-hidden">
            <Image
              src="/images/dashboard_overview.png"
              alt="Zelsis Production Readiness and Security Dashboard Overview"
              fill
              priority
              sizes="(max-width: 1200px) 100vw, 1200px"
              className="object-cover object-top"
            />
          </div>

          {/* Footer Ribbon inside Frame */}
          <div className="px-5 py-2.5 bg-[#0E0E10] border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400">
            <div className="flex items-center gap-4">
              <span>Engine: <strong className="text-zinc-200 font-mono">Lexical &amp; Static Analysis</strong></span>
              <span>Memory: <strong className="text-zinc-200 font-mono">Ephemeral Buffer</strong></span>
              <span>Compliance: <strong className="text-zinc-200 font-mono">OWASP &amp; WCAG 2.2</strong></span>
            </div>
            <div className="flex items-center gap-2 text-zinc-400 text-[11px]">
              <span>Industrial Deployment Readiness Gate</span>
            </div>
          </div>
        </motion.div>

        {/* Supported Stacks Band */}
        <div className="w-full mt-16 pt-8 border-t border-white/10 flex flex-col items-center gap-4">
          <span className="text-xs font-mono uppercase tracking-widest text-zinc-400">
            Calibrated for Enterprise Production Stacks
          </span>
          <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-8 text-xs font-mono text-zinc-400">
            <span className="hover:text-white transition-colors">Next.js 15 (App Router)</span>
            <span className="hover:text-white transition-colors">TypeScript 5.x</span>
            <span className="hover:text-white transition-colors">Python / FastAPI</span>
            <span className="hover:text-white transition-colors">Go Microservices</span>
            <span className="hover:text-white transition-colors">Docker &amp; K8s</span>
            <span className="hover:text-white transition-colors">Swift &amp; Kotlin (Mobile)</span>
          </div>
        </div>
      </div>
    </section>
  );
};
