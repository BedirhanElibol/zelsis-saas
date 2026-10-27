'use client';

import React, { useState } from 'react';
import { m } from 'framer-motion';
import { ArrowRight, Terminal, Loader2, GitPullRequest } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { normalizeRepoUrl } from '@/lib/github-api';
import { ScanPreviewCard, ScanPreviewResult } from '@/components/saas/ScanPreviewCard';
import { HeroGateMock } from './HeroGateMock';
import { CODE_RETENTION_SHORT } from '@/lib/data-retention';

/** Only stacks with their own rules and a benchmark project. */
const WORKS_WITH = [
  'JavaScript & TypeScript (Next.js, React, Express)',
  'Python (Django, FastAPI, Flask)',
  'Go',
  'Ruby on Rails',
  'PHP & Laravel',
  'Java & Spring',
  'C# & ASP.NET Core',
  'Rust',
  'iOS & Android (Swift, Kotlin, Flutter, React Native)',
  'Supabase, Firebase & Postgres',
  'Docker, Kubernetes & Terraform',
  'GitHub Actions & GitLab CI',
];

interface SaasHeroProps {
  onOpenDashboard?: (repoUrl?: string) => void;
}

export const SaasHero: React.FC<SaasHeroProps> = ({ onOpenDashboard }) => {
  const router = useRouter();
  const [repoInput, setRepoInput] = useState('vercel/nextjs-subscription-payments');
  const [isScanning, setIsScanning] = useState(false);

  const sampleRepos = [
    { label: 'Next.js + Supabase', value: 'vercel/nextjs-subscription-payments' },
    { label: 'Express (Node)', value: 'gothinkster/node-express-realworld-example-app' },
    { label: 'FastAPI (Python)', value: 'fastapi/full-stack-fastapi-template' },
    { label: 'Go (Gin)', value: 'gothinkster/golang-gin-realworld-example-app' },
    { label: 'Laravel (PHP)', value: 'laravel/laravel' }
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
    <section className="relative pt-24 sm:pt-28 pb-14 px-4 sm:px-6 lg:px-10 bg-[#0A0A0A] border-b border-white/10">
      <div className="relative z-10 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] gap-10 lg:gap-14 items-center">
          {/* Left: the promise and the way in */}
          <div className="flex flex-col items-start text-left min-w-0">
            <p className="text-xs font-mono uppercase tracking-widest text-emerald-400 mb-5">Release check for every pull request</p>
            {/* Plain elements: the headline is the LCP, so it must not wait for hydration to fade in */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-[#EDEDED] tracking-tight leading-[1.05] [text-wrap:balance]">
              Catch the bug that <span className="text-emerald-400">costs you customers,</span> before you merge.
            </h1>
            <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed mt-6 max-w-xl">
              Zelsis reads every pull request for what users notice first: double charges, leaked keys, slow pages, screens that break, and template leftovers that make an app look unfinished. If something critical gets in, the build fails before it ships.
            </p>

            {/* Direct Repository Scan Command Bar */}
            <div className="w-full max-w-xl mt-8">
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
                    className="w-full bg-transparent text-sm font-mono text-[#EDEDED] placeholder-zinc-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-white/70 rounded px-1"
                    aria-label="GitHub Repository to Scan"
                  />
                </div>
                <button
                  type="submit"
                  data-track="hero-scan"
                  disabled={isScanning}
                  className="px-5 min-h-11 rounded-lg text-xs font-bold font-mono uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400 transition-all flex items-center justify-center gap-2 shrink-0 shadow-sm active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                >
                  {isScanning ? <Loader2 size={13} className="animate-spin" /> : null}
                  <span>{isScanning ? 'Scanning…' : 'See what’s in your repo'}</span>
                  {!isScanning && <ArrowRight size={13} />}
                </button>
              </form>

              {/* Minimal 1-Click Preset Chips */}
              <div className="flex flex-wrap items-center gap-2 mt-3.5 text-xs">
                <span className="text-zinc-400 text-xs font-mono uppercase tracking-wider">Try:</span>
                {sampleRepos.map((r) => (
                  <button
                    key={r.value}
                    type="button"
                    onClick={() => handleSelectAndScan(r.value)}
                    title={`Run instant audit on ${r.value}`}
                    aria-pressed={repoInput === r.value}
                    className={`text-xs font-mono px-3 min-h-11 sm:min-h-9 rounded-md border transition-all cursor-pointer flex items-center gap-1.5 ${
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
            </div>

            {/* Trust line */}
            <ul className="flex flex-wrap items-center gap-x-6 gap-y-2 mt-7 text-xs text-zinc-400 font-mono">
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/70" />
                <a href="/privacy" className="hover:text-white transition-colors">{CODE_RETENTION_SHORT}</a>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/70" />
                <a href="#benchmark" className="inline-flex items-center min-h-[24px] hover:text-white transition-colors">Benchmark published, misses included</a>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/70" />
                <span>No account needed · one flat price, not per developer</span>
              </li>
            </ul>
          </div>

          {/* Right: what a failing pull request looks like */}
          <m.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="w-full min-w-0 relative rounded-xl border border-white/10 bg-[#121212] shadow-2xl overflow-hidden text-left"
          >
            <div className="flex items-center justify-between gap-3 px-4 py-3 bg-[#0E0E10] border-b border-white/10">
              <div className="flex items-center gap-2 min-w-0 text-xs font-mono text-zinc-300">
                <GitPullRequest size={14} className="text-zinc-400 shrink-0" />
                <span className="truncate">Pull request · Zelsis release check</span>
              </div>
              <span className="shrink-0 inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono uppercase bg-white/[0.04] text-zinc-300 border border-white/10">
                Example scan
              </span>
            </div>

            {/* Example result: a failing gate with findings */}
            <HeroGateMock />

            <div className="flex items-center justify-between gap-3 px-4 py-2.5 bg-[#0E0E10] border-t border-white/10 text-xs font-mono text-zinc-400">
              <span className="truncate">Only proven critical findings block a merge</span>
              <button
                onClick={() => {
                  if (onOpenDashboard) onOpenDashboard();
                  else router.push('/dashboard');
                }}
                className="shrink-0 text-zinc-300 hover:text-white flex items-center gap-1 transition-colors cursor-pointer min-h-[24px]"
              >
                <span>Open the console</span>
                <ArrowRight size={11} />
              </button>
            </div>
          </m.div>
        </div>

        {preview && (
          <div className="mt-10 flex justify-center">
            <ScanPreviewCard result={preview} onUnlock={handleUnlockFullReport} />
          </div>
        )}

        {/* Supported Stacks Band */}
        <div className="w-full mt-14 pt-6 border-t border-white/10 flex flex-col sm:flex-row sm:items-start gap-3 sm:gap-6">
          <span className="text-xs font-mono uppercase tracking-widest text-zinc-400 shrink-0 sm:pt-0.5">
            Works with
          </span>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-zinc-400">
            {WORKS_WITH.map((s) => (
              <span key={s} className="hover:text-white transition-colors">{s}</span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};
