'use client';

import React from 'react';
import { ArrowRight, Terminal, ShieldCheck, Play } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { CODE_RETENTION_STATEMENT } from '@/lib/data-retention';

export const FinalCta: React.FC = () => {
  const router = useRouter();

  return (
    <section className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-[600px] min-h-[20rem] aspect-[2/1] bg-white/[0.03] blur-[140px] rounded-full pointer-events-none" />

      <div className="max-w-5xl mx-auto rounded-3xl border border-white/20 bg-gradient-to-b from-[#141414] to-[#0E0E10] p-8 sm:p-16 shadow-2xl relative z-10 flex flex-col items-center text-center">
        {/* Release Status Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-white/10 bg-white/5 text-zinc-300 text-xs font-mono mb-6">
          <ShieldCheck size={14} className="text-zinc-400" />
          <span className="uppercase tracking-wider font-semibold text-xs">Free for public repositories</span>
        </div>

        {/* Big Headline */}
        <h2 className="text-3xl sm:text-5xl lg:text-6xl font-extrabold text-[#EDEDED] tracking-tight max-w-3xl leading-[1.1]">
          Know what you are shipping before your users find out.
        </h2>

        {/* Subtitle */}
        <p className="text-base sm:text-lg text-[#A1A1AA] max-w-2xl mx-auto mt-6 mb-10 font-sans leading-relaxed">
          Scan a repository in seconds. {CODE_RETENTION_STATEMENT}
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto">
          <button
            onClick={() => router.push('/dashboard')}
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400 transition-all flex items-center justify-center gap-2.5 shadow-sm active:scale-[0.98] cursor-pointer"
          >
            <Play size={14} fill="currentColor" />
            <span>Scan a repository</span>
          </button>

          <a
            href="#pricing"
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider text-white hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <span>See pricing</span>
            <ArrowRight size={14} />
          </a>
        </div>

        {/* Footnote */}
        <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-8 mt-8 text-xs font-mono text-zinc-400">
          <span>No install, no credit card</span>
          <span>Code scanned in memory, never stored</span>
          <span>Benchmark published, misses included</span>
        </div>
      </div>
    </section>
  );
};
