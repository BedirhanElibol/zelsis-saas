import React from 'react';
import { AlertCircle, ShieldCheck } from 'lucide-react';
import { LANDING_CHECKS } from '@/data/landing-checks';

/** Framework-specific checks, each backed by a scanned example (tests/unit/landing-checks.test.ts). */
export function FrameworkSpecifics() {
  return (
    <section id="specifics" className="py-24 bg-[#0A0A0A] border-t border-white/5 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="max-w-3xl mb-14">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Knows how real apps break.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            Payment webhooks that pay twice, caches that leak one user&apos;s data to another, admin checks anyone can pass,
            endpoints nobody protected. Zelsis checks for the logic mistakes behind real incidents in Node, Python, Go, Ruby, C#, Swift, Kotlin,
            PHP and Java apps. Every example below is scanned by our test suite on each release, so what you see is what the
            engine catches.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {LANDING_CHECKS.map((check) => (
            <article key={check.ruleId} className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden flex flex-col min-w-0">
              <div className="p-5 border-b border-white/5">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <h3 className="font-semibold text-white">{check.title}</h3>
                  <span className="shrink-0 px-2 py-0.5 rounded bg-white/5 text-[0.68rem] font-mono text-zinc-300">{check.code}</span>
                </div>
                <p className="text-sm text-zinc-400">{check.description}</p>
              </div>

              <div className="bg-[#0A0A0A] p-4 text-xs font-mono leading-relaxed flex-grow">
                <div className="text-zinc-500 mb-2 truncate">{check.path}</div>
                <div className="text-red-400 mb-1.5 flex items-center gap-2">
                  <AlertCircle className="w-3 h-3" aria-hidden="true" /> Flagged
                </div>
                <pre className="text-zinc-500 mb-4 overflow-x-auto [scrollbar-width:thin] [scrollbar-color:#3f3f46_transparent]"><code>{check.bad}</code></pre>
                <div className="text-emerald-400 mb-1.5 flex items-center gap-2">
                  <ShieldCheck className="w-3 h-3" aria-hidden="true" /> Passes
                </div>
                <pre className="text-zinc-300 overflow-x-auto [scrollbar-width:thin] [scrollbar-color:#3f3f46_transparent]"><code>{check.good}</code></pre>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
