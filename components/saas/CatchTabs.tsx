'use client';

import React, { useEffect, useRef, useState } from 'react';
import { m, useReducedMotion } from 'framer-motion';
import { AlertCircle, ShieldCheck } from 'lucide-react';
import { LANDING_CHECKS, type LandingCategory } from '@/data/landing-checks';

/** Tab order on the page; a category with no checks is left out. */
const CATEGORIES: LandingCategory[] = ['Payments', 'Security', 'Performance', 'Screens', 'AI features', 'Looks unfinished'];
const CYCLE_MS = 7000;

/** What Zelsis catches, one category per tab. Every example is scanned on each release (tests/unit/landing-checks.test.ts). */
export function CatchTabs() {
  const tabs = CATEGORIES.map((c) => ({ category: c, checks: LANDING_CHECKS.filter((x) => x.category === c) })).filter((t) => t.checks.length > 0);
  const [active, setActive] = useState(0);
  const [pick, setPick] = useState(0);
  // Auto-advance stops for good once the visitor picks a tab, and pauses while they hover or focus the panel
  const [userChose, setUserChose] = useState(false);
  const [paused, setPaused] = useState(false);
  const reduceMotion = useReducedMotion();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const cycling = !userChose && !paused && !reduceMotion;

  useEffect(() => {
    if (!cycling) return;
    const t = setTimeout(() => { setActive((a) => (a + 1) % tabs.length); setPick(0); }, CYCLE_MS);
    return () => clearTimeout(t);
  }, [cycling, active, tabs.length]);

  const choose = (i: number) => { setActive(i); setPick(0); setUserChose(true); };
  const onTabKey = (e: React.KeyboardEvent) => {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = (active + step + tabs.length) % tabs.length;
    choose(next);
    tabRefs.current.at(next)?.focus();
  };

  const tab = tabs.at(active) ?? tabs[0];
  const check = tab.checks.at(pick) ?? tab.checks[0];

  return (
    <section id="specifics" className="py-12 sm:py-14 px-4 sm:px-6 lg:px-10 bg-[#0A0A0A] border-t border-white/5">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-4 mb-8">
          <div className="max-w-2xl">
            <p className="text-xs font-mono uppercase tracking-widest text-emerald-400 mb-3">What it catches</p>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">Real bugs, caught in real code.</h2>
          </div>
          <p className="text-sm text-zinc-400 max-w-md">
            Every example below is scanned by our test suite on each release, so what you see is what the engine catches.
          </p>
        </div>

        <div
          role="tablist"
          aria-label="Bug categories"
          onKeyDown={onTabKey}
          className="flex gap-1 overflow-x-auto [scrollbar-width:none] border-b border-white/10"
        >
          {tabs.map((t, i) => {
            const selected = i === active;
            return (
              <button
                key={t.category}
                ref={(el) => { tabRefs.current[i] = el; }}
                role="tab"
                id={`catch-tab-${i}`}
                aria-selected={selected}
                aria-controls="catch-panel"
                tabIndex={selected ? 0 : -1}
                onClick={() => choose(i)}
                className={`relative shrink-0 px-4 min-h-11 text-sm font-medium transition-colors cursor-pointer ${selected ? 'text-white' : 'text-zinc-400 hover:text-zinc-200'}`}
              >
                {t.category}
                <span className="absolute inset-x-0 -bottom-px h-0.5 bg-white/10" aria-hidden="true">
                  {selected && (
                    <m.span
                      key={`${active}-${cycling}`}
                      className="block h-full bg-emerald-400"
                      initial={{ width: cycling ? '0%' : '100%' }}
                      animate={{ width: '100%' }}
                      transition={{ duration: cycling ? CYCLE_MS / 1000 : 0, ease: 'linear' }}
                    />
                  )}
                </span>
              </button>
            );
          })}
        </div>

        <div
          id="catch-panel"
          role="tabpanel"
          aria-labelledby={`catch-tab-${active}`}
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
          onFocus={() => setPaused(true)}
          onBlur={() => setPaused(false)}
          className="grid grid-cols-1 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] gap-6 pt-8"
        >
          <div className="flex flex-col gap-3 min-w-0">
            {tab.checks.map((c, i) => {
              const on = c === check;
              return (
                <button
                  key={c.ruleId}
                  type="button"
                  onClick={() => { setPick(i); setUserChose(true); }}
                  aria-pressed={on}
                  className={`text-left rounded-xl border p-4 transition-colors cursor-pointer ${on ? 'border-white/25 bg-[#141414]' : 'border-white/10 hover:border-white/20'}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <h3 className="font-semibold text-white">{c.title}</h3>
                    <span className="shrink-0 px-2 py-0.5 rounded bg-white/5 text-[0.68rem] font-mono text-zinc-300">{c.code}</span>
                  </div>
                  {on && <p className="mt-2 text-sm text-zinc-400">{c.description}</p>}
                </button>
              );
            })}
          </div>

          <m.div
            key={check.ruleId}
            initial={reduceMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="rounded-xl border border-white/10 bg-[#0E0E10] p-4 text-xs font-mono leading-relaxed min-w-0"
          >
            <div className="text-zinc-500 mb-3 truncate">{check.path}</div>
            <div className="text-red-400 mb-1.5 flex items-center gap-2">
              <AlertCircle className="w-3 h-3" aria-hidden="true" /> Flagged
            </div>
            <pre className="text-zinc-400 mb-4 overflow-x-auto [scrollbar-width:thin] [scrollbar-color:#3f3f46_transparent]"><code>{check.bad}</code></pre>
            <div className="text-emerald-400 mb-1.5 flex items-center gap-2">
              <ShieldCheck className="w-3 h-3" aria-hidden="true" /> Passes
            </div>
            <pre className="text-zinc-200 overflow-x-auto [scrollbar-width:thin] [scrollbar-color:#3f3f46_transparent]"><code>{check.good}</code></pre>
          </m.div>
        </div>
      </div>
    </section>
  );
}
