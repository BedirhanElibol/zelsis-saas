'use client';

import React, { useCallback, useEffect, useState } from 'react';

interface Step { target: string; title: string; body: string }

const STEPS: Step[] = [
  { target: '#header-target-repo-input', title: 'Scan any repository', body: 'Paste a GitHub URL (or your live site) here and press Scan. Public repos are free; for private ones, add a project and connect GitHub.' },
  { target: '[data-tour="gate"]', title: 'Can you ship?', body: 'The release gate says PASSED, WARNING or FAILED, with your readiness score. Critical security issues fail it; logic and UI issues only lower the score.' },
  { target: '[data-tour="findings"]', title: 'What to fix', body: 'Every finding has the file, the line and a fix prompt you can paste into Cursor or Claude. Use the tabs to switch between Security, Logic Bugs and UI.' },
  { target: '[data-tour="nav-cicd"]', title: 'Stop bad releases automatically', body: 'CI/CD sets up a GitHub Action that checks every pull request. You will need an API key from Settings & API Keys.' },
  { target: '[data-tour="help"]', title: 'Lost? Ask here', body: 'Press Help (or Ctrl/Cmd + K) and type what you want to do: "private repo", "API key", "report". It takes you there.' },
];

const DONE_KEY = 'zelsis_tour_done_v1';

/** Five-step first-run walkthrough of the dashboard. Shown once; "Show me around" in Help replays it. */
export function ProductTour({ autoStart }: { autoStart: boolean }) {
  const [index, setIndex] = useState<number | null>(null);
  const [rect, setRect] = useState<DOMRect | null>(null);

  const visibleSteps = useCallback(() => STEPS.filter((s) => {
    const el = document.querySelector(s.target);
    return el && (el as HTMLElement).offsetParent !== null;
  }), []);

  const finish = useCallback(() => {
    setIndex(null);
    try { localStorage.setItem(DONE_KEY, '1'); } catch { /* private mode */ }
  }, []);

  useEffect(() => {
    const start = () => setIndex(0);
    window.addEventListener('zelsis:open-tour', start);
    let t: ReturnType<typeof setTimeout> | undefined;
    if (autoStart) {
      let done = false;
      try { done = localStorage.getItem(DONE_KEY) === '1'; } catch { done = true; }
      if (!done) t = setTimeout(start, 1200);
    }
    return () => { window.removeEventListener('zelsis:open-tour', start); if (t) clearTimeout(t); };
  }, [autoStart]);

  const steps = index === null ? [] : visibleSteps();
  const step = index === null || steps.length === 0 ? null : steps[Math.min(index, steps.length - 1)];

  useEffect(() => {
    if (!step) return;
    const el = document.querySelector(step.target) as HTMLElement | null;
    if (!el) return;
    el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    const measure = () => setRect(el.getBoundingClientRect());
    const t = setTimeout(measure, 350);
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    return () => { clearTimeout(t); window.removeEventListener('resize', measure); window.removeEventListener('scroll', measure, true); };
  }, [step]);

  if (index === null || !step || !rect) return null;

  const below = rect.bottom + 220 < window.innerHeight;
  const top = below ? rect.bottom + 12 : Math.max(12, rect.top - 12 - 190);
  const left = Math.min(Math.max(12, rect.left), window.innerWidth - 332);

  return (
    <div className="fixed inset-0 z-[70]" role="dialog" aria-modal="true" aria-labelledby="tour-title">
      {/* dim everything except the highlighted element */}
      <div
        className="absolute rounded-xl ring-2 ring-emerald-400 pointer-events-none transition-all"
        style={{ top: rect.top - 6, left: rect.left - 6, width: rect.width + 12, height: rect.height + 12, boxShadow: '0 0 0 9999px rgba(0,0,0,0.65)' }}
      />
      <div className="absolute w-[320px] max-w-[calc(100vw-24px)] rounded-xl border border-white/10 bg-[#141414] p-4 shadow-2xl" style={{ top, left }}>
        <p className="m-0 text-[10px] font-mono text-zinc-500">{index + 1} / {steps.length}</p>
        <h3 id="tour-title" className="mt-1 mb-1.5 text-sm font-bold text-white">{step.title}</h3>
        <p className="m-0 text-xs leading-relaxed text-zinc-300">{step.body}</p>
        <div className="mt-3 flex items-center justify-between">
          <button type="button" onClick={finish} className="text-xs text-zinc-400 hover:text-white">Skip tour</button>
          <div className="flex gap-2">
            {index > 0 && (
              <button type="button" onClick={() => setIndex(index - 1)} className="px-3 py-1.5 rounded-lg border border-white/10 text-xs text-white hover:bg-white/5">Back</button>
            )}
            <button
              type="button"
              onClick={() => (index + 1 >= steps.length ? finish() : setIndex(index + 1))}
              className="px-3 py-1.5 rounded-lg bg-emerald-500 text-xs font-bold text-black hover:bg-emerald-400"
            >
              {index + 1 >= steps.length ? 'Got it' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
