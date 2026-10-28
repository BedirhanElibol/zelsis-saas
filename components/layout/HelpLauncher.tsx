'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { HelpCircle, Search, X, ArrowRight } from 'lucide-react';

interface HelpLauncherProps {
  onNavigate: (nav: string) => void;
  onOpenConnect: () => void;
  onFocusScan: () => void;
  onOpenTour?: () => void;
}

/** Lowercase without accents, so "özel" matches "ozel" and "İNDİR" matches "indir". */
const fold = (s: string) => s.toLocaleLowerCase('tr').replace(/ı/g, 'i').normalize('NFD').replace(/[̀-ͯ]/g, '');

interface Task {
  title: string;
  hint: string;
  keywords: string;
  run: () => void;
}

/**
 * "What do you want to do?" launcher (Help button, Ctrl/Cmd+K). People should not need to know which page a
 * feature lives on: they type the task (private repo, CI, API key, report...) and get taken there.
 */
export function HelpLauncher({ onNavigate, onOpenConnect, onFocusScan, onOpenTour }: HelpLauncherProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const tasks: Task[] = useMemo(() => {
    const go = (nav: string) => () => onNavigate(nav);
    return [
    { title: 'Scan a public repository', hint: 'Paste a GitHub URL in the box at the top and press Scan.', keywords: 'scan audit check repo github url analyze tara', run: onFocusScan },
    { title: 'Scan a private repository', hint: 'Add a project and connect GitHub (or paste a read-only token).', keywords: 'private token pat secret access connect github ozel gizli', run: onOpenConnect },
    { title: 'See logic bugs and broken features', hint: 'Bugs that break features: fake submits, dead buttons, wrong dates, money.', keywords: 'logic bug broken feature unfinished fake button form mantik hata', run: () => { onNavigate('dashboard'); setTimeout(() => window.dispatchEvent(new CustomEvent('zelsis:findings-tab', { detail: 'VIBECARE' })), 150); } },
    { title: 'See security findings', hint: 'Leaked keys, auth holes, injection, open database access.', keywords: 'security vulnerability rls supabase secret leak xss guvenlik acik acigi sizinti', run: () => { onNavigate('dashboard'); setTimeout(() => window.dispatchEvent(new CustomEvent('zelsis:findings-tab', { detail: 'SECURITY' })), 150); } },
    { title: 'Block bad releases in CI (GitHub Action)', hint: 'Copy the workflow file and add your API key as a GitHub secret.', keywords: 'ci cd github action workflow pull request pr gate block deploy pipeline', run: go('cicd') },
    { title: 'Get an API key', hint: 'Settings & API Keys: create a key for the CI gate or the API.', keywords: 'api key token settings ci secret anahtar', run: go('settings') },
    { title: 'Download a report or PDF', hint: 'Reports & PDF Export: share the audit with your team or client.', keywords: 'report pdf export download share certificate rapor indir', run: go('lab-briefing') },
    { title: 'Re-run a scan / see past scans', hint: 'Scan History lists every scan; re-run from the dashboard.', keywords: 'history rescan re-run previous old gecmis', run: go('scans') },
    { title: 'Manage my projects', hint: 'Connected Projects: add, switch and remove repositories and sites.', keywords: 'projects repositories add remove switch proje', run: go('projects') },
    { title: 'Fix findings one by one', hint: 'Fix Queue: work through open findings with copy-ready fix prompts.', keywords: 'fix remediate queue prompt patch duzelt', run: go('remediation') },
    { title: 'Change plan or billing', hint: 'Billing & Tiers: compare plans and upgrade.', keywords: 'billing plan upgrade price pro enterprise odeme', run: go('checkout') },
    { title: 'See every rule Zelsis checks', hint: 'The full rule catalog with filters.', keywords: 'rules catalog checks list kural', run: () => router.push('/docs/rules') },
    { title: 'What Zelsis does not check', hint: 'Honest limits of static analysis.', keywords: 'limits boundaries not check sinir', run: () => router.push('/docs/boundaries') },
    ...(onOpenTour ? [{ title: 'Show me around (2-minute tour)', hint: 'A short walkthrough of the dashboard.', keywords: 'tour guide onboarding help start tur rehber', run: onOpenTour }] : []),
    { title: 'Contact support', hint: 'Email us; we usually reply within a day.', keywords: 'support contact help email destek', run: () => { window.location.href = 'mailto:contact@zelsis.com?subject=Zelsis%20help'; } },
  ];
  }, [onNavigate, onOpenConnect, onFocusScan, onOpenTour, router]);

  const results = useMemo(() => {
    const words = fold(query).split(/\s+/).filter(Boolean);
    if (!words.length) return tasks;
    return tasks.filter((t) => {
      const hay = fold(`${t.title} ${t.hint} ${t.keywords}`);
      return words.every((w) => hay.includes(w));
    });
  }, [query, tasks]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((v) => !v); }
      if (e.key === 'Escape') setOpen(false);
    };
    const onOpen = () => setOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('zelsis:open-help', onOpen);
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('zelsis:open-help', onOpen); };
  }, []);

  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => inputRef.current?.focus(), 30);
    return () => clearTimeout(t);
  }, [open]);

  const choose = (t: Task) => { setOpen(false); setQuery(''); setActive(0); t.run(); };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 text-[11px] font-semibold text-white transition-colors"
        aria-label="Help: find what you want to do"
        title="Find anything (Ctrl/Cmd + K)"
      >
        <HelpCircle size={13} />
        <span className="hidden sm:inline">Help</span>
      </button>

      {open && (
        <div className="fixed inset-0 z-[60] bg-black/70 flex items-start justify-center p-4 pt-[12vh]" onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}>
          <div role="dialog" aria-modal="true" aria-labelledby="help-launcher-title" className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#141414] shadow-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10 focus-within:bg-white/[0.04] focus-within:shadow-[inset_0_-2px_0_0_#10b981]">
              <Search size={15} className="text-zinc-400 shrink-0" />
              <h2 id="help-launcher-title" className="sr-only">What do you want to do?</h2>
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => { setQuery(e.target.value); setActive(0); }}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(i + 1, results.length - 1)); }
                  if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
                  if (e.key === 'Enter' && results[active]) { e.preventDefault(); choose(results[active]); }
                }}
                placeholder="What do you want to do? e.g. private repo, CI, API key, report"
                aria-label="What do you want to do?"
                className="flex-1 bg-transparent text-base sm:text-sm text-white placeholder:text-zinc-500 outline-none"
              />
              <button type="button" onClick={() => setOpen(false)} aria-label="Close help" className="text-zinc-400 hover:text-white p-1">
                <X size={15} />
              </button>
            </div>
            <ul role="listbox" aria-label="Actions" className="max-h-[55vh] overflow-y-auto py-1">
              {results.length === 0 && (
                <li className="px-4 py-6 text-sm text-zinc-400">
                  Nothing matched. Try other words, or <a className="text-emerald-400 underline" href="mailto:contact@zelsis.com?subject=Zelsis%20help">ask us</a>.
                </li>
              )}
              {results.map((t, i) => (
                <li key={t.title} role="option" aria-selected={i === active}>
                  <button
                    type="button"
                    onMouseEnter={() => setActive(i)}
                    onClick={() => choose(t)}
                    className={`w-full text-left px-4 py-2.5 flex items-start gap-3 ${i === active ? 'bg-white/10' : 'hover:bg-white/5'}`}
                  >
                    <span className="flex-1 min-w-0">
                      <span className="block text-sm font-semibold text-white">{t.title}</span>
                      <span className="block text-xs text-zinc-400">{t.hint}</span>
                    </span>
                    <ArrowRight size={14} className="text-zinc-500 mt-1 shrink-0" />
                  </button>
                </li>
              ))}
            </ul>
            <div className="px-4 py-2 border-t border-white/10 text-[11px] text-zinc-500">
              Tip: press <kbd className="px-1 rounded bg-white/10 text-zinc-300">Ctrl</kbd>/<kbd className="px-1 rounded bg-white/10 text-zinc-300">⌘</kbd> + <kbd className="px-1 rounded bg-white/10 text-zinc-300">K</kbd> anywhere in the dashboard.
            </div>
          </div>
        </div>
      )}
    </>
  );
}
