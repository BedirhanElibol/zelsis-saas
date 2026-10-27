'use client';

import React, { useState } from 'react';
import { ArrowRight, CheckCircle2, CircleX, Globe, Loader2 } from 'lucide-react';
import type { SiteReadinessItem } from '@/lib/site-readiness';

interface Result { url: string; items: SiteReadinessItem[]; passed: number; total: number }

export function SiteCheckForm() {
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/site-readiness', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data) setError(data?.error || 'The check failed. Try again.');
      else setResult(data as Result);
    } catch {
      setError('Network error. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  };

  const failed = result?.items.filter((i) => !i.ok) ?? [];
  const passed = result?.items.filter((i) => i.ok) ?? [];

  return (
    <div className="w-full">
      <form onSubmit={run} className="flex flex-col sm:flex-row items-stretch gap-2 p-1.5 rounded-xl bg-[#141414] border border-white/10 focus-within:border-white/30">
        <label className="flex items-center gap-2.5 px-3 py-2 flex-1 min-w-0">
          <Globe size={16} className="text-zinc-400 shrink-0" aria-hidden="true" />
          <span className="sr-only">Website address</span>
          <input
            name="url"
            type="text"
            inputMode="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="yourapp.com"
            className="w-full bg-transparent text-base sm:text-sm font-mono text-[#EDEDED] placeholder-zinc-500 focus:outline-none"
          />
        </label>
        <button
          type="submit"
          disabled={busy}
          data-track="site-check"
          className="px-5 min-h-11 rounded-lg text-xs font-bold font-mono uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400 disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
        >
          {busy ? <Loader2 size={13} className="animate-spin" aria-hidden="true" /> : null}
          <span>{busy ? 'Checking…' : 'Check my site'}</span>
          {!busy && <ArrowRight size={13} aria-hidden="true" />}
        </button>
      </form>

      {error && <p role="alert" className="mt-3 text-sm text-red-400">{error}</p>}

      {result && (
        <div className="mt-8" aria-live="polite">
          <p className="text-sm text-zinc-300">
            <span className="font-mono text-white">{result.url}</span>: {result.passed} of {result.total} checks pass.
          </p>
          <ul className="mt-4 flex flex-col gap-2">
            {[...failed, ...passed].map((item) => (
              <li key={item.id} className={`rounded-xl border p-4 flex gap-3 ${item.ok ? 'border-white/10 bg-[#111113]' : 'border-red-500/30 bg-red-500/[0.06]'}`}>
                {item.ok
                  ? <CheckCircle2 size={18} className="text-emerald-400 shrink-0 mt-0.5" aria-label="Passes" />
                  : <CircleX size={18} className="text-red-400 shrink-0 mt-0.5" aria-label="Fails" />}
                <div className="min-w-0">
                  <p className="font-semibold text-white">{item.title}</p>
                  <p className="text-sm text-zinc-400 break-words">{item.detail}</p>
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-6 text-sm text-zinc-300">
            This checks one page from the outside. Zelsis also reads your code on every pull request for the bugs users hit after they sign up.{' '}
            <a href="/#pricing" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-4">Check a repository</a>
          </p>
        </div>
      )}
    </div>
  );
}
