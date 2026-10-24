import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { CHANGELOG, type ChangeKind } from '@/data/changelog';

export const metadata: Metadata = {
  title: 'Changelog',
  description: 'What changed in Zelsis: new checks, fewer false alarms and product updates, week by week.',
};

const KIND_STYLE: Record<ChangeKind, string> = {
  New: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  Improved: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  Fixed: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
};

const formatDate = (iso: string) =>
  new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });

export default function ChangelogPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-12 sm:py-16 font-sans">
      <div className="max-w-3xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mt-8">Changelog</h1>
        <p className="text-zinc-400 mt-3">
          New checks, fewer false alarms and product updates. Rules change every week; scans always use the current set, and
          the dashboard tells you when a result comes from older rules.
        </p>

        <ol className="mt-12 flex flex-col gap-12">
          {CHANGELOG.map((entry) => (
            <li key={entry.date} className="grid sm:grid-cols-[9rem_1fr] gap-3 sm:gap-6">
              <time dateTime={entry.date} className="text-sm font-mono text-zinc-400 sm:pt-1">{formatDate(entry.date)}</time>
              <div className="min-w-0">
                <h2 className="text-lg font-semibold text-white">{entry.title}</h2>
                <ul className="mt-3 flex flex-col gap-3">
                  {entry.changes.map((c, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <span className={`shrink-0 mt-0.5 px-2 py-0.5 rounded border text-[0.68rem] font-mono font-bold ${KIND_STYLE[c.kind]}`}>{c.kind}</span>
                      <span className="text-sm text-zinc-300 leading-relaxed">{c.text}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </li>
          ))}
        </ol>

        <div className="mt-16 p-5 rounded-xl border border-white/10 bg-[#141414] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <p className="text-sm text-zinc-300">See what the current rules find in your code.</p>
          <Link href="/?ref=changelog" className="inline-flex items-center justify-center px-4 min-h-11 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400 focus-visible:ring-2 focus-visible:ring-white focus-visible:outline-none">
            Scan a repository
          </Link>
        </div>
      </div>
    </div>
  );
}
