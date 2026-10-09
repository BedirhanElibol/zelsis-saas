import React from 'react';
import Link from 'next/link';
import { ScanSearch, CheckCircle2, XCircle, FlaskConical } from 'lucide-react';

export function CodeBlock({ code, label, tone }: { code: string; label?: string; tone?: 'bad' | 'good' }) {
  const Icon = tone === 'bad' ? XCircle : tone === 'good' ? CheckCircle2 : null;
  const color = tone === 'bad' ? 'text-red-400' : 'text-emerald-400';
  return (
    <div className="min-w-0">
      {label && (
        <div className={`flex items-center gap-1.5 text-xs font-mono mb-1 ${Icon ? color : 'text-zinc-400'}`}>
          {Icon && <Icon size={13} aria-hidden="true" />}
          <span>{label}</span>
        </div>
      )}
      <pre className="bg-black/40 border border-white/10 rounded-lg p-4 text-xs overflow-x-auto max-w-full">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function TestStep({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 bg-sky-500/10 border border-sky-500/20 p-3 rounded-lg text-sm text-zinc-300">
      <FlaskConical size={16} className="text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
      <div className="min-w-0">
        <strong className="text-sky-300">Test it: </strong>
        {children}
      </div>
    </div>
  );
}

export interface CitedRule {
  id: string;
  title: string;
}

export function ZelsisCatches({ rules, children }: { rules: CitedRule[]; children?: React.ReactNode }) {
  return (
    <section className="bg-violet-500/10 border border-violet-500/20 p-4 sm:p-5 rounded-lg space-y-3">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-white m-0">
        <ScanSearch size={18} className="text-violet-300" aria-hidden="true" />
        How Zelsis catches this
      </h2>
      {children && <p className="text-sm text-zinc-300 m-0">{children}</p>}
      <ul className="space-y-1.5 text-sm m-0 p-0 list-none">
        {rules.map((r) => (
          <li key={r.id} className="flex flex-wrap items-baseline gap-2">
            <span className="px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30 text-xs font-mono">{r.id}</span>
            <span className="text-zinc-300">{r.title}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ScanCta() {
  return (
    <section className="space-y-3 border-t border-white/10 pt-6">
      <h2 className="text-xl font-semibold text-white">Check your own repo</h2>
      <p className="text-zinc-300">
        Public repositories scan free. Paste a GitHub URL on the dashboard and every finding comes with the file, the line and a fix.
      </p>
      <Link
        href="/dashboard"
        className="inline-block bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-sm px-4 py-2 rounded-lg no-underline"
      >
        Scan a repository free
      </Link>
    </section>
  );
}
