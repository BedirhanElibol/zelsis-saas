import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { ArrowRight } from 'lucide-react';
import { GUIDES } from './guides';

export const metadata: Metadata = {
  title: 'Guides: Bugs to Fix Before You Ship - Zelsis',
  description:
    'Practical guides for teams shipping web, mobile and SaaS apps: testing Supabase RLS, fixing the user-delete foreign key error, and sending Stripe amounts in cents.',
};

export default function GuidesIndexPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Guides</h1>
      <p className="text-zinc-400">
        Short, practical fixes for bugs that software teams ship again and again. Each guide
        shows the broken pattern, the fix, and how to check it yourself.
      </p>
      <ul className="space-y-3 list-none p-0 m-0">
        {GUIDES.map((g) => (
          <li key={g.slug}>
            <Link
              href={`/guides/${g.slug}`}
              className="group block border border-white/10 hover:border-emerald-500/40 bg-black/20 rounded-lg p-4 transition-colors"
            >
              <h2 className="flex items-center justify-between gap-2 text-lg font-semibold text-white m-0">
                <span>{g.title}</span>
                <ArrowRight size={16} className="text-zinc-500 group-hover:text-emerald-400 shrink-0" aria-hidden="true" />
              </h2>
              <p className="text-zinc-400 mt-1 mb-0">{g.summary}</p>
            </Link>
          </li>
        ))}
      </ul>
      <p className="text-zinc-400">
        More real examples: <Link href="/docs/real-world-bugs" className="text-emerald-400 hover:text-emerald-300 underline">bugs we found in popular open-source repos</Link>.
      </p>
    </div>
  );
}
