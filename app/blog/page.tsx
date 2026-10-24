import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { ArrowRight } from 'lucide-react';
import { POSTS, formatPostDate } from './posts';

export const metadata: Metadata = {
  title: 'Blog - Zelsis',
  description: 'Notes from building release checks: real issues found in open-source code, how they happen and how to fix them.',
};

export default function BlogIndexPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Blog</h1>
      <p className="text-zinc-400">
        What we see when we run release checks on real code, with the fix for each problem. For step-by-step fixes to single bugs, see the{' '}
        <Link href="/guides" className="text-emerald-400 hover:text-emerald-300 underline">guides</Link>.
      </p>
      <ul className="space-y-3 list-none p-0 m-0">
        {POSTS.map((p) => (
          <li key={p.slug}>
            <Link
              href={`/blog/${p.slug}`}
              className="group block border border-white/10 hover:border-emerald-500/40 bg-black/20 rounded-lg p-4 transition-colors"
            >
              <time dateTime={p.date} className="text-xs font-mono text-zinc-500">{formatPostDate(p.date)}</time>
              <h2 className="flex items-center justify-between gap-2 text-lg font-semibold text-white m-0 mt-1">
                <span>{p.title}</span>
                <ArrowRight size={16} className="text-zinc-500 group-hover:text-emerald-400 shrink-0" aria-hidden="true" />
              </h2>
              <p className="text-zinc-400 mt-1 mb-0">{p.summary}</p>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
