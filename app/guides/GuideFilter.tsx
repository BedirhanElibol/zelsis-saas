'use client';

import React from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { ArrowRight } from 'lucide-react';
import { GUIDE_CATEGORIES, GUIDES, type GuideCategory } from './guides';

const isCategory = (value: string): value is GuideCategory => GUIDE_CATEGORIES.some((c) => c.value === value);

function FilterView({ active, onToggle, onReset }: {
  active: GuideCategory[];
  onToggle: (value: GuideCategory) => void;
  onReset: () => void;
}) {
  const guides = active.length > 0 ? GUIDES.filter((g) => active.includes(g.category)) : GUIDES;

  return (
    <>
      <fieldset className="flex flex-wrap items-center gap-x-4 gap-y-2 border-0 p-0 m-0">
        <legend className="sr-only">Filter guides by topic</legend>
        {GUIDE_CATEGORIES.map((c) => (
          <label key={c.value} className="inline-flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              className="accent-emerald-500"
              checked={active.includes(c.value)}
              onChange={() => onToggle(c.value)}
            />
            {c.label}
          </label>
        ))}
        {active.length > 0 && (
          <button type="button" onClick={onReset} className="text-sm text-emerald-400 hover:underline">
            Reset
          </button>
        )}
      </fieldset>
      <p className="text-xs font-mono text-zinc-500 m-0" aria-live="polite">
        Showing {guides.length} of {GUIDES.length} guides
      </p>
      <ul className="space-y-3 list-none p-0 m-0">
        {guides.map((g) => (
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
    </>
  );
}

/** The URL is the only filter state, so filtered links can be shared and the back button works. */
export function GuideFilter() {
  const searchParams = useSearchParams();
  const active = searchParams.getAll('type').filter(isCategory);

  const navigate = (next: GuideCategory[]) => {
    const query = new URLSearchParams();
    // Fixed order: the same selection always produces the same URL.
    GUIDE_CATEGORIES.filter((c) => next.includes(c.value)).forEach((c) => query.append('type', c.value));
    const qs = query.toString();
    window.history.pushState(null, '', qs ? `/guides?${qs}` : '/guides');
  };

  return (
    <FilterView
      active={active}
      onToggle={(value) => navigate(active.includes(value) ? active.filter((v) => v !== value) : [...active, value])}
      onReset={() => navigate([])}
    />
  );
}
