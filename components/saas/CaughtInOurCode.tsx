import React from 'react';
import Link from 'next/link';

/** Real findings from running Zelsis on this codebase, each fixed in a commit on main. Do not add anything that did not happen. */
const FINDINGS = [
  {
    title: 'Private code, public cache',
    body: 'Our GitHub proxy sent files from private repositories with a public cache header, so a CDN was allowed to keep a copy.',
  },
  {
    title: 'Database functions open to hijack',
    body: 'Functions running with elevated rights had no fixed search_path, so a crafted schema could swap in its own code.',
  },
  {
    title: 'Test origins live in production',
    body: 'CORS still accepted localhost origins on the live site.',
  },
  {
    title: 'A search box you could not see focus on',
    body: 'Keyboard users tabbed into the help search and got no sign of where they were.',
  },
];

export function CaughtInOurCode() {
  return (
    <section id="our-own-code" className="py-12 sm:py-14 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-7xl mx-auto flex flex-col gap-10">
        <div className="flex flex-col gap-4 max-w-3xl">
          <div className="text-xs font-mono uppercase tracking-widest text-red-400">We scan ourselves too</div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">Our own scanner caught us.</h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed">
            Zelsis checks its own code on every pull request. These made it into our codebase and Zelsis flagged them. Each
            one is fixed.
          </p>
        </div>

        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-4 list-none p-0 m-0">
          {FINDINGS.map(({ title, body }) => (
            <li key={title} className="flex gap-4 rounded-2xl border border-red-500/20 bg-red-500/[0.04] p-5">
              <div className="flex flex-col gap-1.5">
                <h3 className="text-lg font-bold text-white m-0">{title}</h3>
                <p className="text-sm text-zinc-400 leading-relaxed m-0">{body}</p>
              </div>
            </li>
          ))}
        </ul>

        <p className="text-sm text-zinc-400 m-0">
          It also flagged code that was fine. Each of those became a rule fix with a test, so your scans do not repeat them.{' '}
          <Link href="/changelog" className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-semibold">
            Read the changelog
          </Link>
        </p>
      </div>
    </section>
  );
}
