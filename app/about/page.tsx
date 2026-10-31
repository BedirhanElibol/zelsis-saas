import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';

export const metadata: Metadata = {
  title: 'About Zelsis',
  description:
    'Who builds Zelsis, how the results are measured and published, what happens to your code, and what we do when we find a real bug in someone else’s project.',
  alternates: { canonical: '/about' },
};

const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-12 sm:py-16 font-sans">
      <div className="max-w-3xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mt-8">About Zelsis</h1>
        <p className="text-zinc-400 mt-3 leading-relaxed">
          Zelsis checks every pull request before it merges: logic bugs, performance, risky deploys, privacy gaps, accessibility,
          vulnerable dependencies and security. It was built because the mistakes that cost money or customers pass code review all the
          time, since each line looks reasonable on its own.
        </p>

        <section className="mt-12 space-y-3">
          <h2 className="text-xl font-semibold text-white">Who is behind it</h2>
          <p className="text-zinc-400 leading-relaxed">
            Zelsis is built and run by Bedirhan Elibol at Zelsis Software Technologies in Istanbul, Türkiye. If you write to{' '}
            <a href="mailto:contact@zelsis.com" className={LINK}>
              contact@zelsis.com
            </a>
            , the person who builds the product reads it.
          </p>
          <p className="text-zinc-400 leading-relaxed">
            The code is public in{' '}
            <a href="https://github.com/BedirhanElibol/zelsis-saas" className={LINK} target="_blank" rel="noopener noreferrer">
              BedirhanElibol/zelsis-saas
            </a>
            , rules and benchmark included, so you can read what a finding is based on.
          </p>
        </section>

        <section className="mt-10 space-y-3">
          <h2 className="text-xl font-semibold text-white">How the results are measured</h2>
          <p className="text-zinc-400 leading-relaxed">
            We scan pinned open-source projects: apps that are vulnerable on purpose, to measure what we catch, and maintained
            production apps, to measure noise. The numbers are published as they come out, including the flaws we miss and the clean
            projects where a finding blocks the check. Anyone can rerun them. See the{' '}
            <Link href="/#benchmark" className={LINK}>
              benchmark
            </Link>
            .
          </p>
          <p className="text-zinc-400 leading-relaxed">
            We also compared Zelsis with an AI reviewer on five pull requests with flaws written down in advance, and published every
            comment from both tools, including the case where the other tool did better. Read{' '}
            <Link href="/guides/zelsis-vs-coderabbit" className={LINK}>
              Zelsis vs CodeRabbit
            </Link>
            .
          </p>
          <p className="text-zinc-400 leading-relaxed">
            Only rules that have caught a documented flaw, or were reviewed as true positives, can fail the check. Everything else is
            reported as a warning. A check that cries wolf gets switched off, and then it protects nobody.
          </p>
        </section>

        <section className="mt-10 space-y-3">
          <h2 className="text-xl font-semibold text-white">What happens to your code</h2>
          <p className="text-zinc-400 leading-relaxed">
            Files are fetched into memory, scanned and released. We keep the findings and a short snippet around each one, and the
            snippets are erased after 90 days. Scans are rule-based and send no code to an AI model. Details are in the{' '}
            <Link href="/privacy" className={LINK}>
              privacy policy
            </Link>
            .
          </p>
        </section>

        <section className="mt-10 space-y-3">
          <h2 className="text-xl font-semibold text-white">When we find a real bug in someone else’s project</h2>
          <p className="text-zinc-400 leading-relaxed">
            We tell the maintainers privately first and give them 60 days. We only name a project once the bug is fixed or the
            maintainers agree. Until then we describe findings in general terms, without the project name or the details that would
            let someone exploit it.
          </p>
        </section>

        <div className="mt-14 rounded-xl border border-white/10 bg-[#111113] p-6">
          <p className="text-white font-semibold">Try it on a repository you know</p>
          <p className="text-zinc-400 mt-1 text-sm leading-relaxed">
            Public repositories scan free. If a finding looks wrong, tell us: false alarms on well-kept projects are how the rules get
            better.
          </p>
          <div className="flex flex-wrap gap-3 mt-4">
            <Link href="/dashboard" className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400">
              Scan a repository free
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
