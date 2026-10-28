import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { TutorialPlayer } from '@/components/tutorial/TutorialPlayer';

export const metadata: Metadata = {
  title: 'Zelsis tutorial: the dashboard and one full check',
  description:
    'A three-minute recording of the Zelsis dashboard: what each section is for, then one full check from a GitHub URL to a finding, a fix prompt and a check on every pull request.',
  alternates: { canonical: '/tutorial' },
};

export default function TutorialPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans px-4 sm:px-6 lg:px-10 py-10 sm:py-14">
      <div className="max-w-7xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <p className="mt-8 text-xs font-mono uppercase tracking-widest text-emerald-400">Tutorial · 3 minutes</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-extrabold tracking-tight text-white">How to use Zelsis</h1>
        <p className="mt-4 max-w-3xl text-zinc-400 leading-relaxed">
          Part one walks through every section of the dashboard. Part two runs one full check on a public repository: connect it, run
          the check, read the verdict, open a finding, copy the fix prompt and add the check to every pull request. Recorded in the real
          app; the scan is shown at double speed.
        </p>
        <div className="mt-8">
          <TutorialPlayer />
        </div>
        <div className="mt-10 flex flex-wrap gap-3">
          <Link href="/#pricing" className="inline-flex items-center min-h-11 px-5 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400">
            Scan your repository
          </Link>
          <Link href="/docs" className="inline-flex items-center min-h-11 px-5 rounded-lg border border-white/15 text-sm text-zinc-200 hover:border-white/30">
            Read the docs
          </Link>
        </div>
      </div>
    </div>
  );
}
