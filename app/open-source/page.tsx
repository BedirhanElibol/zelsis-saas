import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, GitPullRequest, Infinity as InfinityIcon, KeyRound, ListChecks } from 'lucide-react';
import { buildGateWorkflow } from '@/lib/ci-gate-snippet';
import { getConfiguredAppUrl } from '@/lib/app-url';

export const metadata: Metadata = {
  title: 'For Open-Source Projects',
  description:
    'Public repositories get the Zelsis release check free: unlimited scans and a check on every pull request, with findings on the lines the pull request changes.',
};

const ITEMS = [
  {
    icon: InfinityIcon,
    title: 'Public repositories scan free, with no limit',
    body: 'The Free plan caps private projects, not public ones. Scan the default branch whenever you like and keep the history.',
  },
  {
    icon: GitPullRequest,
    title: 'A check on every pull request',
    body: 'The workflow below sends the base and head commits, so a contributor’s pull request is only judged on what it changes. Findings appear on their lines in “Files changed”, critical and high as errors, medium as warnings.',
  },
  {
    icon: KeyRound,
    title: 'Your own key, your own limits',
    body: 'The gate runs for public repositories without a key, but then it shares GitHub’s limit for unauthenticated requests with everyone else. A free account and an API key give your project its own.',
  },
  {
    icon: ListChecks,
    title: 'You decide what blocks a merge',
    body: 'Only findings from proven rules can fail the gate, and failStrategy in .zelsisrc.json sets which severities block. Dismiss a finding once and it stops counting.',
  },
];

export default function OpenSourcePage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-12 sm:py-16 font-sans">
      <div className="max-w-3xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mt-8">Zelsis for open-source projects</h1>
        <p className="text-zinc-400 mt-3 leading-relaxed">
          Maintainers review pull requests from people they have never met, often in their spare time. Zelsis checks each one for leaked
          keys, injection, missing auth checks and the logic bugs that slip through review, and it is free for public repositories.
        </p>

        <ul className="mt-12 flex flex-col gap-8">
          {ITEMS.map(({ icon: Icon, title, body }) => (
            <li key={title} className="flex gap-4">
              <Icon size={20} className="text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <h2 className="text-lg font-semibold text-white">{title}</h2>
                <p className="text-zinc-400 mt-1 leading-relaxed">{body}</p>
              </div>
            </li>
          ))}
        </ul>

        <section className="mt-14 space-y-3">
          <h2 className="text-xl font-semibold text-white">Set it up in two steps</h2>
          <p className="text-zinc-400 leading-relaxed">
            1. Create a free account, open <strong className="text-zinc-200">Settings → API keys</strong> and add the key to your repository as
            the Actions secret <code>ZELSIS_API_KEY</code>. 2. Save this as <code>.github/workflows/zelsis.yml</code>.
          </p>
          <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-white/10">
            <code className="text-emerald-400">{buildGateWorkflow({ appUrl: getConfiguredAppUrl() })}</code>
          </pre>
          <p className="text-zinc-400 text-sm">
            Fork pull requests cannot read repository secrets on GitHub, so for them the gate runs without the key. More options are in the{' '}
            <Link href="/docs/ci-gate" className="text-emerald-400 hover:text-emerald-300 underline">CI gate docs</Link>.
          </p>
        </section>

        <div className="mt-14 rounded-xl border border-white/10 bg-[#111113] p-6">
          <p className="text-white font-semibold">Try it on your repository first</p>
          <p className="text-zinc-400 mt-1 text-sm leading-relaxed">
            Paste the GitHub URL on the dashboard and see what a scan finds before you add the workflow. If something looks wrong, tell us:
            false alarms on well-kept projects are how the rules get better.
          </p>
          <div className="flex flex-wrap gap-3 mt-4">
            <Link href="/dashboard" className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400">
              Scan a public repository
            </Link>
            <Link href="/blog/open-source-release-check" className="px-4 py-2 rounded-lg border border-white/15 text-sm text-zinc-200 hover:bg-white/5">
              What it found in open-source apps
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
