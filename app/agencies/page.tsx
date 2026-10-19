import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, FileText, GitPullRequest, BadgeCheck, Wrench, ShoppingBag } from 'lucide-react';

export const metadata: Metadata = {
  title: 'For Agencies',
  description:
    'Check every client repository on each pull request, hand over a PDF report under your own brand, and sell ongoing code checks as part of maintenance.',
};

const ITEMS = [
  {
    icon: GitPullRequest,
    title: 'A gate on every client repository',
    body: 'Connect each client repository once. Every pull request your developers or contractors open gets the same check, and a proven critical finding blocks the merge.',
  },
  {
    icon: FileText,
    title: 'Reports under your name',
    body: 'On the Team plan, set your agency name and logo once in workspace settings. The PDF report carries your brand when you send it to the client.',
  },
  {
    icon: BadgeCheck,
    title: 'A page the client can share',
    body: 'For a project with no open critical or high findings, the owner can publish a trust page that shows the last scan date, gate result and risk areas. It never shows code, files or unfixed issues.',
  },
  {
    icon: Wrench,
    title: 'Something concrete to sell in maintenance',
    body: 'Scan before each monthly check-in and send the PDF. It shows what was checked and what is still open, which gives a maintenance retainer something the client can read.',
  },
  {
    icon: ShoppingBag,
    title: 'Code checks before a client buys an app',
    body: 'If a client is buying a SaaS product, scan the code first. Our guide walks through access, what to look for and what to check by hand.',
    href: '/guides/code-due-diligence',
  },
];

export default function AgenciesPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-12 sm:py-16 font-sans">
      <div className="max-w-3xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mt-8">Zelsis for agencies</h1>
        <p className="text-zinc-400 mt-3 leading-relaxed">
          You ship code for clients who cannot read it. When something breaks after launch, they call you. Zelsis checks every pull
          request in every client repository and gives you a report you can hand over.
        </p>

        <ul className="mt-12 flex flex-col gap-8">
          {ITEMS.map(({ icon: Icon, title, body, href }) => (
            <li key={title} className="flex gap-4">
              <Icon size={20} className="text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <h2 className="text-lg font-semibold text-white">{title}</h2>
                <p className="text-zinc-400 mt-1 leading-relaxed">
                  {body}
                  {href && (
                    <>
                      {' '}
                      <Link href={href} className="text-emerald-400 hover:text-emerald-300 underline">
                        Read the guide
                      </Link>
                      .
                    </>
                  )}
                </p>
              </div>
            </li>
          ))}
        </ul>

        <div className="mt-14 rounded-xl border border-white/10 bg-[#111113] p-6">
          <p className="text-white font-semibold">Start with one client repository</p>
          <p className="text-zinc-400 mt-1 text-sm leading-relaxed">
            Scans are free on every plan. Branded reports and a shared workspace for your team come with the Team plan.
          </p>
          <div className="flex flex-wrap gap-3 mt-4">
            <Link href="/dashboard" className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400">
              Scan a repository
            </Link>
            <Link href="/#pricing" className="px-4 py-2 rounded-lg border border-white/15 text-sm text-zinc-200 hover:bg-white/5">
              See pricing
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
