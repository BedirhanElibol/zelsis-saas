import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { TestStep, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Check the Code Before You Buy a SaaS App - Zelsis Guides',
  description:
    'A code check for buying a small SaaS or app: how to get access to the repository, what to scan for, what a scan cannot tell you, and what to verify by hand before you pay.',
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function CodeDueDiligencePage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Check the code before you buy a SaaS app</h1>
      <p className="text-zinc-400">
        When you buy an app, you buy its bugs too. Revenue and traffic are easy to check in the seller&apos;s dashboards. The code
        usually gets a quick look on a screen share. This guide is a short code check you can run before you sign.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>1. Get read access to the real repository</h2>
        <p className="text-zinc-300">There are two ways to do it, depending on how much the seller wants to share before the sale.</p>
        <ul className="list-disc pl-6 space-y-2 text-zinc-300">
          <li>
            <strong className="text-white">The seller runs the scan.</strong> They connect the repository to Zelsis, scan the branch that
            is deployed and send you the PDF report. The report lists risk areas and each open issue with its file, line and a short snippet. Ask them to
            share their screen while it runs so you can see the repository name and the commit.
          </li>
          <li>
            <strong className="text-white">You run the scan.</strong> The seller pushes a copy of the repository to a private repository
            you own, and you connect it as described in{' '}
            <Link href="/docs/private-repos" className={LINK}>
              Scan a private repo
            </Link>
            . This is the stronger option because you control the scan.
          </li>
        </ul>
        <TestStep>
          Compare the commit you scanned with what is running in production. A clean scan of an old branch tells you little about the
          app you are buying.
        </TestStep>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>2. Read the findings by what they would cost you</h2>
        <p className="text-zinc-300">Sort the open issues by the damage they could do after the sale, not by count.</p>
        <ul className="list-disc pl-6 space-y-2 text-zinc-300">
          <li><strong className="text-white">Data leaks:</strong> one user reading another&apos;s records, database tables without access rules, secret keys in client code.</li>
          <li><strong className="text-white">Money:</strong> prices or amounts the browser can change, payment webhooks without signature checks.</li>
          <li><strong className="text-white">Account takeover:</strong> weak session or token handling, admin routes without a role check.</li>
          <li><strong className="text-white">Licenses:</strong> dependencies whose license limits how you can sell or close the code.</li>
        </ul>
        <p className="text-zinc-300">
          Each of these is something you would pay to fix after closing. Put a fix estimate next to each one and bring it into the price
          discussion.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>3. Check by hand what a scan cannot see</h2>
        <p className="text-zinc-300">
          A static scan reads code. It does not see the live database, the hosting account or how the app behaves at runtime. Our{' '}
          <Link href="/docs/boundaries" className={LINK}>
            list of what Zelsis does not check
          </Link>{' '}
          covers this in detail. Before you pay, check these yourself:
        </p>
        <ul className="list-disc pl-6 space-y-2 text-zinc-300">
          <li>Every API key and secret will be rotated at handover, including keys the seller may have pasted into chats or old commits.</li>
          <li>Database access rules in the live project match the ones in the repository.</li>
          <li>Backups exist and you have restored one at least once.</li>
          <li>Domain, hosting, payment and email accounts can move to you, and you know which ones are in the seller&apos;s personal name.</li>
        </ul>
      </section>

      <p className="text-zinc-400">
        A scan does not replace a lawyer or an accountant, and a clean report is not a guarantee. It gives you a list of concrete code
        problems to ask about before the money moves.
      </p>

      <ScanCta />
    </article>
  );
}
