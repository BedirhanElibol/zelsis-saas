import React from 'react';
import type { Metadata } from 'next';
import { ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Zelsis vs Snyk: What Each Checks Before a Pull Request Merges - Zelsis Guides',
  description:
    'Snyk is a broad security platform for dependencies, containers, infrastructure and code. Zelsis is a rule-based release check for business-logic and access mistakes on pull requests. How they differ, and when to run each.',
  alternates: { canonical: '/guides/zelsis-vs-snyk' },
};

const H2 = 'text-xl font-semibold text-white';

export default function ZelsisVsSnykPage() {
  return (
    <article className="mx-auto max-w-3xl space-y-8 px-4 py-12">
      <header className="space-y-3">
        <p className="text-sm text-emerald-400">Comparison</p>
        <h1 className="text-3xl font-bold text-white">Zelsis vs Snyk: what each checks before a pull request merges</h1>
        <p className="text-zinc-400">
          Snyk covers a lot: dependencies, containers, infrastructure as code and source code. Zelsis looks at one narrower
          thing: the mistakes that cost a customer money or expose their data. This page explains where they overlap,
          where they do not, and how we would choose between them.
        </p>
      </header>

      <section className="space-y-3">
        <h2 className={H2}>What Snyk describes itself as</h2>
        <p className="text-zinc-300">
          Snyk&apos;s product pages describe Snyk Code as a SAST tool with AI-powered analysis, built on a machine learning
          engine and a vulnerability database. Its fixes come from an agentic AI architecture. Snyk also sells scanning for
          open source dependencies, containers and infrastructure as code. Those are areas Zelsis does not cover.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>What Zelsis does instead</h2>
        <p className="text-zinc-300">
          The scan is rule-based. Each finding comes from a written rule with a test, and no AI model reads the code during a
          scan. The same code gives the same result every time. Rules that are not yet proven on real code are shown as notes,
          and they do not fail the check. The rules focus on:
        </p>
        <ul className="list-disc space-y-1 pl-6 text-zinc-300">
          <li>Payments: a checkout amount taken from the browser, a webhook that grants access without checking its signature.</li>
          <li>Access: a record loaded by an id from the request with no owner check, a table with no row level security.</li>
          <li>Secrets: a key shipped to client code or committed config.</li>
          <li>Migrations and queries that lock busy tables or run once per row.</li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Where they overlap</h2>
        <p className="text-zinc-300">
          Both look at source code on pull requests and both can fail a build. Both flag hard-coded secrets and some injection
          patterns. If a pull request changes code that handles money or user data, both are worth running.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Where Snyk is the better choice</h2>
        <ul className="list-disc space-y-1 pl-6 text-zinc-300">
          <li>You need vulnerable dependency tracking, container images or infrastructure as code. Zelsis does not do these.</li>
          <li>You want a platform with a long history of vulnerability data, IDE plugins and a large set of integrations.</li>
          <li>You need automated fix generation across many languages, which is Snyk&apos;s core product.</li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Where Zelsis is the better choice</h2>
        <ul className="list-disc space-y-1 pl-6 text-zinc-300">
          <li>You want a deterministic release check: the same result on every run, with no AI in the scan.</li>
          <li>Your bugs are business-logic and access mistakes that a generic SAST rule set tends to miss.</li>
          <li>You want a free check on a public repository without installing anything.</li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Limits of this comparison</h2>
        <p className="text-zinc-300">
          We have not run Snyk on the same pull requests as Zelsis, so this page makes no claim about which one finds more.
          Our own results for a different tool are published in the{' '}
          <a className="text-emerald-400 underline hover:text-emerald-300" href="/guides/zelsis-vs-coderabbit">
            CodeRabbit comparison
          </a>
          , which uses a written set of planted flaws. Prices change, so we do not list them here; check each vendor&apos;s
          current pricing page.
        </p>
      </section>

      <ScanCta />
    </article>
  );
}
