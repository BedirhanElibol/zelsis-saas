import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';
import { ruleBySlug } from '@/data/rule-pages';

export const metadata: Metadata = {
  title: '5 Checks Before You Merge Code an AI Wrote - Zelsis Guides',
  description:
    'Cursor, Claude Code and Copilot write code that runs. Five quick checks for a pull request before it ships: exposed secrets, open tables, raw SQL, table-locking migrations and open CORS.',
  alternates: { canonical: '/guides/ai-code-merge-checklist' },
};

const H2 = 'text-xl font-semibold text-white';

// Every check reuses a rule page, so the code and the fix here match the fixture that proves the rule.
const CHECKS = [
  { slug: 'secret-in-next-public-variable', look: 'Any variable that starts with NEXT_PUBLIC_ and holds a secret, and any secret read in a file marked use client.' },
  { slug: 'supabase-table-without-rls', look: 'A new create table in a migration with no row level security and no policy.' },
  { slug: 'sql-injection-template-literal', look: 'A query string built with a template literal or string concatenation that includes request input.' },
  { slug: 'migration-locks-existing-table', look: 'A migration that changes a table that already has rows: a new index, a new NOT NULL column, a type change.' },
  { slug: 'cors-wildcard-with-credentials', look: 'A CORS setting that allows any origin while also allowing cookies or credentials.' },
] as const;

export default function AiCodeMergeChecklistPage() {
  const rules = CHECKS.map((c) => ({ ...c, rule: ruleBySlug(c.slug) })).filter((c) => c.rule);

  return (
    <article className="space-y-8">
      <header className="space-y-3">
        <h1 className="text-3xl font-bold text-white">5 checks before you merge code an AI wrote</h1>
        <p className="text-zinc-400">
          Cursor, Claude Code and Copilot can open a pull request in minutes, and the code runs. Whether it is safe to ship is a separate
          question, and the diff rarely answers it on its own. These five checks take a few minutes on any pull request, whoever wrote it.
          Each one links to the rule page with the flagged code and the fix.
        </p>
      </header>

      {rules.map(({ slug, look, rule }, i) => (
        <section key={slug} className="space-y-3">
          <h2 className={H2}>
            {i + 1}. {rule!.title}
          </h2>
          <p className="text-zinc-300">
            <strong className="text-white">Look for:</strong> {look}
          </p>
          <p className="text-zinc-300">
            <strong className="text-white">If it ships:</strong> {rule!.consequence}
          </p>
          <CodeBlock tone="bad" label={`Flagged, ${rule!.path}`} code={rule!.bad} />
          <CodeBlock tone="good" label="Fixed" code={rule!.good} />
          <p className="text-zinc-300">{rule!.fix}</p>
          <p className="text-sm">
            <Link href={`/rules/${slug}`} className="text-violet-300 underline underline-offset-4 hover:text-violet-200">
              See the rule page for {rule!.code}
            </Link>
          </p>
        </section>
      ))}

      <ZelsisCatches rules={rules.map(({ rule }) => ({ id: rule!.code, title: rule!.title }))}>
        Zelsis reads every pull request for these and fails the build when a proven critical issue is in the change, so the check runs
        even when nobody remembers to do it by hand.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
