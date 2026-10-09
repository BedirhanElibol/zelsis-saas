import React from 'react';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Real Bugs Zelsis Found in Popular Open-Source Repos - Zelsis Docs',
  description:
    'Logic and UI bugs Zelsis flagged in well-known open-source starters and apps: an effect that re-runs every render, a Supabase schema that blocks user deletion, and a layout that overflows phones.',
};

interface RealBug {
  repo: string;
  about: string;
  rule: string;
  title: string;
  file: string;
  url: string;
  code: string;
  why: string;
  fix: string;
}

const BUGS: RealBug[] = [
  {
    repo: 'documenso/documenso',
    about: 'Open-source DocuSign alternative',
    rule: 'BUG-28',
    title: 'Auto-save effect re-runs on every render',
    file: 'packages/ui/primitives/document-flow/field-item-advanced-settings.tsx:197',
    url: 'https://github.com/documenso/documenso/blob/8a41a3b/packages/ui/primitives/document-flow/field-item-advanced-settings.tsx#L183-L197',
    code: `const handleAutoSave = () => { ... scheduleSave(fieldState); };

useEffect(() => {
  localStorage.setItem(localStorageKey, JSON.stringify(fieldState));
  handleAutoSave();
}, [fieldState, localStorageKey, handleAutoSave]);`,
    why: 'handleAutoSave is a new function on every render, so the dependency array changes every time. The effect writes to localStorage and schedules a remote save after every render, not only when the field changes.',
    fix: 'Wrap handleAutoSave in useCallback, or drop it from the dependencies and call scheduleSave directly inside the effect.',
  },
  {
    repo: 'vercel/nextjs-subscription-payments',
    about: "Vercel's official Next.js + Supabase + Stripe starter",
    rule: 'BUG-17',
    title: 'Deleting a user fails because of the schema',
    file: 'supabase/migrations/20230530034630_init.sql:7',
    url: 'https://github.com/vercel/nextjs-subscription-payments/blob/bdd0813/supabase/migrations/20230530034630_init.sql#L7',
    code: `create table users (
  id uuid references auth.users not null primary key,
  ...
);`,
    why: 'The foreign key to auth.users has no ON DELETE rule. When you delete the user from the Supabase dashboard (or a GDPR request comes in), Postgres refuses with a foreign key violation. Supabase has a public issue about exactly this error.',
    fix: 'Use references auth.users on delete cascade, so the profile row goes away with the account.',
  },
  {
    repo: 'shadcn-ui/taxonomy',
    about: 'Popular Next.js App Router reference app',
    rule: 'BUG-51',
    title: 'Fixed 800px width overflows phones',
    file: 'app/(editor)/editor/[postId]/loading.tsx:10',
    url: 'https://github.com/shadcn-ui/taxonomy/blob/298a885/app/(editor)/editor/%5BpostId%5D/loading.tsx#L10',
    code: `<div className="mx-auto w-[800px] space-y-6">`,
    why: 'A hard 800px width is wider than every phone screen, so the editor loading state scrolls sideways on mobile.',
    fix: 'Use w-full max-w-[800px] so it fills small screens and caps at 800px on desktop.',
  },
  {
    repo: 'supabase/supabase-js',
    about: 'The official Supabase JavaScript client',
    rule: 'BUG-17',
    title: 'Same user-deletion trap in an example migration',
    file: 'packages/core/supabase-js/supabase/migrations/20250422000000_create_todos_table.sql:7',
    url: 'https://github.com/supabase/supabase-js/blob/a684cf9/packages/core/supabase-js/supabase/migrations/20250422000000_create_todos_table.sql#L7',
    code: `user_id UUID REFERENCES auth.users(id)`,
    why: 'Even the official client repo has a table that blocks deleting a user who owns todos. Code copied from examples like this is how the bug spreads into AI-generated apps.',
    fix: 'REFERENCES auth.users(id) ON DELETE CASCADE (or SET NULL if the rows must outlive the user).',
  },
];

export default function RealWorldBugsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Real Bugs We Found in Popular Repos</h1>
      <p className="text-zinc-400">
        Security scanners stop at vulnerabilities. Zelsis also checks for the logic and UI bugs that break features after you ship,
        the kind fast-moving teams and AI coding tools introduce every day. These are real findings from well-maintained open-source
        projects, each linked to the exact commit we scanned.
      </p>

      <div className="bg-violet-500/10 border border-violet-500/20 p-4 rounded-lg">
        <p className="text-sm text-zinc-300">
          <strong className="text-violet-300">95 logic bug checks</strong> cover React effects, async mistakes, Supabase schemas, Stripe
          amounts, deployment config and mobile layout. They cost score points but never fail your release gate on their own.
        </p>
      </div>

      {BUGS.map((bug) => (
        <section key={bug.url} className="space-y-3 border-t border-white/10 pt-6">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30">{bug.rule}</span>
            <span className="text-zinc-400">{bug.repo}</span>
            <span className="text-zinc-600">· {bug.about}</span>
          </div>
          <h2 className="text-xl font-semibold text-white">{bug.title}</h2>
          <pre className="bg-black/40 border border-white/10 rounded-lg p-4 text-xs overflow-x-auto"><code>{bug.code}</code></pre>
          <p className="text-zinc-300"><strong className="text-white">Why it breaks:</strong> {bug.why}</p>
          <p className="text-zinc-300"><strong className="text-white">Fix:</strong> {bug.fix}</p>
          <a href={bug.url} target="_blank" rel="noopener noreferrer" className="inline-block text-xs font-mono text-emerald-400 hover:text-emerald-300 underline break-all">
            {bug.file}
          </a>
        </section>
      ))}

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className="text-xl font-semibold text-white">Check your own repo</h2>
        <p className="text-zinc-300">
          Public repositories scan free. Paste a GitHub URL on the dashboard and every finding comes with the file, the line and a fix.
        </p>
        <a href="/dashboard" className="inline-block bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-sm px-4 py-2 rounded-lg no-underline">
          Scan a repository
        </a>
      </section>
    </div>
  );
}
