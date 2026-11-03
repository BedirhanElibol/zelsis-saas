import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Is NEXT_PUBLIC_ Safe for Secrets? No, Anyone Can Read It - Zelsis Guides',
  description:
    'Next.js copies every NEXT_PUBLIC_ variable into the JavaScript it sends to the browser. Which keys are safe to expose, how to move a secret to the server, and how to check your build.',
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function NextPublicSecretsPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">A NEXT_PUBLIC_ variable is not a secret</h1>
      <p className="text-zinc-400">
        A request fails in the browser with &quot;undefined&quot;, someone adds <code>NEXT_PUBLIC_</code> to the variable name, and the
        page works. The fix is also a leak: from that build on, the value is in the JavaScript file every visitor downloads. If the value is
        a database service key or a payment secret, anyone who opens the page can use it.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>Why it happens</h2>
        <p className="text-zinc-300">
          Next.js replaces every <code>process.env.NEXT_PUBLIC_*</code> reference with its value when it builds the app. The value ends up as
          plain text in a file under <code>/_next/static/</code>. Other frameworks do the same with their own prefix: <code>VITE_</code> in
          Vite and <code>EXPO_PUBLIC_</code> in Expo. The prefix means &quot;send this to the browser&quot;, nothing more.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: server secret with a public prefix"
          code={`# .env.local
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...

// app/admin/page.tsx ('use client')
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!, // shipped to every visitor
);`}
        />
        <p className="text-zinc-300">
          A Supabase service role key skips every row level security policy, so whoever holds it can read and change every table. A Stripe
          secret key can issue refunds and read customer data.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Which keys are fine in the browser</h2>
        <p className="text-zinc-300">
          Some keys are built to be public: the Supabase URL and anon key (your RLS policies protect the data), a Stripe publishable key
          (<code>pk_</code>), a Firebase web config, and analytics site ids. Keys that end in <code>SECRET</code>,{' '}
          <code>SERVICE_ROLE</code>, <code>PRIVATE</code> or that hold a database URL with a password are never fine there.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>The fix</h2>
        <p className="text-zinc-300">
          Drop the prefix and read the secret only in server code: a Server Action, a Route Handler or a Server Component. Add{' '}
          <code>import &apos;server-only&apos;</code> to the module that holds the client, so the build fails if a client component imports it.
        </p>
        <CodeBlock
          tone="good"
          label="Good: secret stays on the server"
          code={`# .env.local
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...

// lib/supabase-admin.ts
import 'server-only';
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

// app/admin/actions.ts
'use server';
import { supabaseAdmin } from '@/lib/supabase-admin';

export async function banUser(userId: string) {
  // check that the caller is an admin first
  await supabaseAdmin.auth.admin.updateUserById(userId, { ban_duration: '876000h' });
}`}
        />
        <p className="text-zinc-300">
          Then rotate the key. Renaming the variable does not remove the old value from builds that are already deployed, cached by a CDN
          or saved in someone&apos;s browser. Create a new key in the provider&apos;s dashboard, update the server variable, redeploy, and
          revoke the old one.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Verify it</h2>
        <TestStep>
          Run <code>next build</code> and search the client output for the start of each secret, for example{' '}
          <code>grep -rl &quot;sk_live_&quot; .next/static</code> or the first characters of your service role key. The search should find
          nothing. On the live site, open the browser&apos;s developer tools, search all sources for the same text and expect no match.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'SEC-36', title: 'Backend secret exposed through a NEXT_PUBLIC_ environment variable' }]}>
        Zelsis flags <code>NEXT_PUBLIC_</code> names that point to a server secret, such as ones containing <code>SERVICE_ROLE</code>,{' '}
        <code>SECRET</code>, <code>PRIVATE</code> or <code>DATABASE_URL</code>, and shows the server-only fix on the pull request.
      </ZelsisCatches>

      <p className="text-zinc-400">
        Using Supabase? Read{' '}
        <Link href="/guides/supabase-rls-testing" className={LINK}>
          how to test RLS before you ship
        </Link>
        , since the anon key is only safe when your policies are right.
      </p>

      <ScanCta />
    </article>
  );
}
