import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'How to Test Supabase RLS Before You Ship - Zelsis Guides',
  description:
    'Test Supabase Row Level Security before launch: USING (true) on private tables, INSERT policies with USING, storage bucket policies, the service-role key in client code, and user deletion.',
};

const H2 = 'text-xl font-semibold text-white';

export default function SupabaseRlsTestingPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">How to test Supabase RLS before you ship</h1>
      <p className="text-zinc-400">
        Your Supabase anon key is public: it ships in the browser bundle and anyone can copy it. Row Level Security (RLS) policies are the
        only thing between that key and your tables. A policy that looks fine in the dashboard can still let every visitor read or edit
        every row. Below are five common mistakes, a fixed version of each, and a manual test you can run in a few minutes.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>Before you start: get a test setup</h2>
        <p className="text-zinc-300">
          You need your project URL, the anon key (Project Settings, API) and two test users, A and B. Most tests below are plain HTTP
          requests against the REST API. Without a user token they run as the <code>anon</code> role; with a user&apos;s access token
          they run as that user.
        </p>
        <CodeBlock
          label="Query a table as an anonymous visitor"
          code={`curl "https://YOUR_PROJECT.supabase.co/rest/v1/profiles?select=*" \\
  -H "apikey: YOUR_ANON_KEY"`}
        />
        <p className="text-zinc-300">
          To act as user A, sign in with <code>supabase.auth.signInWithPassword()</code> in a scratch script and add{' '}
          <code>-H &quot;Authorization: Bearer USER_A_ACCESS_TOKEN&quot;</code> to the request.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>1. USING (true) on a table with private data</h2>
        <p className="text-zinc-300">
          <code>USING (true)</code> means &quot;every row matches&quot;. It is fine for a public catalog such as products or prices. On a
          table with emails, orders, messages or anything per-user, it hands the whole table to anyone holding the anon key. On an UPDATE
          or DELETE policy it is worse: any client can change or wipe every row.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: everyone reads every profile"
          code={`create policy "Profiles are viewable"
  on profiles for select
  using (true);`}
        />
        <CodeBlock
          tone="good"
          label="Good: each user reads their own row"
          code={`create policy "Users read own profile"
  on profiles for select
  to authenticated
  using ((select auth.uid()) = id);`}
        />
        <TestStep>
          Run the anon curl above against each private table. The result should be <code>[]</code>, not rows. Then query as user A and
          confirm you never see user B&apos;s rows. Try a <code>PATCH</code> on B&apos;s row with A&apos;s token: it should update zero rows.
        </TestStep>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>2. INSERT policy written with USING instead of WITH CHECK</h2>
        <p className="text-zinc-300">
          <code>USING</code> filters rows that already exist. New rows are checked with <code>WITH CHECK</code>. Postgres rejects an INSERT
          policy that has a USING clause (&quot;only WITH CHECK expression allowed for INSERT&quot;), so the migration fails and every
          statement after it in the same file is not applied. That can leave RLS enabled with no working insert policy, or leave later
          policies missing entirely.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: migration errors out"
          code={`create policy "Users insert own todos"
  on todos for insert
  using (auth.uid() = user_id);`}
        />
        <CodeBlock
          tone="good"
          label="Good"
          code={`create policy "Users insert own todos"
  on todos for insert
  to authenticated
  with check ((select auth.uid()) = user_id);`}
        />
        <TestStep>
          Run <code>supabase db reset</code> locally and read the output; a failed migration stops there. Then, as user A, insert a row
          with <code>user_id</code> set to user B&apos;s id. It must be rejected with a row-level security error.
        </TestStep>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>3. Storage bucket policies scoped only by bucket</h2>
        <p className="text-zinc-300">
          Storage uses RLS on <code>storage.objects</code>. A policy that only checks <code>bucket_id</code> applies to every file in that
          bucket, whoever uploaded it. For a private bucket (invoices, documents, IDs) that means any caller can list and download all files;
          for an UPDATE or DELETE policy it means any signed-in user can overwrite or delete other people&apos;s files.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: any user can delete any file in the bucket"
          code={`create policy "Users can delete files"
  on storage.objects for delete
  to authenticated
  using (bucket_id = 'documents');`}
        />
        <CodeBlock
          tone="good"
          label="Good: files live under the owner's folder"
          code={`create policy "Users delete own files"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'documents'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- upload with: supabase.storage.from('documents').upload(\`\${user.id}/\${file.name}\`, file)`}
        />
        <TestStep>
          Upload a file as user B. As user A, call <code>supabase.storage.from(&apos;documents&apos;).list(USER_B_ID)</code>, then{' '}
          <code>download()</code> and <code>remove()</code> on B&apos;s file path. All three should return nothing or an error. Also check
          the bucket is not marked public in the dashboard if it holds private files.
        </TestStep>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>4. Service-role key in client code</h2>
        <p className="text-zinc-300">
          The service-role key bypasses RLS completely. If it reaches the browser, every policy above stops mattering. The usual ways it
          leaks: a <code>NEXT_PUBLIC_</code> prefix on the variable, importing an admin client into a <code>&apos;use client&apos;</code>{' '}
          component, or pasting the key straight into source.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: bundled into the browser"
          code={`'use client';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);`}
        />
        <CodeBlock
          tone="good"
          label="Good: server-only module, no NEXT_PUBLIC_ prefix"
          code={`// lib/supabase/admin.ts
import 'server-only';
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);
// Only call this after checking who the caller is.`}
        />
        <TestStep>
          Run a production build, then search the output for the key: open your site, view the JS files in the browser&apos;s Network
          tab, and search for <code>service_role</code> or the first characters of the key. Nothing should match. Also search the repo for{' '}
          <code>NEXT_PUBLIC_</code> variables containing <code>SERVICE_ROLE</code> or <code>SECRET</code>.
        </TestStep>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>5. Foreign key to auth.users without ON DELETE</h2>
        <p className="text-zinc-300">
          This one is not a leak, but it breaks a feature you need for privacy requests: deleting an account. If a table references{' '}
          <code>auth.users</code> without an <code>ON DELETE</code> rule, deleting a user who owns rows there fails with a foreign key
          violation.
        </p>
        <CodeBlock tone="bad" label="Bad" code={`user_id uuid references auth.users(id)`} />
        <CodeBlock tone="good" label="Good" code={`user_id uuid references auth.users(id) on delete cascade`} />
        <TestStep>
          Create a test user, create a row in every user-owned table for them, then delete the user from Authentication, Users. It should
          succeed. Full walkthrough:{' '}
          <Link href="/guides/supabase-user-delete-foreign-key" className="text-emerald-400 hover:text-emerald-300 underline">
            Supabase: can&apos;t delete user (foreign key violation)
          </Link>
          .
        </TestStep>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Quick checklist</h2>
        <ul className="list-disc pl-5 space-y-1 text-zinc-300">
          <li>RLS is enabled on every table in the <code>public</code> schema.</li>
          <li>The anon key returns no rows from private tables.</li>
          <li>User A cannot read, update or delete user B&apos;s rows or files.</li>
          <li>All migrations apply cleanly from scratch.</li>
          <li>The service-role key is not in any browser bundle or <code>NEXT_PUBLIC_</code> variable.</li>
          <li>Deleting a test user with data succeeds.</li>
        </ul>
      </section>

      <ZelsisCatches
        rules={[
          { id: 'GAP-17', title: 'RLS policy lets anyone read every row (USING (true)) on a table with private data' },
          { id: 'GAP-01', title: 'RLS policy lets any client modify every row (USING (true))' },
          { id: 'BUG-14', title: 'INSERT policy uses USING instead of WITH CHECK (migration fails)' },
          { id: 'GAP-21', title: 'Storage policy lets every caller read all files in a private bucket' },
          { id: 'NEXT-SB-05', title: 'Storage policy lets any user overwrite or delete every file in the bucket' },
          { id: 'SEC-36', title: 'Public exposure of backend secret via NEXT_PUBLIC_ environment variable' },
          { id: 'SEC-SECRET-18', title: 'Supabase service role secret key in source' },
          { id: 'BUG-17', title: 'Foreign key to auth.users has no ON DELETE rule (user deletion fails)' },
        ]}
      >
        Zelsis reads your SQL migrations and source files and flags these patterns with the file and line. The manual tests above are still
        worth running: static checks see your code, not the policies you changed by hand in the dashboard.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
