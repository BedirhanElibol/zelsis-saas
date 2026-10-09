import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: "Supabase: Can't Delete User (Foreign Key Violation) - How to Fix",
  description:
    'Fix "Database error deleting user" in Supabase: a table references auth.users without ON DELETE. Add ON DELETE CASCADE or SET NULL with an ALTER TABLE migration.',
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function SupabaseUserDeleteFkPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Supabase: can&apos;t delete user (foreign key violation)</h1>
      <p className="text-zinc-400">
        You click Delete user in the Supabase dashboard, or call <code>supabase.auth.admin.deleteUser()</code>, and get &quot;Database
        error deleting user&quot;. The Postgres log shows a foreign key violation. The cause is almost always one line in a migration, and
        the fix is a short ALTER TABLE.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>The cause</h2>
        <p className="text-zinc-300">
          Some table in your schema (often <code>profiles</code> or <code>users</code>) has a column that references{' '}
          <code>auth.users</code> without saying what should happen when the user is deleted. The default is <code>NO ACTION</code>:
          Postgres refuses to delete a row that other rows still point to. So the user can be deleted only if they never created any data.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: no ON DELETE rule"
          code={`create table profiles (
  id uuid references auth.users not null primary key,
  full_name text
);

create table posts (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id),
  body text
);`}
        />
        <p className="text-zinc-300">
          This pattern is common in starter templates, which is how it ends up in so many apps. Vercel&apos;s official{' '}
          <code>nextjs-subscription-payments</code> starter ships it in its initial migration (
          <a
            href="https://github.com/vercel/nextjs-subscription-payments/blob/bdd0813/supabase/migrations/20230530034630_init.sql#L7"
            target="_blank"
            rel="noopener noreferrer"
            className={`${LINK} break-all`}
          >
            supabase/migrations/20230530034630_init.sql, line 7
          </a>
          ). More examples are on our{' '}
          <Link href="/docs/real-world-bugs" className={LINK}>
            real bugs page
          </Link>
          .
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Pick CASCADE or SET NULL</h2>
        <ul className="list-disc pl-5 space-y-2 text-zinc-300">
          <li>
            <strong className="text-white">ON DELETE CASCADE</strong> deletes the user&apos;s rows along with the account. Use it for data
            that only makes sense with the user: profiles, settings, private notes, sessions.
          </li>
          <li>
            <strong className="text-white">ON DELETE SET NULL</strong> keeps the rows and clears the owner. Use it for data other people
            depend on, such as comments in a shared thread or orders you must keep for accounting. The column must be nullable (no{' '}
            <code>NOT NULL</code>), and your UI has to handle a missing author.
          </li>
        </ul>
        <CodeBlock
          tone="good"
          label="Good: new tables"
          code={`create table profiles (
  id uuid not null primary key references auth.users(id) on delete cascade,
  full_name text
);

create table posts (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  body text
);`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>The fix for an existing database</h2>
        <p className="text-zinc-300">
          You cannot change an existing foreign key in place. Drop it and add it again with the rule, in a new migration. First find the
          constraint names:
        </p>
        <CodeBlock
          label="Find every foreign key that points at auth.users"
          code={`select conrelid::regclass as table_name,
       conname          as constraint_name,
       pg_get_constraintdef(oid) as definition
from pg_constraint
where contype = 'f'
  and confrelid = 'auth.users'::regclass;`}
        />
        <p className="text-zinc-300">
          Any row whose definition does not end in <code>ON DELETE CASCADE</code> or <code>ON DELETE SET NULL</code> needs fixing. Postgres
          names them <code>&lt;table&gt;_&lt;column&gt;_fkey</code> by default:
        </p>
        <CodeBlock
          tone="good"
          label="supabase/migrations/20260101000000_fix_user_fks.sql"
          code={`alter table public.profiles
  drop constraint profiles_id_fkey,
  add constraint profiles_id_fkey
    foreign key (id) references auth.users(id) on delete cascade;

alter table public.posts
  drop constraint posts_user_id_fkey,
  add constraint posts_user_id_fkey
    foreign key (user_id) references auth.users(id) on delete set null;`}
        />
        <p className="text-zinc-300">
          Both steps run inside one statement, so there is no moment without the constraint. Create the file with{' '}
          <code>supabase migration new fix_user_fks</code> and apply it with <code>supabase db push</code>. Check tables that reference{' '}
          <code>profiles</code> too: if <code>profiles</code> rows now cascade away, their children need a rule as well.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Verify it</h2>
        <TestStep>
          Create a test user, give them a row in every user-owned table, then delete them from Authentication, Users. The delete should
          succeed, CASCADE tables should have no rows left for that id, and SET NULL tables should keep their rows with an empty owner.
          Re-run the constraint query above: nothing should be missing a rule.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'BUG-17', title: 'Foreign key to auth.users has no ON DELETE rule (user deletion fails)' }]}>
        Zelsis reads the SQL migrations in your repository and flags every <code>references auth.users</code> line that has no{' '}
        <code>on delete</code> rule, with the file, the line and the fix.
      </ZelsisCatches>

      <p className="text-zinc-400">
        Related:{' '}
        <Link href="/guides/supabase-rls-testing" className={LINK}>
          How to test Supabase RLS before you ship
        </Link>
        .
      </p>

      <ScanCta />
    </article>
  );
}
