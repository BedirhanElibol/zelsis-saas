import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Postgres Migrations That Lock Your Tables (and Safe Versions) - Zelsis Guides',
  description:
    'Why a migration can freeze checkout during a deploy: CREATE INDEX without CONCURRENTLY, SET NOT NULL on a big table, and the lock queue. Safe patterns and a lock_timeout you can add today.',
  alternates: { canonical: '/guides/postgres-migration-locks' },
};

const H2 = 'text-xl font-semibold text-white';

export default function PostgresMigrationLocksPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Postgres migrations that lock your tables</h1>
      <p className="text-zinc-400">
        The migration ran in two seconds on staging. In production the orders table has a few million rows, the migration holds a
        lock while it works, and every checkout waits behind it. Nothing errors; the site just stops answering until the deploy
        finishes. These are the statements that cause it and the versions that do not.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>1. CREATE INDEX blocks writes</h2>
        <p className="text-zinc-300">
          A plain <code>CREATE INDEX</code> blocks inserts, updates and deletes on the table until the index is built. On a large table
          that can take minutes.
        </p>
        <CodeBlock tone="bad" label="Writes to orders wait until this finishes" code={`create index orders_customer_id_idx on orders (customer_id);`} />
        <CodeBlock
          tone="good"
          label="Builds while writes continue"
          code={`create index concurrently orders_customer_id_idx on orders (customer_id);`}
        />
        <p className="text-zinc-300">
          <code>CONCURRENTLY</code> cannot run inside a transaction, so most migration tools need it in a migration of its own with the
          transaction turned off. If it fails halfway it leaves an invalid index; drop it and run it again.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>2. SET NOT NULL scans the whole table under the strictest lock</h2>
        <p className="text-zinc-300">
          <code>ALTER TABLE ... ALTER COLUMN ... SET NOT NULL</code> takes an ACCESS EXCLUSIVE lock, which blocks reads too, and keeps it
          while Postgres checks every row. On Postgres 12 and later you can do the check first without blocking anyone.
        </p>
        <CodeBlock tone="bad" label="Reads and writes stop while every row is checked" code={`alter table orders alter column shop_id set not null;`} />
        <CodeBlock
          tone="good"
          label="Check without blocking, then the lock is only held for a moment"
          code={`alter table orders add constraint orders_shop_id_not_null check (shop_id is not null) not valid;
alter table orders validate constraint orders_shop_id_not_null;  -- scans, but allows reads and writes
alter table orders alter column shop_id set not null;             -- uses the valid constraint, no scan
alter table orders drop constraint orders_shop_id_not_null;`}
        />
        <p className="text-zinc-300">
          Adding a new column with a constant default (<code>add column status text not null default &apos;new&apos;</code>) is fast on
          Postgres 11 and later because existing rows are not rewritten. A volatile default such as <code>now()</code> or{' '}
          <code>gen_random_uuid()</code> still rewrites the table.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>3. The lock queue: a quick ALTER can still freeze the site</h2>
        <p className="text-zinc-300">
          Even an ALTER that needs its lock for a millisecond has to wait for running queries to finish. While it waits, every new query
          on that table queues behind it. One slow report query plus one migration is enough to stop checkout. Set a lock timeout so the
          migration gives up and retries instead of holding everyone up.
        </p>
        <CodeBlock
          tone="good"
          label="At the top of each migration"
          code={`set lock_timeout = '3s';
set statement_timeout = '15min';`}
        />
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Test it before you ship</h2>
        <TestStep>
          Restore a production-sized copy (or generate a few million rows) and run the migration while a script inserts rows in a loop.
          If the inserts pause, the migration locks the table.
        </TestStep>
        <TestStep>
          During the run, check <code>select pid, mode, granted, query from pg_locks join pg_stat_activity using (pid) where relation =
          &apos;orders&apos;::regclass;</code> to see which lock the migration holds and who is waiting.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'DB-PERF-51', title: 'Migration takes a blocking table lock on an existing table' }]}>
        Zelsis reads the migrations in each pull request and flags non-concurrent indexes and NOT NULL changes on existing tables, with
        the safe version to paste in.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
