import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, ScanCta } from '@/components/guides/GuideParts';
import { formatPostDate } from '../posts';

export const metadata: Metadata = {
  title: 'What a Release Check Found in Well-Kept Open-Source Apps - Zelsis Blog',
  description:
    'A fallback JWT secret, a storage policy that ignores the owner, an unpinned SECURITY DEFINER function, root containers, tag-pinned CI actions and Android config issues, each with the fix.',
};

const PUBLISHED = '2026-10-15';
const H2 = 'text-xl font-semibold text-white';
const SECTION = 'space-y-3 border-t border-white/10 pt-6';

export default function OpenSourceReleaseCheckPost() {
  return (
    <article className="space-y-6">
      <header className="space-y-2">
        <time dateTime={PUBLISHED} className="text-xs font-mono text-zinc-500">{formatPostDate(PUBLISHED)}</time>
        <h1 className="text-3xl font-bold text-white m-0">What a release check found in well-kept open-source apps</h1>
      </header>
      <p className="text-zinc-300">
        We keep a public benchmark of open-source projects that people copy from: SaaS starters, framework example apps, a few production
        products and some Android apps. They are well maintained and widely forked, and most of them have nothing seriously wrong. We use
        them to measure false alarms, so a person reads every high-severity finding on them before we count it as real.
      </p>
      <p className="text-zinc-300">
        Some of those findings held up. None of them is exotic. They are the kind of thing that gets copied into a new project on day one
        and is still there when it ships, so here they are with the fix for each. We left out project names because several are not fixed
        upstream yet, and the snippets show the shape of each issue rather than the exact upstream code.
      </p>

      <section className={SECTION}>
        <h2 className={H2}>A fallback secret that signs real tokens</h2>
        <p className="text-zinc-300">An Express example app signs its JWTs with this:</p>
        <CodeBlock tone="bad" code={`const secret = process.env.JWT_SECRET || 'superSecret';`} />
        <p className="text-zinc-300">
          Locally this is convenient. In production, if the variable goes missing because a deploy dropped it or someone renamed it, the
          app keeps running and signs tokens with a key anyone can read in the repo. Nothing errors, so nobody notices. Fail at startup
          instead:
        </p>
        <CodeBlock
          tone="good"
          code={`const secret = process.env.JWT_SECRET;
if (!secret) throw new Error('JWT_SECRET is not set');`}
        />
      </section>

      <section className={SECTION}>
        <h2 className={H2}>A storage policy that only checks the bucket</h2>
        <p className="text-zinc-300">A test migration in a database client library has a storage policy shaped like this:</p>
        <CodeBlock
          tone="bad"
          code={`create policy "avatars" on storage.objects
  for all using (bucket_id = 'avatars');`}
        />
        <p className="text-zinc-300">
          <code>for all</code> covers insert, update and delete, and the condition never looks at who owns the file, so any signed-in user
          can overwrite or delete anyone&apos;s avatar. The same project has a <code>using (true)</code> read policy that makes every row
          of a table public. In an example that may be on purpose, but example migrations are exactly what people paste into real
          projects. Scope write policies to the owner:
        </p>
        <CodeBlock
          tone="good"
          code={`create policy "owners update own files" on storage.objects
  for update using (bucket_id = 'avatars' and (select auth.uid()) = owner_id::uuid);`}
        />
      </section>

      <section className={SECTION}>
        <h2 className={H2}>A SECURITY DEFINER function without a search path</h2>
        <p className="text-zinc-300">
          A popular subscription starter creates a trigger function that runs with its owner&apos;s privileges and no fixed{' '}
          <code>search_path</code>:
        </p>
        <CodeBlock
          tone="bad"
          code={`create function public.handle_new_user() returns trigger
language plpgsql security definer as $$ ... $$;`}
        />
        <p className="text-zinc-300">
          The function then resolves table names through whatever schemas the calling session puts first. If a user can create objects in
          one of those schemas, they can shadow a table the function writes to and run code as the owner. Pin the path and schema-qualify
          the tables:
        </p>
        <CodeBlock
          tone="good"
          code={`create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$ ... $$;`}
        />
        <p className="text-zinc-300">
          The same starter pins Next.js 14.2.3. That version is affected by CVE-2025-29927, where a request header lets a caller skip
          middleware, including any auth check that lives there. The fix is an upgrade, plus a dependency check in CI so the next advisory
          shows up in a pull request.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Containers that run as root and a database on every interface</h2>
        <p className="text-zinc-300">
          Several Dockerfiles in the set have no <code>USER</code> line, so the app runs as root inside the container. A compose file
          publishes Postgres like this:
        </p>
        <CodeBlock
          tone="bad"
          code={`ports:
  - "5432:5432"`}
        />
        <p className="text-zinc-300">
          That binds to all interfaces. On a laptop it hardly matters. On a VPS without a firewall in front, the database is on the
          internet. Use <code>&quot;127.0.0.1:5432:5432&quot;</code> unless something outside the host needs it, and give the image a
          non-root user:
        </p>
        <CodeBlock
          tone="good"
          code={`RUN useradd --create-home app
USER app`}
        />
      </section>

      <section className={SECTION}>
        <h2 className={H2}>CI actions pinned to a tag</h2>
        <p className="text-zinc-300">
          Workflows reference third-party actions as <code>some-org/some-action@v3</code>. Whoever controls that repo can move the tag to
          different code, and the job often holds a token with write access. Pin to the full commit SHA and keep the tag in a comment, so
          the code that runs is the code you reviewed:
        </p>
        <CodeBlock tone="good" code={`- uses: some-org/some-action@<full-commit-sha> # v3`} />
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Android: cleartext traffic, exported components and a feed parser</h2>
        <p className="text-zinc-300">
          An open-source Android podcast app sets <code>android:usesCleartextTraffic=&quot;true&quot;</code> so feeds and media can load
          over plain HTTP. For a podcast player that is a real trade-off, since some feeds are still HTTP only, but the flag applies to
          every request the app makes. A network security config can allow cleartext for the hosts that need it and keep everything else
          on HTTPS.
        </p>
        <p className="text-zinc-300">
          The same app exports a broadcast receiver and a widget that accept its own custom actions, so any other installed app can send
          them. If only the system needs to reach a component, a permission on it, or a separate unexported component for the app&apos;s
          internal actions, closes that.
        </p>
        <p className="text-zinc-300">
          It also parses remote feeds with a default <code>SAXParserFactory</code> and no DTD or external-entity settings, on XML that
          comes straight from the internet. Whether that is exploitable depends on the parser underneath, which is a good reason to set
          those features explicitly and test them on the Android versions you support.
        </p>
        <p className="text-zinc-300">
          A database upgrade step builds <code>UPDATE ... WHERE file_url=&apos;...&apos;</code> by concatenating a file path into the
          string. A path with a quote in it breaks the query. That is a bug before it is a security issue, and a bound parameter fixes
          both.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>A migration that locks a busy table</h2>
        <p className="text-zinc-300">
          One migration creates an index on an existing table without <code>CONCURRENTLY</code>. On Postgres, a plain{' '}
          <code>CREATE INDEX</code> blocks writes to the table until the build finishes. On a small table nobody notices. On a large one,
          the deploy that runs it stops writes for as long as the index takes.
        </p>
        <CodeBlock tone="good" code={`create index concurrently if not exists idx_orders_user on orders (user_id);`} />
        <p className="text-zinc-300">
          <code>CONCURRENTLY</code> can&apos;t run inside a transaction, so some migration tools need it in a migration of its own.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Checking your own project</h2>
        <p className="text-zinc-300">
          None of this needs a pentest. Each issue is visible in code or config, and each fix is a few lines. The hard part is noticing
          before release, when nobody is reading the Dockerfile or the old migrations anymore.
        </p>
        <p className="text-zinc-300">
          We build Zelsis to run that check on every pull request, across code, dependencies, migrations, containers and CI config, in
          most languages. If you maintain one of the projects above and want the details, write to{' '}
          <a href="mailto:contact@zelsis.com" className="text-emerald-400 hover:text-emerald-300 underline">contact@zelsis.com</a> and
          we&apos;ll send what we found.
        </p>
      </section>

      <ScanCta />
    </article>
  );
}
