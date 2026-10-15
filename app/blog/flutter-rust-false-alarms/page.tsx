import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, ScanCta } from '@/components/guides/GuideParts';
import { formatPostDate } from '../posts';

export const metadata: Metadata = {
  title: 'We Ran Our Release Checks on a Flutter App and a Rust Service. Most Alarms Were Ours. - Zelsis Blog',
  description:
    'LocalSend and Lemmy joined our benchmark. What the checks got wrong (format! in error messages, pinned self-signed certs, placeholder CI passwords, USER $NAME) and what was worth a look.',
};

const PUBLISHED = '2026-10-15';
const H2 = 'text-xl font-semibold text-white';
const SECTION = 'space-y-3 border-t border-white/10 pt-6';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function FlutterRustFalseAlarmsPost() {
  return (
    <article className="space-y-6">
      <header className="space-y-2">
        <time dateTime={PUBLISHED} className="text-xs font-mono text-zinc-500">{formatPostDate(PUBLISHED)}</time>
        <h1 className="text-3xl font-bold text-white m-0">We ran our release checks on a Flutter app and a Rust service. Most of the alarms were ours.</h1>
      </header>
      <p className="text-zinc-300">
        Our benchmark is a set of open-source projects we scan every time the rules change. Well-run projects are in it to catch false
        alarms: a person reads every high-severity finding on them, and a rule that is wrong gets fixed or stops blocking releases. Until
        this week the set had no Flutter app and no Rust web service, so we added two:{' '}
        <a href="https://github.com/localsend/localsend" className={LINK}>LocalSend</a>, a Flutter app with a Rust core for sending files
        between devices on the same network, and <a href="https://github.com/LemmyNet/lemmy" className={LINK}>Lemmy</a>, a Rust forum
        server on Actix and Postgres.
      </p>
      <p className="text-zinc-300">
        The first scan flagged both of them hard. After reading every finding, most turned out to be our mistakes, so this post is mainly
        about what we got wrong, because the same patterns are in plenty of other codebases.
      </p>

      <section className={SECTION}>
        <h2 className={H2}>&quot;delete&quot; in an error message is not SQL</h2>
        <p className="text-zinc-300">
          The Rust SQL injection check looked for <code>format!</code> strings containing words like SELECT, UPDATE or DELETE. That caught
          these:
        </p>
        <CodeBlock
          tone="bad"
          label="Flagged, not SQL"
          code={`format!("Invalid identity file: {} (delete it to generate a new identity)", path.display())
format!("{}internal/delete?alias={}", pictrs_config.url, alias)
format!("Failed to update {} hot_ranks: {}", table_name, e)`}
        />
        <p className="text-zinc-300">
          The check now asks for the shape of a query (SELECT … FROM, INSERT INTO, UPDATE … SET, DELETE FROM) plus an interpolation, and
          it reads raw strings like <code>r#&quot;...&quot;#</code>, which the old version skipped entirely. That second part matters:
          Lemmy does build some SQL with <code>format!</code>, in raw strings the old check never looked at.
        </p>
        <CodeBlock
          label="Still reported, for review"
          code={`sql_query(format!(
  r#"WITH batch AS (SELECT a.id FROM {table_name} a WHERE ... AND ({where_clause}) ...)"#
))`}
        />
        <p className="text-zinc-300">
          Here the table name and clause come from Lemmy&apos;s own code, so nothing a user sends reaches the string today. We still report
          it, because the function signature does not stop a future caller from passing user input, and a reviewer should know the query
          is assembled by hand.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Accepting a self-signed certificate is fine if you pin it yourself</h2>
        <p className="text-zinc-300">LocalSend&apos;s Rust client turns off normal certificate checks:</p>
        <CodeBlock
          code={`reqwest::Client::builder()
    .use_rustls_tls()
    .danger_accept_invalid_certs(true)
    .tls_info(true)`}
        />
        <p className="text-zinc-300">
          On its own that line means anyone on the network can impersonate the other side. LocalSend devices use self-signed certificates,
          so a public CA could not vouch for them anyway. Instead the client reads the peer certificate (<code>tls_info(true)</code>) and
          checks its fingerprint against the one it expects. That is certificate pinning done by hand, and it is the right design for
          devices on a LAN. The check now skips clients that read and verify the peer certificate in the same file.
        </p>
        <p className="text-zinc-300">
          The Flutter side had a similar case: a Dart <code>badCertificateCallback</code> that returns <code>true</code>, in a helper that
          only ever connects to <code>127.0.0.1</code>, meaning the app talking to itself. There is no network path to intercept, so
          loopback-only clients are no longer reported.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>A password called &quot;password&quot; in CI is not a leak</h2>
        <p className="text-zinc-300">Lemmy&apos;s CI runs Postgres as a service container:</p>
        <CodeBlock code={`LEMMY_DATABASE_URL: postgres://lemmy:password@database:5432/lemmy`} />
        <p className="text-zinc-300">
          We already skipped localhost URLs, but this host is the CI service name, and the dev script builds the host from a shell
          variable. Neither is a credential anyone could use. Literal placeholder passwords (<code>password</code>, <code>changeme</code>,
          <code>example</code> and similar) and hosts taken from a variable are now skipped. A real-looking password on a real hostname is
          still reported.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>A PEM header is not a private key</h2>
        <p className="text-zinc-300">LocalSend has tests that check the format of a generated key:</p>
        <CodeBlock code={`assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));`} />
        <p className="text-zinc-300">
          The secret check matched the header and reported a committed private key. It now needs key material after the header before it
          calls something a key.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>USER $UNAME is a non-root user</h2>
        <p className="text-zinc-300">Lemmy&apos;s Dockerfile creates a user from build arguments and switches to it:</p>
        <CodeBlock
          code={`RUN groupadd -g \${GID} -o \${UNAME} && \\
  useradd -m -u \${UID} -g \${GID} -o -s /bin/bash \${UNAME}
USER $UNAME`}
        />
        <p className="text-zinc-300">
          Two of our container checks only accepted a literal name after <code>USER</code>, so they reported the image as running as
          root. Both now accept <code>USER $NAME</code> and <code>USER $&#123;NAME&#125;</code>.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>What was worth a look</h2>
        <p className="text-zinc-300">
          LocalSend&apos;s Android manifest sets <code>usesCleartextTraffic=&quot;true&quot;</code>. For an app that talks to other
          devices on the local network and has a plain HTTP mode, that is a deliberate trade-off, but it applies to every request the app
          makes, and a network security config could limit it to the cases that need it. Its server Dockerfile also has no{' '}
          <code>USER</code> line, so that container does run as root.
        </p>
        <p className="text-zinc-300">
          Neither project had the kind of problem the first scan suggested. Both are careful codebases, and the rule fixes they led to apply
          to every Rust and Dart project we scan.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>How we decide what counts</h2>
        <p className="text-zinc-300">
          A finding on a benchmark project is either confirmed by reading the code, or the rule is changed. We do not count a project as
          clean by hiding findings on it. Every rule change ships with a test that keeps the real case reported and the false one quiet,
          and the scan of the vulnerable apps in the benchmark has to find the same flaws afterwards. The changes from this round are in the{' '}
          <Link href="/changelog" className={LINK}>changelog</Link>.
        </p>
      </section>

      <ScanCta />
    </article>
  );
}
