import React from 'react';
import type { Metadata } from 'next';
import { ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Zelsis vs CodeRabbit: Five Pull Requests With Planted Flaws - Zelsis Guides',
  description:
    'We opened five pull requests, each with one security flaw written down in advance, and let Zelsis and CodeRabbit review them with default settings. What each found, what each missed, and how they differ.',
  alternates: { canonical: '/guides/zelsis-vs-coderabbit' },
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';
const REPO = 'https://github.com/BedirhanElibol/review-bench-app';

const ROWS = [
  {
    pr: 1,
    change: 'Team notes table and a server action',
    flaw: 'No row level security on the table, and the action does not check team membership',
    zelsis: 'Found the missing RLS. Did not report the missing membership check on its own.',
    coderabbit: 'Named both problems in its summary as "High, inferred", but left no line comment for either.',
  },
  {
    pr: 2,
    change: 'Promotional price at checkout',
    flaw: 'The amount comes from the browser, so 50 can be sent instead of 2900',
    zelsis: 'Found it',
    coderabbit: 'Found it',
  },
  {
    pr: 3,
    change: 'Token for a public API',
    flaw: 'parseToken never checks the signature, so anyone can write role: admin',
    zelsis: 'Found it',
    coderabbit: 'Found it',
  },
  {
    pr: 4,
    change: 'Credits from a Stripe webhook',
    flaw: 'No signature check, the same event can be applied twice, concurrent requests lose credits',
    zelsis: 'Found all three',
    coderabbit: 'Found all three',
  },
  {
    pr: 5,
    change: 'Sign in with a phone code',
    flaw: 'No rate limit on sending SMS, so anyone can run up the SMS bill',
    zelsis: 'Found it, as a warning that does not block the merge',
    coderabbit: 'Found it',
  },
];

export default function ZelsisVsCoderabbitPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Zelsis vs CodeRabbit: five pull requests with planted flaws</h1>
      <p className="text-zinc-400">
        We built a small Next.js and Supabase app and opened five pull requests against it. Each one adds a normal-looking feature
        with one security flaw, and we wrote the flaws down before either tool ran. Both tools reviewed the same pull requests with
        their default settings. The code, the pull requests and every comment both tools left are public in{' '}
        <a href={REPO} className={LINK}>
          review-bench-app
        </a>
        , so you can check each result yourself.
      </p>
      <p className="text-zinc-400">
        Zelsis is our product, so read this with that in mind. We publish the cases where CodeRabbit did better too.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>Results (October 2026)</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs sm:text-sm border-collapse">
            <thead>
              <tr className="text-zinc-400 border-b border-white/10">
                <th className="py-2 pr-3">PR</th>
                <th className="py-2 pr-3">Planted flaw</th>
                <th className="py-2 pr-3">Zelsis</th>
                <th className="py-2">CodeRabbit</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((r) => (
                <tr key={r.pr} className="border-b border-white/5 align-top">
                  <td className="py-2 pr-3 text-zinc-400">
                    <a href={`${REPO}/pull/${r.pr}`} className={LINK}>
                      #{r.pr}
                    </a>
                  </td>
                  <td className="py-2 pr-3 text-zinc-300">
                    <span className="text-white">{r.change}.</span> {r.flaw}.
                  </td>
                  <td className="py-2 pr-3 text-zinc-300">{r.zelsis}</td>
                  <td className="py-2 text-zinc-300">{r.coderabbit}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-zinc-300">
          On the planted flaws the two tools came out close. CodeRabbit handled pull request 1 better: it noticed the missing team
          membership check, which Zelsis did not report separately, although it only mentioned it in the summary.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Comments that were not about the planted flaw</h2>
        <p className="text-zinc-300">
          Zelsis left one: on pull request 1 it said the server action does not validate its input, which is true of the code.
          CodeRabbit left nine across the five pull requests. Most of them are fair code review points, such as a Supabase{' '}
          <code>error</code> that is never checked or a phone number that is never validated. They are not false alarms; they are a
          different kind of review.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Where they differ</h2>
        <p className="text-zinc-300">
          CodeRabbit is a reviewer. It reads the change, explains its reasoning and comments on correctness and style as well as
          security. It does not stop a merge.
        </p>
        <p className="text-zinc-300">
          Zelsis is a release check. Every finding comes from a rule with a file and a line, and when a proven critical issue is in
          the change, the Zelsis check fails, so a required check blocks the merge. In this test it failed pull requests 1 to 4 and
          passed pull request 5 with a warning, because a missing SMS rate limit is reported as high, not critical. Beyond security,
          it also looks at logic bugs, dependencies with known vulnerabilities, UI and accessibility, privacy, and infrastructure
          config, which this test did not cover.
        </p>
        <p className="text-zinc-300">
          They do different jobs, and plenty of teams will want both: a reviewer that talks about the code, and a check that refuses
          to ship a critical hole.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Limits of this test</h2>
        <ul className="list-disc pl-5 space-y-1 text-zinc-300">
          <li>Five pull requests in one stack is a small sample. Treat it as an example, not a ranking.</li>
          <li>
            Some of CodeRabbit&apos;s security comments carry a &quot;Detected with Advanced Tier&quot; label, so another CodeRabbit
            plan may give different results.
          </li>
          <li>GitHub Copilot code review was not run, because it needs a paid subscription.</li>
          <li>
            While running the test we found a bug in Zelsis: GitHub Actions tokens had grown past 256 characters and the gate API
            rejected them. The results above are from the run after that fix.
          </li>
        </ul>
      </section>

      <ScanCta />
    </article>
  );
}
