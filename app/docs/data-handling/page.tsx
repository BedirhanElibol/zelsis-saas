import React from 'react';
import { CODE_SNIPPET_RETENTION_DAYS } from '@/lib/data-retention';

export const metadata = { title: 'Data Handling - Zelsis Docs' };

export default function DataHandlingPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Data Handling &amp; Security</h1>
      <p className="text-zinc-400">How we process, store and protect your source code and findings.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">What we store</h2>
        <p>
          Files are fetched from GitHub into server memory, scanned and discarded. We never store your repository.
          We keep the findings (rule code, file path, line number, severity) so they appear in your dashboard and scan history,
          plus a short code snippet around each finding for context.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">AI double-check (opt-in)</h2>
        <p>
          Scans are rule-based and send no code to an AI model. On Pro and Team you can turn on an AI double-check in settings. When it is
          on and a pull request has a critical finding, Zelsis sends the flagged file and up to two files it imports to Anthropic&apos;s
          Claude API and asks whether the code already guards against the issue. At most three findings per pull request are checked.
          The model can only lower a blocking finding to high; it cannot add, hide or raise findings. Nothing is sent while the setting
          is off, and Zelsis does not store what was sent.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Retention and location</h2>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong>Code snippets</strong> are erased automatically after <strong>{CODE_SNIPPET_RETENTION_DAYS} days</strong> by a daily
            database job.
          </li>
          <li>
            <strong>Findings and scan history</strong> stay in your account until you delete the project or your account.
          </li>
          <li>
            <strong>Region:</strong> data is stored on Supabase in the EU (Ireland, <code>eu-west-1</code>).
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Service-role key</h2>
        <p>
          Background jobs that must bypass Row Level Security use the <code>SUPABASE_SERVICE_ROLE_KEY</code>. It lives only in
          server-side environment variables and is never sent to the browser. Everything you read in the dashboard goes through
          RLS policies, so you can only see your own and your organization&apos;s data.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Data flow</h2>
        <ol className="list-decimal pl-5 space-y-2">
          <li>You start a scan from the dashboard, the public preview or the CI gate.</li>
          <li>The server fetches the repository files from GitHub into memory (public repos, or private ones with your token).</li>
          <li>The static analysis engine scans them; the file contents are discarded when the scan ends.</li>
          <li>Findings and short snippets are written to the database; snippets are erased after {CODE_SNIPPET_RETENTION_DAYS} days.</li>
        </ol>
      </section>
    </div>
  );
}
