import React from 'react';
import { buildGateActionWorkflow, buildGateWorkflow } from '@/lib/ci-gate-snippet';
import { getConfiguredAppUrl } from '@/lib/app-url';

export const metadata = { title: 'CI Release Gate - Zelsis Docs' };

export default function CIGatePage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">CI Release Gate</h1>
      <p className="text-zinc-400">Run Zelsis on every pull request and block the merge when a proven critical issue is introduced.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">1. Create an API key</h2>
        <p>
          In the dashboard open <strong>Settings → API keys</strong> and create a key. Add it to your repository as the
          secret <code>ZELSIS_API_KEY</code> (GitHub: Settings → Secrets and variables → Actions). Private repositories cannot be
          gated without it.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">2. Add the workflow</h2>
        <p>
          The short way: save this as <code>.github/workflows/zelsis.yml</code>. The action sends the head and base commits on a
          pull request, so the gate only fails on findings the pull request introduces. For production, pin the action to a
          commit SHA instead of <code>@main</code>.
        </p>
        <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-white/10">
          <code className="text-emerald-400">{buildGateActionWorkflow()}</code>
        </pre>
        <p>
          Inputs: <code>api-key</code>, <code>app-url</code>, <code>fail-open</code> (pass the gate if Zelsis is unreachable),
          <code> fail-on-failed</code> and <code>upload-report</code>. Outputs: <code>status</code> and <code>score</code>.
        </p>
        <p>The same workflow without the action, as plain shell, if you would rather not depend on another repository:</p>
        <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-white/10">
          <code className="text-emerald-400">{buildGateWorkflow({ appUrl: getConfiguredAppUrl() })}</code>
        </pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Findings on the pull request diff</h2>
        <p>
          On a pull request the job only reports findings in files the PR changes, and each one appears on its line in the
          &quot;Files changed&quot; tab: critical and high as errors, medium as warnings (up to 10 of each, the most severe
          first). No GitHub App is needed; the job prints GitHub&apos;s standard annotation commands.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">When the Zelsis API is unreachable</h2>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong>Fail-closed (default):</strong> the job fails, so unverified code is not merged.
          </li>
          <li>
            <strong>Fail-open:</strong> set the repository variable <code>ZELSIS_FAIL_OPEN</code> to <code>true</code> and the job
            passes when the API cannot be reached.
          </li>
        </ul>
        <p>
          A rejected request (for example a missing or revoked API key) always fails with an error message; it is never reported as
          a vulnerability. Which severities block the release is configured separately with <code>failStrategy</code> in{' '}
          <a href="/docs/configuration" className="underline hover:text-white">.zelsisrc.json</a>.
        </p>
      </section>
    </div>
  );
}
