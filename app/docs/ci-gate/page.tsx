import React from 'react';

export const metadata = { title: 'CI Release Gate - Zelsis Docs' };

export default function CIGatePage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">CI Release Gate</h1>
      <p className="text-zinc-400">Integrate Zelsis into your GitHub Actions pipeline to prevent vulnerable code from being merged.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">GitHub Actions Example</h2>
        <p>
          Add the following workflow file (e.g., <code>.github/workflows/zelsis.yml</code>) to your repository. 
          It uses the PR ref and base parameters to trigger an isolated audit without polluting your main branch metrics.
        </p>
        <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm font-mono border border-white/10">
          <code className="text-emerald-400">
{`name: Zelsis Security Gate

on:
  pull_request:
    branches: [ "main" ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Zelsis Audit
        run: |
          curl -X POST https://api.zelsis.com/v1/scan \\
            -H "Authorization: Bearer \${{ secrets.ZELSIS_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{
              "repo": "\${{ github.repository }}",
              "pr_ref": "\${{ github.head_ref }}",
              "base_ref": "\${{ github.base_ref }}"
            }'`}
          </code>
        </pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Fail-Open vs. Fail-Closed</h2>
        <p>
          You can configure the behavior of the CI gate in the event that the Zelsis API is unreachable or times out:
        </p>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong>Fail-Open:</strong> The pipeline continues and allows the PR to be merged even if the scan fails to complete. 
            Recommended for teams prioritizing velocity over strict enforcement.
          </li>
          <li>
            <strong>Fail-Closed:</strong> The pipeline fails and blocks the PR if the scan cannot complete. 
            Recommended for highly regulated environments where unverified code must never reach production.
          </li>
        </ul>
        <p>
          This can be configured in your <code>.zelsisrc.json</code> via the <code>failStrategy</code> setting (e.g., <code>smart</code>, <code>strict</code>, or <code>advisory</code>).
        </p>
      </section>
    </div>
  );
}
