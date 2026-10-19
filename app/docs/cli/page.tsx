import React from 'react';

export const metadata = {
  title: 'CLI and AI Agents (MCP) - Zelsis Docs',
  description: 'Run Zelsis from your terminal before you push, or let Claude Code, Cursor and other AI coding agents check their own changes over MCP.',
};

const pre = 'bg-zinc-900 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-white/10';

const MCP_JSON = `{
  "mcpServers": {
    "zelsis": {
      "command": "npx",
      "args": ["-y", "zelsis", "mcp"],
      "env": { "ZELSIS_API_KEY": "your-key" }
    }
  }
}`;

const SAMPLE_OUTPUT = `CRITICAL app/api/checkout/route.ts:14  Payment Amount or Price Controlled by the Client
         Anyone can edit the request and pay any price they like.
         Fix: Accept only a plan key from the client and look up the price server-side.

Zelsis gate: FAILED · 1 finding(s) in changed files · 214 file(s) scanned`;

export default function CliPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">CLI and AI Agents (MCP)</h1>
      <p className="text-zinc-400">
        Check your changes before you push, from the terminal or from the AI agent that wrote them. Same rules and gate as the
        pull request check.
      </p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">1. Create an API key</h2>
        <p>
          In the dashboard open <strong>Settings → API keys</strong>, create a key and set it as <code>ZELSIS_API_KEY</code> in your
          shell. Node 18 or newer and git are the only requirements.
        </p>
        <pre className={pre}><code className="text-emerald-400">export ZELSIS_API_KEY=your-key</code></pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">2. Run a check</h2>
        <pre className={pre}><code className="text-emerald-400">npx zelsis check</code></pre>
        <p>
          This scans your uncommitted changes. The rest of the repository goes along as context, because some issues only show
          across files (a migration and the route that reads the table, for example), but only the files you changed decide the
          result:
        </p>
        <pre className={pre}><code className="text-zinc-300">{SAMPLE_OUTPUT}</code></pre>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong>FAILED</strong> (exit code 1): a proven critical issue in your changes.</li>
          <li><strong>WARNING</strong> (exit code 0): high-severity issues worth a look. Add <code>--strict</code> to exit 1 here too.</li>
          <li><strong>PASSED</strong> (exit code 0).</li>
        </ul>
        <p>Options:</p>
        <ul className="list-disc pl-5 space-y-2">
          <li><code>--all</code> scans and gates on every file, not only your changes.</li>
          <li><code>--base origin/main</code> also counts commits since that ref as changed. Useful in a pre-push hook.</li>
          <li><code>--json</code> prints the raw result for scripts.</li>
        </ul>
        <p>Fix guidance is shown on Pro and Team plans; on Free each finding names the issue, its line and what it allows.</p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">3. Let your AI agent check its own code</h2>
        <p>
          <code>zelsis mcp</code> starts an MCP server with one tool, <code>zelsis_check</code>. After the agent edits code it can
          call the tool, read the findings and fix them before you review the change.
        </p>
        <p><strong>Claude Code</strong></p>
        <pre className={pre}><code className="text-emerald-400">claude mcp add zelsis --env ZELSIS_API_KEY=your-key -- npx -y zelsis mcp</code></pre>
        <p><strong>Cursor, Windsurf and other MCP clients</strong> (<code>mcp.json</code>)</p>
        <pre className={pre}><code className="text-emerald-400">{MCP_JSON}</code></pre>
        <p>
          To make the agent use it every time, add a line to your project instructions (<code>CLAUDE.md</code>,{' '}
          <code>.cursorrules</code> or similar): &quot;After changing code, run the zelsis_check tool and fix critical and high
          findings before finishing.&quot;
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">What gets sent</h2>
        <ul className="list-disc pl-5 space-y-2">
          <li>Files git tracks, plus new files that are not gitignored. Gitignored files such as <code>.env</code> are never read.</li>
          <li>Build folders, dependencies, binaries, lockfiles and files over 512 KB are skipped.</li>
          <li>Up to about 3.5 MB per check, changed files first.</li>
        </ul>
        <p>
          Files are scanned in memory and released when the check ends, the same as repository scans. See{' '}
          <a href="/docs/data-handling" className="underline hover:text-white">Data Handling</a>.
        </p>
      </section>
    </div>
  );
}
