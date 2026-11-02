import React from 'react';

export const metadata = {
  title: 'VS Code Extension - Zelsis Docs',
  description: 'Check your changed files with Zelsis inside VS Code and see each finding as a problem on the line, with the fix and its CWE.',
  alternates: { canonical: '/docs/vscode' },
};

const pre = 'bg-zinc-900 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-white/10';

export default function VscodePage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">VS Code Extension</h1>
      <p className="text-zinc-400">
        Check your changes before you commit, without leaving the editor. Findings appear in the Problems panel and under the
        line they point at, with the fix and a CWE link where one applies. The extension uses the same rules and gate as the pull
        request check and the CLI.
      </p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">1. Install</h2>
        <p>
          Open the Extensions view (<code>Ctrl+Shift+X</code>, or <code>Cmd+Shift+X</code> on macOS), search for{' '}
          <strong>Zelsis</strong> and select <strong>Install</strong>. You can also install it from the{' '}
          <a href="https://marketplace.visualstudio.com/items?itemName=zelsis.zelsis" className="text-emerald-400 hover:text-emerald-300 underline">
            Visual Studio Marketplace
          </a>{' '}
          or from a terminal:
        </p>
        <pre className={pre}><code className="text-emerald-400">code --install-extension zelsis.zelsis</code></pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">2. Add your API key</h2>
        <p>
          In the dashboard open <strong>Settings → API keys</strong> and create a key. In VS Code open the Command Palette
          (<code>Ctrl+Shift+P</code>) and run <strong>Zelsis: Set API Key</strong>. The key is kept in the editor&apos;s secret
          storage. A <code>ZELSIS_API_KEY</code> environment variable works too.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">3. Run a check</h2>
        <p>Open a folder that is a git repository and run one of these from the Command Palette:</p>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong>Zelsis: Check Changed Files</strong> scans your uncommitted changes. The rest of the repository goes along
            as context, but only the files you changed decide the result.
          </li>
          <li><strong>Zelsis: Check Whole Workspace</strong> gates on every file.</li>
          <li><strong>Zelsis: Clear Findings</strong> removes the results from the editor.</li>
        </ul>
        <p>
          Each finding shows as a problem: critical and high as errors, medium as warnings, low as information. Hover the line
          to read the fix, and select the code (for example <code>ZLS-33 CWE-78</code>) to open the CWE entry. The status bar
          shows the gate result and the number of findings; select it to run the check again.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Settings</h2>
        <ul className="list-disc pl-5 space-y-2">
          <li><code>zelsis.url</code>: the server to use. The default is <code>https://zelsis.com</code>.</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">What is sent</h2>
        <p>
          Files are scanned in memory on the Zelsis server and are not stored. Build folders, binaries and lockfiles are not
          sent. On the free plan the fix text is replaced by a short note, as in the dashboard.
        </p>
      </section>
    </div>
  );
}
