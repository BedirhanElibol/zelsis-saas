import React from 'react';
import Link from 'next/link';

interface Place {
  title: string;
  body: string;
  code?: string;
  href: string;
  linkLabel: string;
  note?: string;
}

/** Only places that were run end to end against zelsis.com belong here. */
const PLACES: Place[] = [
  {
    title: 'VS Code',
    body: 'Run the check from the command palette. Each finding appears under its line with the fix and a CWE link.',
    href: '/docs/vscode',
    linkLabel: 'Install the extension',
  },
  {
    title: 'Every pull request',
    body: 'The GitHub Action runs the check on each PR and fails the build when a change ships a critical bug.',
    href: '/docs/ci-gate',
    linkLabel: 'Set up the CI gate',
  },
  {
    title: 'Your terminal and AI agents',
    body: 'Check uncommitted changes before you push. Claude Code, Cursor and other agents can run it on their own work through MCP. Export SARIF for code scanning and an SBOM in CycloneDX or SPDX.',
    code: 'npx zelsis check',
    href: '/docs/cli',
    linkLabel: 'CLI and MCP guide',
  },
  {
    title: 'Jira',
    body: 'Open a Jira issue from any finding in one click, with the location, severity and fix filled in.',
    href: '/#pricing',
    linkLabel: 'See plans',
    note: 'Pro and Team',
  },
];

export function WorksWhereYouWork() {
  return (
    <section id="integrations" className="py-12 sm:py-14 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-7xl mx-auto flex flex-col gap-10">
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center text-xs uppercase tracking-widest text-emerald-400">
            <span>Where it runs</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            The same check in every step of your work
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed">
            One set of rules from the editor to the pull request, so a bug caught early is caught the same way later.
          </p>
        </div>

        <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 list-none p-0 m-0">
          {PLACES.map(({ title, body, code, href, linkLabel, note }) => (
            <li key={title} className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-[#121214] p-5">
              {note && <span className="self-start px-2 py-0.5 rounded bg-white/5 text-[0.68rem] font-mono text-zinc-300">{note}</span>}
              <h3 className="text-lg font-bold text-white m-0">{title}</h3>
              <p className="text-sm text-zinc-400 leading-relaxed m-0">{body}</p>
              {code && <code className="self-start px-2 py-1 rounded bg-black/40 border border-white/10 text-xs font-mono text-emerald-300">{code}</code>}
              <Link href={href} className="mt-auto inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-400 hover:text-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 rounded">
                {linkLabel}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
