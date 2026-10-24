import React from 'react';
import version from '@/data/rules-version.generated.json';

export const metadata = { title: 'Rules Version - Zelsis Docs' };

export default function RulesVersionPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Rules Version</h1>
      <p className="text-zinc-400">Which version of the detection rules your scans run on, and what happens when the rules change.</p>

      <section className="space-y-3 mt-8">
        <div className="bg-zinc-900 border border-white/10 p-4 rounded-lg font-mono text-sm">
          <p className="text-zinc-400">Rules last changed: <strong className="text-white">{version.updatedAt}</strong></p>
          <p className="text-zinc-400 mt-1">Version: <strong className="text-white">{version.hash}</strong></p>
        </div>
        <p>
          The version is a fingerprint of the detection code. It changes only when a rule is added, removed or changed, and the date
          above moves with it.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">When the rules change</h2>
        <ul className="list-disc pl-6 space-y-2">
          <li>Scans run before that date may show findings the current rules would word differently, drop or add. The dashboard notes when your results come from an earlier scan, so you know to run it again.</li>
          <li>Pull request checks always run on the current rules.</li>
          <li>Rule changes are described in the <a href="/changelog" className="underline hover:text-white">changelog</a>.</li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">Framework releases</h2>
        <p>
          Frameworks change their defaults over time. When a new release of a framework makes a rule wrong, for example a setting that
          became safe by default, we narrow or remove the rule rather than keep a false alarm. If a finding looks wrong for the version
          you run, mark it as a false positive on the finding so it stops counting against your score.
        </p>
      </section>
    </div>
  );
}
