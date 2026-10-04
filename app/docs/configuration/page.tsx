import React from 'react';
import { PREFIX_OFFSETS } from '@/lib/scanner/ignore-parser';

export const metadata = { title: 'Configuration - Zelsis Docs' };

export default function ConfigurationPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Configuration</h1>
      <p className="text-zinc-400">Configure Zelsis using <code>.zelsisrc.json</code> and ignore specific files or rules with <code>.zelsisignore</code>.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">The .zelsisrc.json File</h2>
        <p>
          Place a <code>.zelsisrc.json</code> file in the root of your repository to configure global scan behavior.
        </p>
        <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm font-mono border border-white/10">
          <code className="text-emerald-400">
{`{
  "projectName": "My SaaS App",
  "minScoreThreshold": 80,
  "failStrategy": "smart",
  "gates": {
    "security": true,
    "legalCompliance": true,
    "infraDatabase": true,
    "designVibePolish": false,
    "vibeCareHealth": true
  },
  "ignoreRules": ["SEC-123", "UI-A11Y-01"],
  "ignoredPaths": ["tests/", "scripts/**/*.js"]
}`}
          </code>
        </pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">The .zelsisignore File</h2>
        <p>
          Similar to <code>.gitignore</code>, you can use <code>.zelsisignore</code> to suppress specific rules or ignore entire files/directories. 
          Each line can be a file path or a rule code/ID.
        </p>
        <h3 className="text-lg font-medium text-white mt-4">Supported Rule Prefixes</h3>
        <p>You can ignore entire categories of rules by using the defined prefixes. The following prefixes are supported:</p>
        <div className="bg-zinc-900 border border-white/10 rounded-lg overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-black/50 border-b border-white/10">
              <tr>
                <th className="px-4 py-2 font-mono text-zinc-300">Prefix Pattern</th>
                <th className="px-4 py-2 font-mono text-zinc-300">Offset(s)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {PREFIX_OFFSETS.map((offsetTuple, idx) => (
                <tr key={idx} className="hover:bg-white/5">
                  <td className="px-4 py-2 font-mono text-emerald-400">{String(offsetTuple[0])}</td>
                  <td className="px-4 py-2 font-mono text-zinc-400">{offsetTuple[1].join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
