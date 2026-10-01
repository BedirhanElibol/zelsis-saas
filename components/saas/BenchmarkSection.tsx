'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { CheckCircle2, CircleAlert, CircleX, ExternalLink } from 'lucide-react';
import benchmark from '@/data/benchmark-summary.generated.json';
import { formatCount, RULE_COUNTS } from '@/lib/rule-status';

/**
 * Landing benchmark: every number here comes from scripts/benchmark/run.ts
 * (pinned open-source repositories), never from hand-written values.
 */
type Tab = 'flaws' | 'clean' | 'method';

const REPO_URL = (repo: string, sha: string) => `https://github.com/${repo}/tree/${sha}`;

const { summary } = benchmark;
const cleanRepos = benchmark.repos.filter((r) => r.kind === 'clean');
const cleanPassedOrWarned = cleanRepos.filter((r) => r.gate !== 'FAILED').length;

const GateBadge: React.FC<{ gate: string }> = ({ gate }) => {
  const style = gate === 'PASSED'
    ? { dot: 'bg-emerald-500', label: 'Passed' }
    : gate === 'WARNING'
      ? { dot: 'bg-amber-400', label: 'Warning' }
      : { dot: 'bg-red-400', label: 'Failed' };
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono text-zinc-300 bg-white/[0.04] border border-white/10">
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} /> {style.label}
    </span>
  );
};

const Stat: React.FC<{ value: string; label: string; detail: string }> = ({ value, label, detail }) => (
  <div className="p-5 rounded-2xl border border-white/10 bg-[#121214] flex flex-col gap-1">
    <span className="text-[11px] font-mono uppercase text-zinc-400 font-semibold tracking-wider">{label}</span>
    <span className="text-2xl font-extrabold text-white tabular-nums">{value}</span>
    <span className="text-xs text-zinc-400 leading-relaxed">{detail}</span>
  </div>
);

export const BenchmarkSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('flaws');
  const tabs: { id: Tab; label: string }[] = [
    { id: 'flaws', label: `Documented flaws (${summary.documentedFlawsDetected}/${summary.documentedFlaws})` },
    { id: 'clean', label: `Clean projects (${cleanRepos.length})` },
    { id: 'method', label: 'Method & limits' }
  ];

  return (
    <section id="benchmark" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10 font-sans relative">
      <div className="max-w-6xl mx-auto flex flex-col gap-12">
        <div className="flex flex-col gap-3 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 justify-center text-xs font-mono uppercase tracking-wider text-zinc-300 bg-white/[0.04] border border-white/10 px-3 py-1 rounded-full self-center">
            <span>Measured benchmark · {benchmark.generatedAt}</span>
          </div>
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-white tracking-tight">
            Measured on real code, published as-is.
          </h2>
          <p className="text-sm sm:text-base text-zinc-400 leading-relaxed font-sans">
            We scan pinned open-source projects: intentionally vulnerable apps to measure what we catch, and maintained
            production apps to measure noise. These are the latest results, including what we miss.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Stat
            label="Documented flaws found"
            value={`${summary.documentedFlawsDetected} / ${summary.documentedFlaws}`}
            detail={`${summary.documentedFlawsBlockingGate} of them block the release gate (HIGH or CRITICAL).`}
          />
          <Stat
            label="Clean projects not failed"
            value={`${cleanPassedOrWarned} / ${cleanRepos.length}`}
            detail={`${cleanRepos.length - cleanPassedOrWarned} failed on issues we reviewed as real.`}
          />
          <Stat
            label="Active rules"
            value={formatCount(RULE_COUNTS.gating)}
            detail={`${formatCount(RULE_COUNTS.experimental)} more are experimental: reported, but never decide the gate.`}
          />
          <Stat
            label="Rules that can fail a release"
            value={formatCount(RULE_COUNTS.canBlockRelease)}
            detail={`Backed by test fixtures (${formatCount(RULE_COUNTS.fixtureTested)} rules), a caught benchmark flaw or a reviewed finding. Other rules can warn, not fail.`}
          />
        </div>

        <div className="flex flex-wrap items-center justify-center gap-2 p-1 rounded-xl bg-[#141414] border border-white/10 max-w-2xl mx-auto w-full">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 min-w-[140px] py-2 px-3 rounded-lg text-[11px] font-mono font-bold transition-all cursor-pointer ${
                activeTab === tab.id ? 'bg-white text-black shadow-sm' : 'text-zinc-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'flaws' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="rounded-2xl border border-white/10 bg-[#121214] overflow-hidden shadow-2xl">
            <div className="p-4 sm:p-6 border-b border-white/10 bg-[#0E0E10]">
              <h3 className="text-base font-bold text-white">Known vulnerabilities in intentionally vulnerable apps</h3>
              <p className="text-xs text-zinc-400 mt-1">Each flaw is located in the app&apos;s source; it counts as found only if Zelsis reports that class of issue in that file.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141418] border-b border-white/10 text-zinc-400">
                  <tr>
                    <th className="py-3 px-4">Project</th>
                    <th className="py-3 px-4">Flaw</th>
                    <th className="py-3 px-4">File</th>
                    <th className="py-3 px-4 text-center">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-zinc-300">
                  {benchmark.flaws.map((f) => (
                    <tr key={`${f.repo}-${f.flaw}`} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-4 text-zinc-400 whitespace-nowrap">{f.repo}</td>
                      <td className="py-3 px-4 text-white font-medium">{f.flaw}</td>
                      <td className="py-3 px-4 text-zinc-400">{f.file}</td>
                      <td className="py-3 px-4 text-center whitespace-nowrap">
                        {!f.found ? (
                          <span className="inline-flex items-center gap-1.5 text-red-300"><CircleX size={12} /> Missed</span>
                        ) : f.blocksGate ? (
                          <span className="inline-flex items-center gap-1.5 text-zinc-200"><CheckCircle2 size={12} className="text-emerald-500" /> Found · blocks</span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-zinc-200"><CircleAlert size={12} className="text-amber-400" /> Found · warning</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {activeTab === 'clean' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="rounded-2xl border border-white/10 bg-[#121214] overflow-hidden shadow-2xl">
            <div className="p-4 sm:p-6 border-b border-white/10 bg-[#0E0E10]">
              <h3 className="text-base font-bold text-white">Maintained production projects</h3>
              <p className="text-xs text-zinc-400 mt-1">
                HIGH and CRITICAL findings here are reviewed by hand. Rules that fired on clean code without a real issue were moved to experimental.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141418] border-b border-white/10 text-zinc-400">
                  <tr>
                    <th className="py-3 px-4">Project</th>
                    <th className="py-3 px-4">Stack</th>
                    <th className="py-3 px-4 text-right">Files</th>
                    <th className="py-3 px-4 text-right">Critical / High</th>
                    <th className="py-3 px-4 text-right">Engine time</th>
                    <th className="py-3 px-4 text-center">Gate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-zinc-300">
                  {cleanRepos.map((r) => (
                    <tr key={r.repo} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <a href={REPO_URL(r.repo, r.sha)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-white hover:underline">
                          {r.repo} <ExternalLink size={10} className="text-zinc-500" />
                        </a>
                      </td>
                      <td className="py-3 px-4 text-zinc-400">{r.stack}</td>
                      <td className="py-3 px-4 text-right tabular-nums">{formatCount(r.files)}</td>
                      <td className="py-3 px-4 text-right tabular-nums">{r.critical} / {r.high}</td>
                      <td className="py-3 px-4 text-right tabular-nums">{(r.scanMs / 1000).toFixed(1)}s</td>
                      <td className="py-3 px-4 text-center"><GateBadge gate={r.gate} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {activeTab === 'method' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-6 rounded-2xl border border-white/10 bg-[#121214] flex flex-col gap-3">
              <h4 className="text-sm font-bold text-white">How it is measured</h4>
              <ul className="text-xs text-zinc-400 leading-relaxed list-disc pl-4 flex flex-col gap-1.5">
                <li>{benchmark.repos.length} open-source repositories, each pinned to a commit so results are reproducible.</li>
                <li>Recall: flaws documented by the vulnerable apps themselves, located in their source before scanning.</li>
                <li>Noise: every HIGH/CRITICAL finding on clean projects is reviewed; rules that misfire become experimental.</li>
                <li>Evidence: a CRITICAL finding fails the gate only if its rule has a test fixture, caught a documented flaw, or was reviewed as a true positive. Otherwise it warns.</li>
                <li>Engine time is the scan itself on one machine; downloading the repository is not included.</li>
              </ul>
            </div>
            <div className="p-6 rounded-2xl border border-white/10 bg-[#121214] flex flex-col gap-3">
              <h4 className="text-sm font-bold text-white">Current limits</h4>
              <ul className="text-xs text-zinc-400 leading-relaxed list-disc pl-4 flex flex-col gap-1.5">
                <li>Rules are pattern-based static analysis, not full data-flow analysis: unusual code shapes can be missed.</li>
                <li>The corpus covers JavaScript/TypeScript, Python, Go, PHP, Java, Ruby and C# projects; other languages are not yet benchmarked.</li>
                <li>Dependency vulnerabilities are checked for selected advisories, not a full CVE database yet.</li>
                <li>A small benchmark cannot prove the absence of false positives on every codebase. Report one and we add it.</li>
              </ul>
            </div>
          </motion.div>
        )}
      </div>
    </section>
  );
};
