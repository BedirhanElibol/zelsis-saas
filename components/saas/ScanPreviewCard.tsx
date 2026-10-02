'use client';

import React from 'react';
import { ArrowRight, Lock, ShieldAlert, ShieldCheck } from 'lucide-react';

export interface ScanPreviewResult {
  repoUrl: string;
  repoName: string;
  filesScanned: number;
  score: number;
  gateStatus: 'PASSED' | 'WARNING' | 'FAILED';
  counts: { critical: number; high: number; medium: number; low: number };
  totalFindings: number;
  topFindings: { title: string; severity: string; category: string }[];
  remaining: number;
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/30 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  MEDIUM: 'text-amber-300 border-amber-500/30 bg-amber-500/10',
  LOW: 'text-zinc-300 border-white/10 bg-white/[0.04]',
};

const GATE_STYLES: Record<ScanPreviewResult['gateStatus'], string> = {
  PASSED: 'text-emerald-400',
  WARNING: 'text-amber-300',
  FAILED: 'text-red-400',
};

interface ScanPreviewCardProps {
  result: ScanPreviewResult;
  onUnlock: () => void;
}

export const ScanPreviewCard: React.FC<ScanPreviewCardProps> = ({ result, onUnlock }) => {
  const hiddenCount = Math.max(0, result.totalFindings - result.topFindings.length);
  const hasFindings = result.totalFindings > 0;

  return (
    <div className="w-full max-w-2xl mb-10 rounded-xl border border-white/10 bg-[#141414] text-left shadow-2xl overflow-hidden" role="region" aria-label="Scan preview">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-white/10">
        <div className="flex items-center gap-2 min-w-0">
          {hasFindings ? (
            <ShieldAlert size={16} className="text-red-400 shrink-0" />
          ) : (
            <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
          )}
          <span className="text-xs font-mono text-[#EDEDED] truncate">{result.repoName}</span>
          <span className="text-[11px] font-mono text-zinc-400 shrink-0">{result.filesScanned} files</span>
        </div>
        <span className={`text-xs font-mono font-bold ${GATE_STYLES[result.gateStatus]}`}>
          {result.gateStatus} · {result.score}/100
        </span>
      </div>

      <div className="grid grid-cols-4 divide-x divide-white/10 border-b border-white/10 text-center">
        {(
          [
            ['Critical', result.counts.critical, 'text-red-400'],
            ['High', result.counts.high, 'text-orange-400'],
            ['Medium', result.counts.medium, 'text-amber-300'],
            ['Low', result.counts.low, 'text-zinc-300'],
          ] as const
        ).map(([label, count, color]) => (
          <div key={label} className="py-3">
            <div className={`text-lg font-extrabold font-mono ${color}`}>{count}</div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">{label}</div>
          </div>
        ))}
      </div>

      {hasFindings ? (
        <ul className="px-4 py-3 space-y-2">
          {result.topFindings.map((f, i) => (
            <li key={`${f.title}-${i}`} className="flex items-start gap-2">
              <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border shrink-0 ${SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.LOW}`}>
                {f.severity}
              </span>
              <span className="text-xs text-[#EDEDED] leading-relaxed">{f.title}</span>
            </li>
          ))}
          {hiddenCount > 0 && (
            <li className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
              <Lock size={12} className="shrink-0" />
              <span>+{hiddenCount} more findings, with exact file locations</span>
            </li>
          )}
        </ul>
      ) : (
        <p className="px-4 py-3 text-xs text-zinc-300">
          No issues found in this preview. Sign up to run continuous checks on every deploy.
        </p>
      )}

      <div className="px-4 py-3 border-t border-white/10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <span className="text-[11px] font-mono text-zinc-400">
          Free account: full report with exact file locations. Fix prompts with Pro.
        </span>
        <button
          type="button"
          onClick={onUnlock}
          className="px-4 py-2 rounded-lg text-xs font-bold font-mono bg-emerald-500 text-black hover:bg-emerald-400 transition-all flex items-center justify-center gap-2 shrink-0 cursor-pointer"
        >
          <span>{hasFindings ? 'See full report' : 'Create free account'}</span>
          <ArrowRight size={13} />
        </button>
      </div>
    </div>
  );
};
