import React from 'react';
import { ScanResult } from '@/lib/scanner-engine';

interface ScanRunnerProgressPanelProps {
  progress: number;
  isFinished: boolean;
  scanResult: ScanResult | null;
}

export const ScanRunnerProgressPanel: React.FC<ScanRunnerProgressPanelProps> = ({
  progress,
  isFinished,
  scanResult,
}) => {
  const stages = [
    { label: 'Connecting & fetching repository',   range: [0,  24] },
    { label: 'Resolving dependency tree',          range: [25, 49] },
    { label: 'Running AST security rules',         range: [50, 89] },
    { label: 'Generating remediation report',      range: [90, 100] },
  ];
  const activeStageIdx = isFinished
    ? (scanResult ? 4 : stages.findIndex(({ range }) => progress >= range[0] && progress <= range[1]))
    : stages.findIndex(({ range }) => progress >= range[0] && progress <= range[1]);
  const isFailedOrAborted = isFinished && !scanResult;

  return (
    <div className="flex flex-col gap-1 bg-[#0A0A0A] rounded-xl border border-white/10 overflow-hidden">
      {stages.map((stage, idx) => {
        let statusIcon: React.ReactNode;
        let statusLabel: string;
        let statusColor: string;
        let textColor: string;

        if (isFailedOrAborted) {
          if (idx < activeStageIdx) {
            statusIcon = <span className="text-emerald-400 font-bold shrink-0">✓</span>;
            statusLabel = 'Done';
            statusColor = 'text-emerald-400';
            textColor = 'text-zinc-400';
          } else if (idx === activeStageIdx || (activeStageIdx === -1 && idx === 0)) {
            statusIcon = <span className="text-red-400 font-bold shrink-0 font-mono">✕</span>;
            statusLabel = 'Aborted';
            statusColor = 'text-red-400 font-bold';
            textColor = 'text-red-300 font-medium';
          } else {
            statusIcon = <span className="text-zinc-600 font-bold shrink-0 font-mono">—</span>;
            statusLabel = 'Skipped';
            statusColor = 'text-zinc-600';
            textColor = 'text-zinc-600';
          }
        } else if (isFinished && scanResult) {
          statusIcon = <span className="text-emerald-400 font-bold shrink-0">✓</span>;
          statusLabel = 'Done';
          statusColor = 'text-emerald-400';
          textColor = 'text-zinc-400';
        } else {
          const isDone = idx < activeStageIdx;
          const isActive = idx === activeStageIdx;
          if (isDone) {
            statusIcon = <span className="text-emerald-400 font-bold shrink-0">✓</span>;
            statusLabel = 'Done';
            statusColor = 'text-emerald-400';
            textColor = 'text-zinc-400';
          } else if (isActive) {
            statusIcon = <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse shrink-0 inline-block" />;
            statusLabel = `${progress}%`;
            statusColor = 'text-blue-400';
            textColor = 'text-white font-bold';
          } else {
            statusIcon = <span className="w-2 h-2 rounded-full bg-white/20 shrink-0 inline-block" />;
            statusLabel = 'Wait';
            statusColor = 'text-zinc-700';
            textColor = 'text-zinc-600';
          }
        }

        return (
          <div
            key={stage.label}
            className={`flex items-center justify-between px-4 py-2.5 text-xs font-mono border-b border-white/5 last:border-b-0 transition-colors ${
              !isFinished && idx === activeStageIdx ? 'bg-white/[0.04]' : ''
            }`}
          >
            <div className="flex items-center gap-3 min-w-0">
              {statusIcon}
              <span className={`truncate ${textColor}`}>
                Stage {idx + 1}: {stage.label}
              </span>
            </div>
            <span className={`text-[10px] shrink-0 ml-4 ${statusColor}`}>
              {statusLabel}
            </span>
          </div>
        );
      })}
      {/* Thin progress line at bottom */}
      <div className="w-full h-[2px] bg-white/5">
        <div
          className={`h-full transition-all duration-150 ${isFailedOrAborted ? 'bg-red-500/60' : 'bg-blue-500/60'}`}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
};
