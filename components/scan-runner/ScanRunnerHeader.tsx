import React from 'react';
import { Clock, Database } from 'lucide-react';
import { extractRepoDisplayName } from '@/lib/github-api';
import { Project } from '@/data/schema';
import { ScanResult } from '@/lib/scanner-engine';
import { canAccessLocalAudit } from '@/lib/env-config';
import { safeLower } from '@/lib/safe-utils';

interface ScanRunnerHeaderProps {
  project: Project;
  isFinished: boolean;
  progress: number;
  handleAbortScan: () => void;
  scanResult: ScanResult | null;
  queuedFilesCount: number;
  currentFileName: string;
  elapsedSeconds: number;
}

export const ScanRunnerHeader: React.FC<ScanRunnerHeaderProps> = ({
  project,
  isFinished,
  progress,
  handleAbortScan,
  scanResult,
  queuedFilesCount,
  currentFileName,
  elapsedSeconds,
}) => {
  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-lg sm:text-xl font-extrabold text-[#EDEDED] truncate">
            Sequential AST Audit: {project.name || extractRepoDisplayName(project.repoUrl) || 'Target Repository'}
          </h1>
          <div className="text-xs text-[#A1A1AA] mt-1">
            <span className="truncate">Automated security clearance &amp; UX quality gates</span>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
          {!isFinished && (
            <button
              onClick={handleAbortScan}
              className="btn btn-secondary text-xs px-3 py-1.5 text-red-400 border-red-500/30 hover:bg-red-500/10 font-bold font-mono"
            >
              Abort Audit
            </button>
          )}
          <div className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] font-mono">
            {progress}%
          </div>
        </div>
      </div>

      {/* Current Active File Card */}
      <div className="bg-[#0A0A0A] p-3 sm:p-4 rounded-xl border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0 flex-1 w-full">
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-xs text-white shrink-0">
            AST
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[0.68rem] text-[#A1A1AA] font-bold uppercase tracking-wider font-mono">
              {isFinished ? 'Audit Execution Status:' : 'Currently Inspecting File:'}
            </div>
            <div className="text-xs font-mono font-bold mt-0.5 truncate text-white">
              {isFinished
                ? scanResult
                  ? `All ${queuedFilesCount} Source Files Inspected & Verified`
                  : (project?.repoUrl === 'local' || safeLower(project?.repoUrl) === 'local') && !canAccessLocalAudit()
                  ? 'Local workspace self-audit is available only in local development.'
                  : 'Audit Terminated'
                : currentFileName}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono text-[#A1A1AA] shrink-0 w-full sm:w-auto justify-between sm:justify-end">
          <div className="flex items-center gap-1.5 bg-white/5 px-2.5 py-1 rounded border border-white/10 shrink-0">
            <Clock size={12} className="text-white" />
            <span>Elapsed: {Math.floor(elapsedSeconds / 60)}m {elapsedSeconds % 60}s</span>
          </div>
          {queuedFilesCount > 0 && (
            <span className="text-white font-bold hidden md:inline">
              {queuedFilesCount.toLocaleString()} Files
            </span>
          )}
        </div>
      </div>

      {/* Target Architecture & Multi-Database Stack Banner */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 px-3.5 py-2.5 bg-[#0D0D14] border border-white/10 rounded-xl">
        <div className="flex items-center gap-2">
          <Database size={14} className="text-cyan-400 shrink-0" />
          <span className="text-[11px] font-mono font-bold text-zinc-300 uppercase tracking-wider">
            Target Architecture:
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {scanResult?.detectedDatabases && scanResult.detectedDatabases.length > 0 ? (
            scanResult.detectedDatabases.map((db) => (
              <span
                key={db}
                className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30"
              >
                {db}
              </span>
            ))
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-white/5 text-zinc-400 border border-white/10">
              Universal (Postgres · MySQL · MongoDB · Redis · SQLite)
            </span>
          )}
          {scanResult?.detectedOrms && scanResult.detectedOrms.map((orm) => (
            <span
              key={orm}
              className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-300 border border-blue-500/30"
            >
              {orm}
            </span>
          ))}
        </div>
      </div>
    </>
  );
};
