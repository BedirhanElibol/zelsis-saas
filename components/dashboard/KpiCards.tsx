'use client';

import React from 'react';
import { Project } from '@/data/schema';
import NumberFlow from '@number-flow/react';
import { summarizeFindings, verifiedFindings } from '@/lib/finding-counts';

interface KpiCardsProps {
  project: Project;
  onNavigatePillar: (pillar: string) => void;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ project, onNavigatePillar }) => {
  // Same counts as the header, the table, exports and the API (lib/finding-counts): verified findings only
  const summary = summarizeFindings(project?.findings);
  const { openRisks, verifiedUi, suggestionUi } = summary;
  const logicBugs = verifiedFindings(project?.findings).filter((f) => f.type === 'VIBECARE').length;
  const readiness = typeof project?.readinessScore === 'number' ? project.readinessScore : 100;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
      {/* Scorecard 1: Overall Readiness Score */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-3.5 sm:p-5 flex flex-col justify-between relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            OVERALL READINESS
          </span>
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span
            className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-mono ${
              readiness < 50
                ? 'text-[#EF4444]'
                : readiness < 85
                ? 'text-[#F59E0B]'
                : 'text-white'
            }`}
          >
            <NumberFlow value={readiness} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">/ 100</span>
        </div>

        {/* Progress Bar Gauge */}
        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${
              readiness < 50
                ? 'bg-[#EF4444]'
                : readiness < 85
                ? 'bg-[#F59E0B]'
                : 'bg-white'
            }`}
            style={{ width: `${Math.min(100, Math.max(0, readiness))}%` }}
          />
        </div>

        <div className="text-[0.68rem] sm:text-[0.72rem] text-[#A1A1AA] mt-2 sm:mt-3 flex items-center justify-between font-mono">
          <span>Gate:</span>
          <span className={`font-bold truncate ${
            project.gateStatus === 'FAILED'
              ? 'text-[#EF4444]'
              : project.gateStatus === 'WARNING'
              ? 'text-[#F59E0B]'
              : 'text-emerald-400'
          }`}>
            {project.gateStatus}
          </span>
        </div>
      </div>

      {/* Scorecard 2: Security Pre-Flight */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => onNavigatePillar('security')}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onNavigatePillar('security');
          }
        }}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            SECURITY CLEARANCE
          </span>
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${openRisks > 0 ? 'text-[#EF4444]' : 'text-white'}`}>
            <NumberFlow value={openRisks} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">to fix</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${openRisks > 0 ? 'bg-[#EF4444]' : 'bg-white'}`}
            style={{ width: '100%' }}
          />
        </div>

        <div className={`text-[0.68rem] sm:text-[0.72rem] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono ${openRisks > 0 ? 'text-[#EF4444]' : 'text-zinc-400'}`}>
          <span className="truncate">{openRisks > 0 ? `${openRisks} critical or high ${openRisks === 1 ? 'risk' : 'risks'}` : 'No open risks'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 3: UI Quality & Accessibility (open finding count) */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => onNavigatePillar('vibepolish')}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onNavigatePillar('vibepolish');
          }
        }}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            UI QUALITY &amp; A11Y
          </span>
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${verifiedUi > 0 ? 'text-[#F59E0B]' : 'text-white'}`}>
            <NumberFlow value={verifiedUi} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">open</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${verifiedUi > 0 ? 'bg-[#F59E0B]' : 'bg-white'}`}
            style={{ width: '100%' }}
          />
        </div>

        <div className={`text-[0.68rem] sm:text-[0.72rem] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono ${verifiedUi > 0 ? 'text-[#F59E0B]' : 'text-zinc-400'}`}>
          <span className="truncate">{verifiedUi > 0 ? `${verifiedUi} UI ${verifiedUi === 1 ? 'issue' : 'issues'}` : 'No open UI issues'}{suggestionUi > 0 ? ` · ${suggestionUi} suggestions` : ''}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 4: Master Quality Matrix */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => onNavigatePillar('logicbugs')}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onNavigatePillar('logicbugs');
          }
        }}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            LOGIC BUGS
          </span>
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${logicBugs > 0 ? 'text-[#F59E0B]' : 'text-white'}`}>
            <NumberFlow value={logicBugs} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">open</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${logicBugs > 0 ? 'bg-[#F59E0B]' : 'bg-white'}`}
            style={{ width: '100%' }}
          />
        </div>

        <div className={`text-[0.68rem] sm:text-[0.72rem] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono ${logicBugs > 0 ? 'text-[#F59E0B]' : 'text-zinc-400'}`}>
          <span className="truncate">{logicBugs > 0 ? `${logicBugs} broken ${logicBugs === 1 ? 'feature' : 'features'}` : 'No logic bugs found'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>
    </div>
  );
};
