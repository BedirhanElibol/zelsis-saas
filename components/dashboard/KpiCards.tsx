'use client';

import React from 'react';
import { Project } from '@/data/schema';
import { ShieldCheck, Palette, Layers, Activity, AlertTriangle } from 'lucide-react';
import NumberFlow from '@number-flow/react';

interface KpiCardsProps {
  project: Project;
  onNavigatePillar: (pillar: string) => void;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ project, onNavigatePillar }) => {
  const safeFindings = Array.isArray(project?.findings) ? project.findings : [];
  const openFindings = safeFindings.filter((f) => f && f.status === 'OPEN');
  const criticals = openFindings.filter((f) => f && f.severity === 'CRITICAL').length;
  const highs = openFindings.filter((f) => f && f.severity === 'HIGH').length;

  // Real count of open UI quality / accessibility findings; no invented "rules passed" baseline.
  const openUiIssues = openFindings.filter(
    (f) => f && (f.type === 'VIBEPOLISH' || f.category?.includes('UI') || f.category?.includes('Visual'))
  ).length;

  const openSlop = openFindings.filter(
    (f) => f && (f.category?.includes('Architecture') || f.category?.includes('Slop') || f.category?.includes('Code'))
  ).length;
  const totalSlopBaseline = Math.max(200, openSlop);
  const clearedSlopRules = Math.max(0, totalSlopBaseline - openSlop);
  const slopPercent = Math.round((clearedSlopRules / totalSlopBaseline) * 100);
  const readiness = typeof project?.readinessScore === 'number' ? project.readinessScore : 100;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
      {/* Scorecard 1: Overall Readiness Score */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-3.5 sm:p-5 flex flex-col justify-between relative overflow-hidden group">
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            OVERALL READINESS
          </span>
          <Activity size={14} className="text-white/80 shrink-0" />
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
        onClick={() => onNavigatePillar('security')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            SECURITY CLEARANCE
          </span>
          <ShieldCheck size={14} className="text-white/80 group-hover:scale-105 transition-transform shrink-0" />
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
            <NumberFlow value={Math.max(0, Math.round(((23 - Math.min(23, criticals + highs)) / 23) * 100))} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">%</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-700 rounded-full"
            style={{ width: `${Math.max(0, Math.round(((23 - Math.min(23, criticals + highs)) / 23) * 100))}%` }}
          />
        </div>

        <div className="text-[0.68rem] sm:text-[0.72rem] text-[#EF4444] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono">
          <span className="truncate">{criticals + highs} Open Risks</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 3: UI Quality & Accessibility (open finding count) */}
      <div
        onClick={() => onNavigatePillar('vibepolish')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            UI QUALITY &amp; A11Y
          </span>
          <Palette size={14} className="text-white/80 group-hover:scale-105 transition-transform shrink-0" />
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${openUiIssues > 0 ? 'text-[#F59E0B]' : 'text-white'}`}>
            <NumberFlow value={openUiIssues} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">open</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${openUiIssues > 0 ? 'bg-[#F59E0B]' : 'bg-white'}`}
            style={{ width: '100%' }}
          />
        </div>

        <div className={`text-[0.68rem] sm:text-[0.72rem] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono ${openUiIssues > 0 ? 'text-[#F59E0B]' : 'text-zinc-400'}`}>
          <span className="truncate">{openUiIssues > 0 ? `${openUiIssues} UI ${openUiIssues === 1 ? 'issue' : 'issues'}` : 'No open UI issues'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 4: Master Quality Matrix */}
      <div
        onClick={() => onNavigatePillar('aimaster')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-3.5 sm:p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-2 sm:mb-3">
          <span className="text-[0.62rem] sm:text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase truncate">
            QUALITY MATRIX
          </span>
          <Layers size={14} className="text-white/80 group-hover:scale-105 transition-transform shrink-0" />
        </div>

        <div className="flex items-baseline gap-1.5 sm:gap-2">
          <span className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
            <NumberFlow value={slopPercent} />
          </span>
          <span className="text-[10px] sm:text-xs font-mono text-[#A1A1AA]">%</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-2 sm:mt-3 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-700 rounded-full"
            style={{ width: `${slopPercent}%` }}
          />
        </div>

        <div className={`text-[0.68rem] sm:text-[0.72rem] font-bold mt-2 sm:mt-3 flex items-center justify-between font-mono ${openSlop > 0 ? 'text-[#F59E0B]' : 'text-zinc-400'}`}>
          <span className="truncate">{openSlop > 0 ? `${openSlop} Slop Rules` : 'Cleared'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:inline">
            Inspect &rarr;
          </span>
        </div>
      </div>
    </div>
  );
};
