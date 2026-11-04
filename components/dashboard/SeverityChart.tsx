'use client';

import React from 'react';
import { Project } from '@/data/schema';
import { summarizeFindings } from '@/lib/finding-counts';

interface SeverityChartProps {
  project: Project;
}

export const SeverityChart: React.FC<SeverityChartProps> = ({ project }) => {
  // Verified findings only, the same counts as the header and the API; suggestions are listed beside them
  const summary = summarizeFindings(project?.findings);
  const { critical, high, medium, low, total: verifiedTotal } = summary.verified;
  const suggestions = summary.suggestions.total;
  const total = Math.max(1, verifiedTotal);

  const pctCritical = (critical / total) * 100;
  const pctHigh = (high / total) * 100;
  const pctMedium = (medium / total) * 100;
  const pctLow = (low / total) * 100;
  const readiness = typeof project?.readinessScore === 'number' ? project.readinessScore : 100;

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-extrabold text-[#EDEDED]">
            Severity &amp; Risk Distribution
          </h3>
          <div className="text-xs text-[#94A3B8] mt-0.5">
            Verified findings by severity
          </div>
        </div>

        <div className="text-xs font-mono text-white font-bold">
          READINESS: {readiness}%
        </div>
      </div>

      {/* Visual Stacked Progress Bar */}
      <div className="w-full h-3.5 bg-white/10 rounded-lg overflow-hidden flex">
        {pctCritical > 0 && (
          <div
            style={{ width: `${pctCritical}%` }}
            className="bg-[#EF4444] h-full transition-all duration-500"
            title={`Critical: ${critical}`}
          />
        )}
        {pctHigh > 0 && (
          <div
            style={{ width: `${pctHigh}%` }}
            className="bg-[#F97316] h-full transition-all duration-500"
            title={`High: ${high}`}
          />
        )}
        {pctMedium > 0 && (
          <div
            style={{ width: `${pctMedium}%` }}
            className="bg-[#F59E0B] h-full transition-all duration-500"
            title={`Medium: ${medium}`}
          />
        )}
        {pctLow > 0 && (
          <div
            style={{ width: `${pctLow}%` }}
            className="bg-white/40 h-full transition-all duration-500"
            title={`Low: ${low}`}
          />
        )}
        {verifiedTotal === 0 && <div className="bg-white h-full w-full" title="No verified findings" />}
      </div>

      {/* Legend Row */}
      <div className="flex flex-wrap gap-4 text-xs font-bold text-[#A1A1AA]">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
          <span>Critical ({critical})</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#F97316]" />
          <span>High ({high})</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" />
          <span>Medium ({medium})</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-white/40" />
          <span>Low ({low})</span>
        </div>
        {suggestions > 0 && (
          <div className="flex items-center gap-1.5 text-[#71717A]">
            <span>+ {suggestions} {suggestions === 1 ? 'suggestion' : 'suggestions'}, not counted</span>
          </div>
        )}
      </div>
    </div>
  );
};
