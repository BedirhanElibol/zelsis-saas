'use client';

import React from 'react';
import { Project, ScanHistoryItem } from '@/data/schema';
import { UserTier } from '@/data/schema';
import { History, Play, CheckCircle2, AlertTriangle, ShieldCheck, Clock, Lock } from 'lucide-react';
import { filterHistoryByRetention, TIER_CONFIGS } from '@/lib/quota-manager';

interface ScanHistoryViewProps {
  project: Project;
  onTriggerScan: () => void;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  project,
  onTriggerScan,
  userTier = 'Free',
  onOpenCheckout
}) => {
  // Read authentic historical audit records from project state
  const allRecords: ScanHistoryItem[] = ((project as any).scanHistory && (project as any).scanHistory.length > 0)
    ? (project as any).scanHistory
    : [];

  const { visible: historyRecords, locked: lockedRecords } = filterHistoryByRetention(allRecords, userTier);
  const retentionDays = TIER_CONFIGS[userTier].historyRetentionDays;

  return (
    <div className="flex flex-col gap-6">
      {/* Header Card */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 bg-[#141414] border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
              <History size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-extrabold text-[#EDEDED]">
                Release Gate Audit History &amp; Timeline
              </h1>
              <p className="text-xs text-[#A1A1AA] mt-0.5">
                Historical scan logs, score deltas, and pre-flight clearance records for {project.name}
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={() => onTriggerScan()}
          className="btn btn-primary text-xs px-5 py-2.5 font-bold uppercase tracking-wider flex items-center gap-2 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm"
        >
          <Play size={14} fill="#0A0A0A" />
          <span>Run New Live Scan</span>
        </button>
      </div>

      {/* History Table */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 bg-[#141414] border-white/10 flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="text-xs font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">
            PAST AUDIT EXECUTIONS ({historyRecords.length}
            {lockedRecords.length > 0 && (
              <span className="text-amber-400 ml-1">+ {lockedRecords.length} locked</span>
            )}
            )
          </div>
          <span className="text-xs font-mono text-white">Target: {project.repoUrl}</span>
        </div>

        {/* Retention paywall banner */}
        {lockedRecords.length > 0 && (
          <div className="flex items-center justify-between gap-4 p-3.5 rounded-xl bg-amber-500/5 border border-amber-500/20">
            <div className="flex items-center gap-2.5">
              <Lock size={15} className="text-amber-400 shrink-0" />
              <p className="text-xs text-amber-300 leading-relaxed">
                <span className="font-bold">{lockedRecords.length} older records</span> are hidden.{' '}
                {typeof retentionDays === 'number'
                  ? `Free tier shows the last ${retentionDays} days.`
                  : `Pro tier shows 90 days.`}{' '}
                Upgrade to unlock full audit history.
              </p>
            </div>
            {onOpenCheckout && (
              <button
                onClick={() => onOpenCheckout('Pro')}
                className="shrink-0 text-[10px] font-bold uppercase tracking-wider text-black bg-white hover:bg-neutral-200 transition-colors rounded-lg px-3 py-1.5"
              >
                Upgrade
              </button>
            )}
          </div>
        )}

        <div className="space-y-3">
          {historyRecords.length === 0 && lockedRecords.length === 0 ? (
            <div className="p-8 text-center bg-[#0A0A0A] rounded-xl border border-white/10 text-xs text-[#A1A1AA] flex flex-col items-center justify-center gap-3">
              <History size={28} className="text-white/20" />
              <div>
                <p className="font-bold text-white mb-1">No Historical Scan Logs Recorded</p>
                <p className="text-[#A1A1AA]">Running an audit scan will populate real historical logs, readiness scores, and differential gates.</p>
              </div>
              <button
                onClick={() => onTriggerScan()}
                className="btn btn-primary text-xs px-4 py-2 mt-1 font-bold uppercase tracking-wider flex items-center gap-2 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 transition-all cursor-pointer"
              >
                <Play size={12} fill="#0A0A0A" />
                <span>Run First Live Scan</span>
              </button>
            </div>
          ) : (
            historyRecords.map((scan) => (
              <div
                key={scan.id}
                className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:border-white/10 transition-all"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center font-mono text-xs text-white font-bold">
                    {scan.id.split('-')[1]}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-[#EDEDED]">{scan.id}</span>
                      <span className="text-[0.68rem] text-[#A1A1AA] font-mono">{scan.date}</span>
                    </div>
                    <div className="text-[0.68rem] text-white font-mono mt-0.5 flex items-center gap-1.5">
                      <Clock size={12} />
                      <span>Duration: {scan.duration} / Trigger: {scan.triggeredBy}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {/* Findings summary */}
                  <div className="text-right font-mono text-xs">
                    <div className="text-[#EDEDED] font-bold">
                      Score: <span className="text-white">{scan.score}/100</span>
                    </div>
                    <div className="text-[0.68rem] text-[#A1A1AA]">
                      {scan.criticalCount} Critical / {scan.highCount} High
                    </div>
                  </div>

                  {/* Gate badge */}
                  <span
                    className={`text-[0.65rem] font-extrabold uppercase px-2.5 py-1 rounded-md border ${
                      scan.gateStatus === 'PASSED'
                        ? 'bg-white/5 border-white/10 text-white'
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}
                  >
                    {scan.gateStatus}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

