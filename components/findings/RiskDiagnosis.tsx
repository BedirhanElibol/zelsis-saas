import React from 'react';
import { AlertTriangle, Lock } from 'lucide-react';
import type { Finding } from '@/data/schema';
import { RISK_LABEL, type RiskKind } from '@/lib/scanner/risk-kind';

const ORDER: RiskKind[] = ['DATA_LEAK', 'FINANCIAL', 'ACCOUNT_TAKEOVER', 'CODE_EXECUTION', 'DOWNTIME'];
const NOUN: Record<RiskKind, [string, string]> = {
  DATA_LEAK: ['data leak point', 'data leak points'],
  FINANCIAL: ['financial risk', 'financial risks'],
  ACCOUNT_TAKEOVER: ['account takeover path', 'account takeover paths'],
  CODE_EXECUTION: ['server takeover path', 'server takeover paths'],
  DOWNTIME: ['downtime risk', 'downtime risks'],
};

/**
 * One-line diagnosis above the findings: what this project is open to if it ships as is, counted from open
 * CRITICAL / HIGH findings by risk kind. Plain counts from the scan; nothing is estimated.
 */
export function RiskDiagnosis({ findings }: { findings: Finding[] }) {
  const serious = findings.filter((f) => f.status === 'OPEN' && (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.risk);
  if (serious.length === 0) return null;
  const counts = new Map<RiskKind, number>();
  for (const f of serious) counts.set(f.risk!, (counts.get(f.risk!) ?? 0) + 1);
  const parts = ORDER.filter((k) => counts.has(k)).map((k) => `${counts.get(k)} ${NOUN[k][counts.get(k) === 1 ? 0 : 1]}`);
  const locked = serious.filter((f) => f.lockedLocation).length;

  return (
    <div role="status" className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2.5 rounded-lg border border-red-500/30 bg-red-500/10 text-xs">
      <div className="flex items-start gap-2 text-red-200">
        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
        <span>
          <strong className="text-red-100">If this ships as it is:</strong> {parts.join(', ')}.{' '}
          <span className="text-red-300/80">({ORDER.filter((k) => counts.has(k)).map((k) => RISK_LABEL[k]).join(' · ')})</span>
        </span>
      </div>
      {locked > 0 && (
        <a href="/#pricing" className="inline-flex items-center gap-1.5 shrink-0 px-2.5 py-1 rounded-md bg-emerald-500 text-black font-bold hover:bg-emerald-400">
          <Lock className="w-3.5 h-3.5" aria-hidden="true" />
          See where the other {locked} are
        </a>
      )}
    </div>
  );
}
