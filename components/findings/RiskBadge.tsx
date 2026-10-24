import React from 'react';
import { Banknote, Database, KeyRound, ServerCrash, Terminal } from 'lucide-react';
import { RISK_LABEL, type RiskKind } from '@/lib/scanner/risk-kind';

const STYLE: Record<RiskKind, { icon: typeof Banknote; className: string }> = {
  FINANCIAL: { icon: Banknote, className: 'bg-amber-500/15 text-amber-300 border-amber-500/30' },
  DATA_LEAK: { icon: Database, className: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
  ACCOUNT_TAKEOVER: { icon: KeyRound, className: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30' },
  CODE_EXECUTION: { icon: Terminal, className: 'bg-red-500/15 text-red-300 border-red-500/30' },
  DOWNTIME: { icon: ServerCrash, className: 'bg-sky-500/15 text-sky-300 border-sky-500/30' },
};

/** Small label saying what kind of damage a finding leads to (money, data, accounts, server, uptime). */
export function RiskBadge({ risk, className = '' }: { risk?: RiskKind; className?: string }) {
  if (!risk) return null;
  const { icon: Icon, className: tone } = STYLE[risk];
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wide ${tone} ${className}`}>
      <Icon className="w-3 h-3" aria-hidden="true" />
      {RISK_LABEL[risk]}
    </span>
  );
}
