import React from 'react';
import { Lock } from 'lucide-react';

/** Folder of a finding whose file and line are withheld on the Free plan (private repositories), with the upgrade link. */
export function LockedLocation({ folder, className = '' }: { folder: string; className?: string }) {
  return (
    <span className={`inline-flex flex-wrap items-center gap-1.5 font-mono ${className}`}>
      <span className="text-zinc-300">{folder}</span>
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300 text-[10px] font-bold uppercase tracking-wide">
        <Lock className="w-3 h-3" aria-hidden="true" />
        File and line on Pro
      </span>
      <a href="/#pricing" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-2 text-[11px]">
        Upgrade
      </a>
    </span>
  );
}
