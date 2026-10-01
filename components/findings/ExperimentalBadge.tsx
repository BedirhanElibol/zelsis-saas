import React from 'react';
import { CircleHelp, FlaskConical } from 'lucide-react';

/** Marks findings from rules not yet proven precise on the benchmark: reported, but they do not decide the gate. */
export const ExperimentalBadge: React.FC<{ className?: string }> = ({ className = '' }) => (
  <span
    title="Experimental rule: not yet proven precise on our benchmark. Shown for review; it does not affect the release gate or score."
    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-amber-400/30 bg-amber-400/10 text-amber-200 text-[10px] font-mono font-semibold align-middle ${className}`}
  >
    <FlaskConical size={10} aria-hidden="true" />
    Experimental
  </span>
);

/** Marks CRITICAL findings from rules without evidence yet: they warn, but cannot fail the release gate alone. */
export const UnprovenBadge: React.FC<{ className?: string }> = ({ className = '' }) => (
  <span
    title="No test fixture or benchmark evidence for this rule yet. The finding is reported as CRITICAL, but counts as HIGH for the gate: it warns instead of failing the release."
    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-white/15 bg-white/[0.04] text-zinc-300 text-[10px] font-mono font-semibold align-middle ${className}`}
  >
    <CircleHelp size={10} aria-hidden="true" />
    Warns only
  </span>
);
