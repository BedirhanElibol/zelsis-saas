import React from 'react';
import { FlaskConical } from 'lucide-react';

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
