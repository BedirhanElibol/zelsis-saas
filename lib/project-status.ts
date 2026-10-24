import type { Project } from '@/data/schema';
import { calculateGateStatus, calculateReadinessScore, gateSeverity, gatingFindings } from '@/lib/scanner/scoring';

/**
 * Gate, score and counts derived from the findings the user is looking at. Stored project fields can be stale
 * (an older scan, a weekly rescan that added findings), which showed "PASSED 100/100" next to "2 Critical".
 * Projects without loaded findings keep their stored values.
 */
export function withLiveStatus<P extends Project>(p: P): P {
  const findings = Array.isArray(p.findings) ? p.findings : [];
  if (findings.length === 0) return p;
  const open = gatingFindings(findings);
  const count = (sev: string) => open.filter((f) => f.type !== 'VIBEPOLISH' && f.type !== 'VIBECARE' && gateSeverity(f) === sev).length;
  return {
    ...p,
    gateStatus: calculateGateStatus(findings),
    readinessScore: calculateReadinessScore(findings),
    criticalCount: count('CRITICAL'),
    highCount: count('HIGH'),
    mediumCount: count('MEDIUM'),
    lowCount: count('LOW'),
    uiClicheCount: open.filter((f) => f.type === 'VIBEPOLISH').length,
  };
}
