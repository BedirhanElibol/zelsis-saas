import { runStaticCodeScan } from '@/lib/scanner-engine';
import { calculateGateStatus, gatingFindings, gateSeverity } from '@/lib/scanner/scoring';
import { LOCKED_FIX_TEXT } from '@/lib/fix-gate';
import { RISK_LABEL } from '@/lib/scanner/risk-kind';

export interface ScanFilesOptions {
  projectName?: string;
  /** Paths the caller changed. When set, only findings in these files decide the gate. */
  changed?: string[];
  canSeeFixes: boolean;
  orgPolicy?: string | null;
  dismissals?: { ruleId: number; filePath: string }[];
}

/**
 * Scans files sent from a developer machine (zelsis CLI, MCP server) and shapes the result for it.
 * Contents are only held in memory for the scan, like repository scans.
 */
export async function scanUploadedFiles(files: { path: string; content: string }[], opts: ScanFilesOptions) {
  const result = await runStaticCodeScan(
    files.map((f) => ({ path: f.path.replace(/\\/g, '/'), content: f.content })),
    opts.projectName || 'local',
    { dependencyAudit: false, orgPolicy: opts.orgPolicy ?? null, dismissals: opts.dismissals },
  );

  const changed = opts.changed ? new Set(opts.changed.map((p) => p.replace(/\\/g, '/'))) : null;
  const inScope = changed ? result.findings.filter((f) => changed.has(f.filePath)) : result.findings;
  const gateStatus = changed ? calculateGateStatus(gatingFindings(inScope)) : result.gateStatus;

  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as Record<string, number>;
  const findings = inScope
    .filter((f) => f.status === 'OPEN')
    .sort((a, b) => (rank[gateSeverity(a)] ?? 9) - (rank[gateSeverity(b)] ?? 9))
    .map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      ...(f.cweId ? { cweId: f.cweId } : {}),
      severity: gateSeverity(f),
      category: f.category,
      filePath: f.filePath,
      lineRange: f.lineRange,
      impact: f.impact,
      risk: f.risk ? RISK_LABEL[f.risk] : undefined,
      experimental: f.maturity === 'experimental' || undefined,
      fix: opts.canSeeFixes ? f.remediationPrompt : LOCKED_FIX_TEXT,
    }));

  return {
    gateStatus,
    readinessScore: result.score,
    filesScanned: files.length,
    scope: changed ? 'changed' : 'all',
    findings,
    crossFileVerified: result.crossFileVerified ?? [],
    otherFindings: changed ? result.findings.filter((f) => f.status === 'OPEN' && !changed.has(f.filePath)).length : 0,
  };
}
