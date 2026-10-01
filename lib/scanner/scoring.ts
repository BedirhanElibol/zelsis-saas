import type { Finding } from '@/data/schema';

/** Findings that count toward score and gate: open, and from rules proven precise. */
export const gatingFindings = (findings: Finding[]): Finding[] =>
  findings.filter((f) => f.status === 'OPEN' && f.maturity !== 'experimental');

/**
 * Severity a finding carries in score and gate. A CRITICAL from a rule without evidence
 * (no fixture, benchmark catch or reviewed true positive) counts as HIGH: it warns, but
 * cannot fail the release on its own. Findings without a maturity tag predate this policy.
 */
export const gateSeverity = (f: Finding): Finding['severity'] =>
  f.severity === 'CRITICAL' && f.maturity === 'unproven' ? 'HIGH' : f.severity;

export function calculateReadinessScore(findings: Finding[]): number {
  const openFindings = gatingFindings(findings);
  // Separate core security/infra/legal blockers from cosmetic polish/UI items (F-38)
  const securityFindings = openFindings.filter(
    (f) => f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE'
  );
  const cosmeticFindings = openFindings.filter(
    (f) => f.type === 'VIBEPOLISH' || f.type === 'VIBECARE'
  );

  const criticalSecCount = securityFindings.filter((f) => gateSeverity(f) === 'CRITICAL').length;
  const highSecCount = securityFindings.filter((f) => gateSeverity(f) === 'HIGH').length;
  const mediumSecCount = securityFindings.filter((f) => gateSeverity(f) === 'MEDIUM').length;
  const lowSecCount = securityFindings.filter((f) => gateSeverity(f) === 'LOW').length;

  // Soft cosmetic deductions capped at 10 points total so clean repos never score below 90 on style alone
  const highCosmetic = cosmeticFindings.filter((f) => gateSeverity(f) === 'HIGH').length;
  const medCosmetic = cosmeticFindings.filter((f) => gateSeverity(f) === 'MEDIUM').length;
  const lowCosmetic = cosmeticFindings.filter((f) => gateSeverity(f) === 'LOW').length;
  const cosmeticDeduction = Math.min(10, highCosmetic * 2 + medCosmetic * 1 + lowCosmetic * 0.5);

  // Critical blockers directly deplete production readiness
  if (criticalSecCount > 0) {
    const criticalDeduction =
      criticalSecCount * 25 + Math.min(30, highSecCount * 5) + Math.min(15, mediumSecCount * 2) + cosmeticDeduction;
    return Math.max(0, Math.round(100 - criticalDeduction));
  }

  // Non-blocking repositories (GateStatus = PASSED or WARNING)
  // Bounded weighted deductions prevent score collapse on large multi-file codebases
  const highDeduction = Math.min(40, highSecCount * 7);
  const mediumDeduction = Math.min(25, mediumSecCount * 2);
  const lowDeduction = Math.min(10, lowSecCount * 0.5);

  const totalDeduction = highDeduction + mediumDeduction + lowDeduction + cosmeticDeduction;
  return Math.max(25, Math.min(100, Math.round(100 - totalDeduction)));
}

export function calculateGateStatus(findings: Finding[]): 'PASSED' | 'WARNING' | 'FAILED' {
  const openFindings = gatingFindings(findings);
  // Gate status is strictly a security, infrastructure & legal release gate (F-38).
  // Pure cosmetic, accessibility suggestions, and vibe polish rules do NOT fail or warn-block the gate.
  const securityFindings = openFindings.filter(
    (f) => f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE'
  );
  const criticalCount = securityFindings.filter((f) => gateSeverity(f) === 'CRITICAL').length;
  const highCount = securityFindings.filter((f) => gateSeverity(f) === 'HIGH').length;

  if (criticalCount > 0) return 'FAILED';
  if (highCount > 0) return 'WARNING';
  return 'PASSED';
}
