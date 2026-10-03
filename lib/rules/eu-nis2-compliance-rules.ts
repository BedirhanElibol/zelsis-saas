/**
 * evaluateEuNis2ComplianceRules: every rule this engine shipped (NIS2-01..05, ids 15401-15405) was removed as unsound (sentinel identifiers,
 * path-name or file-level "absence of X" checks, or compliance process requirements that are invisible
 * in code). The ids must not be reused. The engine stays registered so new, fixture-proven rules can land here.
 */
import type { Finding } from "@/data/schema";
export interface EuNis2ComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEuNis2ComplianceRules(): EuNis2ComplianceRuleResult {
    return { findings: [], logs: [] };
}
