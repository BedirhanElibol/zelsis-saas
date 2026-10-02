/**
 * evaluateEuAiActRules: every rule this engine shipped (AIACT-01..05, ids 11601-11605) was removed as unsound (sentinel identifiers,
 * path-name or file-level "absence of X" checks, or compliance process requirements that are invisible
 * in code). The ids must not be reused. The engine stays registered so new, fixture-proven rules can land here.
 */
import type { Finding } from "@/data/schema";
export interface EuAiActRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEuAiActRules(): EuAiActRuleResult {
    return { findings: [], logs: [] };
}
