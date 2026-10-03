/**
 * evaluateGlbaComplianceRules: every rule this engine shipped (GLBA-01..05, ids 14901-14905) was removed as unsound (sentinel identifiers,
 * path-name or file-level "absence of X" checks, or compliance process requirements that are invisible
 * in code). The ids must not be reused. The engine stays registered so new, fixture-proven rules can land here.
 */
import type { Finding } from "@/data/schema";
export interface GlbaComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGlbaComplianceRules(): GlbaComplianceRuleResult {
    return { findings: [], logs: [] };
}
