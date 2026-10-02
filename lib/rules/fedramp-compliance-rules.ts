/**
 * evaluateFedrampComplianceRules: no active rules.
 * Rule ids 13901-13905 were removed as unsound and are never reused: FEDRAMP-01..05 keyed on sentinel names (autoDeprovision / fipsMode / siemStreamBuffer ...) and file-level absence.
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface FedrampComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateFedrampComplianceRules(): FedrampComplianceRuleResult {
    return { findings: [], logs: [] };
}
