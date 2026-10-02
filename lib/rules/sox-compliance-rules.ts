/**
 * evaluateSoxComplianceRules: no active rules.
 * Rule ids 13401-13405 were removed as unsound and are never reused: SOX-01..05 are process controls (peer review, SoD, restore drills) invisible in code; they matched path words and sentinel names.
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface SoxComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSoxComplianceRules(): SoxComplianceRuleResult {
    return { findings: [], logs: [] };
}
