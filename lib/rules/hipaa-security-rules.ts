/**
 * evaluateHipaaSecurityRules: no active rules.
 * Rule ids 14401-14405 were removed as unsound and are never reused: HIPAASEC-01..05 fired on any "healthcare" / "medicalRecord" text missing sentinel names (uniqueUserIdentifier / aes256Gcm ...).
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface HipaaSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateHipaaSecurityRules(): HipaaSecurityRuleResult {
    return { findings: [], logs: [] };
}
