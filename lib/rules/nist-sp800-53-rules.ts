/**
 * evaluateNistSp80053Rules: no active rules.
 * Rule ids 11901-11905 were removed as unsound and are never reused: NIST-01..05 keyed on made-up identifiers (sessionManager / leastPrivilegeEnforced / emitAuditEvent ...) and reported file-level "absence of X".
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface NistSp80053RuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateNistSp80053Rules(): NistSp80053RuleResult {
    return { findings: [], logs: [] };
}
