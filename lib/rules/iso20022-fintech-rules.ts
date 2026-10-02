/**
 * evaluateIso20022FintechRules: no active rules.
 * Rule ids 15801-15805 were removed as unsound and are never reused: ISO20022-01..05 matched sentinel strings and file-level absence of made-up validator names.
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface Iso20022FintechRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateIso20022FintechRules(): Iso20022FintechRuleResult {
    return { findings: [], logs: [] };
}
