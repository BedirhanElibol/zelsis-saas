/**
 * evaluateQuantitativeRiskRules: no active rules.
 * Rule ids 16201-16205 were removed as unsound and are never reused: QUANT-RISK-01..05 matched path words and absence of made-up names (minVarObservationDays = 250 ...).
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface QuantitativeRiskRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateQuantitativeRiskRules(): QuantitativeRiskRuleResult {
    return { findings: [], logs: [] };
}
