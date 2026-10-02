/**
 * evaluateVectorIndexOptimizationRules: no active rules.
 * Rule ids 16601-16605 were removed as unsound and are never reused: VEC-OPT-01..05 were tuning opinions keyed on absence of made-up names (enableAvx512OrNeonSimd ...).
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface VectorIndexOptimizationRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateVectorIndexOptimizationRules(): VectorIndexOptimizationRuleResult {
    return { findings: [], logs: [] };
}
