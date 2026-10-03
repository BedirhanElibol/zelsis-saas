/**
 * Zelsis Master evaluateEdgeAiModelQuantizationRules Engine (all rules retired)
 *
 * Retired rules: EDGE-AI-OPT-01..05 (17301-17305). Removed as unsound: model-optimisation advice keyed on sentinel identifiers; not a security or correctness defect.
 * The ids are retired and must not be reused. The engine stays registered in lib/scanner/rule-engines.ts.
 */
import { Finding } from "@/data/schema";
export interface EdgeAiModelQuantizationRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEdgeAiModelQuantizationRules(): EdgeAiModelQuantizationRuleResult {
    return { findings: [], logs: [] };
}
