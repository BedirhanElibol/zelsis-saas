/**
 * Zelsis Master evaluateRaspAntiTamperRules Engine (all rules retired)
 *
 * Retired rules: RASP-01..05 (14601-14605). Removed as unsound: matched made-up identifiers (dynamicExecution, raspGuard, initializeRuntime...) or any binding.gyp mention.
 * The ids are retired and must not be reused. The engine stays registered in lib/scanner/rule-engines.ts.
 */
import { Finding } from "@/data/schema";
export interface RaspAntiTamperRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateRaspAntiTamperRules(): RaspAntiTamperRuleResult {
    return { findings: [], logs: [] };
}
