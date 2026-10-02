/**
 * Zelsis Master evaluateConfidentialComputingRules Engine (all rules retired)
 *
 * Retired rules: CONF-COMPUTE-01..05 (16401-16405). Removed as unsound: matched path names and sentinel identifiers (verifyHardwareRemoteAttestation...), not real enclave code.
 * The ids are retired and must not be reused. The engine stays registered in lib/scanner/rule-engines.ts.
 */
import { Finding } from "@/data/schema";
export interface ConfidentialComputingRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateConfidentialComputingRules(): ConfidentialComputingRuleResult {
    return { findings: [], logs: [] };
}
