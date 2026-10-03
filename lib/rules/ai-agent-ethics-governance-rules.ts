/**
 * evaluateAiAgentEthicsGovernanceRules: every rule this engine shipped (AI-ETHICS-01..05, ids 16901-16905) was removed as unsound (sentinel identifiers,
 * path-name or file-level "absence of X" checks, or compliance process requirements that are invisible
 * in code). The ids must not be reused. The engine stays registered so new, fixture-proven rules can land here.
 */
import type { Finding } from "@/data/schema";
export interface AiAgentEthicsGovernanceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateAiAgentEthicsGovernanceRules(): AiAgentEthicsGovernanceRuleResult {
    return { findings: [], logs: [] };
}
