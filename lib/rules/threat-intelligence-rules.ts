/**
 * Zelsis Master evaluateThreatIntelligenceRules Engine (50 Rules)
 * Rules CTI-01 to CTI-50 (Rule IDs 15601 to 15650).
 */
import { Finding } from "@/data/schema";
export interface ThreatIntelligenceRuleResult {
    findings: Finding[];
    logs: string[];
}
/**
 * No active rules. The former rules were removed as unsound: CTI-01..05 keyed on sentinel identifiers (verifyFeedSignature, iocTtlDays, ...) and file-level absence.
 * The engine stays registered so rule ids are never reused.
 */
export function evaluateThreatIntelligenceRules(): ThreatIntelligenceRuleResult {
    return { findings: [], logs: [] };
}
