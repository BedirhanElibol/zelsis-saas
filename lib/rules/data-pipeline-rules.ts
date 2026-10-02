/**
 * evaluateDataPipelineRules: no active rules.
 * Rule ids 11501-11505 were removed as unsound and are never reused: DATA-01..05 flagged normal code (any spark read, CSV export, INSERT..SELECT, email VARCHAR column) via file-level absence.
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface DataPipelineRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateDataPipelineRules(): DataPipelineRuleResult {
    return { findings: [], logs: [] };
}
