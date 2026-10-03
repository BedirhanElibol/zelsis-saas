/**
 * evaluateWasmEdgeRuntimeRules: no active rules.
 * Rule ids 15201-15205 were removed as unsound and are never reused: WASM-EDGE-01..05 fired on any wasm / worker / simd mention missing sentinel names (maximum_memory_pages / capabilitySandbox ...).
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface WasmEdgeRuntimeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWasmEdgeRuntimeRules(): WasmEdgeRuntimeRuleResult {
    return { findings: [], logs: [] };
}
