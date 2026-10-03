/**
 * evaluateEdgeCdnRules: no active rules.
 * Rule ids 11101-11105 were removed as unsound and are never reused: CDN-01 (Cache-Control without
 * `immutable` anywhere in next.config / static paths; Next already serves hashed assets immutable),
 * CDN-02 (`compress: false` is the documented setting behind a compressing proxy / CDN), CDN-03
 * (file-level absence of Access-Control-Max-Age), CDN-04 (sentinel string), CDN-05 (any GET route
 * without Cache-Control; uncached dynamic responses are the safe default).
 * The engine stays registered so the rule-engine registry and its imports are unchanged.
 */
import { Finding } from "@/data/schema";
export interface EdgeCdnRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEdgeCdnRules(): EdgeCdnRuleResult {
    return { findings: [], logs: [] };
}
