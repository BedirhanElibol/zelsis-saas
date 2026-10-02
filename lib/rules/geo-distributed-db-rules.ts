/**
 * Zelsis Master evaluateGeoDistributedDbRules Engine (all rules retired)
 *
 * Retired rules: GEODIST-01..05 (15001-15005). Removed as unsound: GEODIST-01 fired on every CREATE TABLE without PARTITION BY; the rest matched sentinel names (cluster_topology, sortKeysBeforeUpdate...).
 * The ids are retired and must not be reused. The engine stays registered in lib/scanner/rule-engines.ts.
 */
import { Finding } from "@/data/schema";
export interface GeoDistributedDbRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGeoDistributedDbRules(): GeoDistributedDbRuleResult {
    return { findings: [], logs: [] };
}
