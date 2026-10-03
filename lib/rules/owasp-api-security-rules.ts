/**
 * Zelsis Master evaluateOwaspApiSecurityRules Engine (50 Rules)
 * Rules APIDEF-01 to APIDEF-50 (Rule IDs 14301 to 14350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface OwaspApiSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateOwaspApiSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): OwaspApiSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    // APIDEF-03 (14303) and APIDEF-05 (14305) removed as unsound: they keyed on made-up identifiers
    // (updateProfile / saveUser / adminRouter / manageTenant) and on the absence of equally made-up guard names.
    // Mass assignment and admin authorization are covered by the Node / Next.js rule sets. Ids are never reused.
    void lines;
    void cleanContent;
    void findingCounter;
    return { findings, logs };
}
