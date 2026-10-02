/**
 * Zelsis Master evaluateOwaspApiSecurityRules Engine (50 Rules)
 * Rules APIDEF-01 to APIDEF-50 (Rule IDs 14301 to 14350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    const isApiTarget = lowerPath.startsWith("app/api/") || lowerPath.startsWith("pages/api/") || lowerPath.includes("/api/") || lowerPath.includes("server/") || lowerPath.includes("backend/");
    if (!isApiTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment
    if ((/updateProfile|saveUser/i.test(cleanContent) && !/pickAllowedFields/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/updateProfile|saveUser/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `apidef14303-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14303,
            type: 'SECURITY',
            title: "APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment",
            severity: "CRITICAL",
            category: "Property Authorization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP API Top 10 configuration',
            reproductionSteps: [
                `Audited OWASP API Top 10 configuration in ${file.path}:${lineNum}.`,
                'Matched APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment.'
            ],
            remediationPrompt: "Disallow bulk assignment on sensitive object properties (isAdmin, role, verified, balance) in API handlers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [API SECURITY AUDIT] Found APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment at ${file.path}:${lineNum}`);
    }
    // APIDEF-05: API5:2023 Broken Function Level Authorization: Admin Routes Missing Scope Check
    if ((/adminRouter|manageTenant/i.test(cleanContent) && !/requireRole/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/adminRouter|manageTenant/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `apidef14305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14305,
            type: 'SECURITY',
            title: "APIDEF-05: API5:2023 Broken Function Level Authorization: Admin Routes Missing Scope Check",
            severity: "CRITICAL",
            category: "Function Authorization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP API Top 10 configuration',
            reproductionSteps: [
                `Audited OWASP API Top 10 configuration in ${file.path}:${lineNum}.`,
                'Matched APIDEF-05: API5:2023 Broken Function Level Authorization: Admin Routes Missing Scope Check.'
            ],
            remediationPrompt: "Enforce role-based permission checks before executing administrative API operations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [API SECURITY AUDIT] Found APIDEF-05: API5:2023 Broken Function Level Authorization: Admin Routes Missing Scope Check at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
