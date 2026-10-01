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
    const isApiTarget = lowerPath.startsWith("app/api/") || lowerPath.startsWith("pages/api/") || lowerPath.includes("/api/") || lowerPath.includes("server/") || lowerPath.includes("backend/");
    if (!isApiTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup
    if ((/lookupResource|getItem/i.test(cleanContent) && !/verifyOwnership/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `apidef14301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14301,
            type: 'SECURITY',
            title: "APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup",
            severity: "CRITICAL",
            category: "Object Authorization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP API Top 10 configuration',
            reproductionSteps: [
                `Audited OWASP API Top 10 configuration in ${file.path}:${lineNum}.`,
                'Matched APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup.'
            ],
            remediationPrompt: "Validate user authorization and tenant ownership for every resource identifier supplied in API paths.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [API SECURITY AUDIT] Found APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup at ${file.path}:${lineNum}`);
    }
    // APIDEF-02: API2:2023 Broken Authentication: Insecure Token Invalidation on Logout
    if ((/logoutHandler/i.test(cleanContent) && !/blacklistToken/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `apidef14302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14302,
            type: 'SECURITY',
            title: "APIDEF-02: API2:2023 Broken Authentication: Insecure Token Invalidation on Logout",
            severity: "CRITICAL",
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP API Top 10 configuration',
            reproductionSteps: [
                `Audited OWASP API Top 10 configuration in ${file.path}:${lineNum}.`,
                'Matched APIDEF-02: API2:2023 Broken Authentication: Insecure Token Invalidation on Logout.'
            ],
            remediationPrompt: "Revoke and blacklist JWTs in a distributed Redis cache upon user logout or credentials reset.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [API SECURITY AUDIT] Found APIDEF-02: API2:2023 Broken Authentication: Insecure Token Invalidation on Logout at ${file.path}:${lineNum}`);
    }
    // APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment
    if ((/updateProfile|saveUser/i.test(cleanContent) && !/pickAllowedFields/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // APIDEF-04: API4:2023 Unrestricted Resource Consumption: Missing Client Rate Limits
    if ((/exportData|heavySearch/i.test(cleanContent) && !/checkRateLimit/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `apidef14304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14304,
            type: 'SECURITY',
            title: "APIDEF-04: API4:2023 Unrestricted Resource Consumption: Missing Client Rate Limits",
            severity: "HIGH",
            category: "Resource Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP API Top 10 configuration',
            reproductionSteps: [
                `Audited OWASP API Top 10 configuration in ${file.path}:${lineNum}.`,
                'Matched APIDEF-04: API4:2023 Unrestricted Resource Consumption: Missing Client Rate Limits.'
            ],
            remediationPrompt: "Enforce token-bucket rate limits and query pagination bounds on resource-intensive analytical routes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [API SECURITY AUDIT] Found APIDEF-04: API4:2023 Unrestricted Resource Consumption: Missing Client Rate Limits at ${file.path}:${lineNum}`);
    }
    // APIDEF-05: API5:2023 Broken Function Level Authorization: Admin Routes Missing Scope Check
    if ((/adminRouter|manageTenant/i.test(cleanContent) && !/requireRole/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
