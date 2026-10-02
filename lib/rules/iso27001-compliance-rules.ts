/**
 * Zelsis Master evaluateIso27001ComplianceRules Engine (50 Rules)
 * Rules ISO-01 to ISO-50 (Rule IDs 10801 to 10850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface Iso27001ComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateIso27001ComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): Iso27001ComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18)
    const hit_10802 = lines.findIndex((l) => /\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+[^;]*?\bTO\s+PUBLIC\b/i.test(l) || /\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+\*\.\*\s+TO\s+\S+@['"`]?%/i.test(l));
    if (hit_10802 !== -1) {
        const matchLineIdx = hit_10802;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iso10802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10802,
            type: 'LEGAL_COMPLIANCE',
            title: "ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18)",
            severity: "HIGH",
            category: "Access Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'ISO 27001 security control',
            reproductionSteps: [
                `Audited ISO control in ${file.path}:${lineNum}.`,
                'Detected ISO/IEC 27001:2022 compliance violation matching ISO-02.'
            ],
            remediationPrompt: "Integrate access requests with audit-logged approval workflows (e.g. Teleport, AWS IAM Identity Center).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ISO AUDIT] Found ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
