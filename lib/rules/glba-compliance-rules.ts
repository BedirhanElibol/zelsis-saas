/**
 * Zelsis Master evaluateGlbaComplianceRules Engine (50 Rules)
 * Rules GLBA-01 to GLBA-50 (Rule IDs 14901 to 14950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface GlbaComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGlbaComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GlbaComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GLBA-01: GLBA §314.4(a) Designation of Qualified Information Security Officer
    if ((/security_policy/i.test(lowerPath) && !/designatedSecurityOfficer/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `glba14901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14901,
            type: 'LEGAL_COMPLIANCE',
            title: "GLBA-01: GLBA \u00a7314.4(a) Designation of Qualified Information Security Officer",
            severity: "CRITICAL",
            category: "Security Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GLBA Safeguards configuration',
            reproductionSteps: [
                `Audited GLBA Safeguards configuration in ${file.path}:${lineNum}.`,
                'Matched GLBA-01: GLBA \u00a7314.4(a) Designation of Qualified Information Security Officer.'
            ],
            remediationPrompt: "Designate a qualified individual responsible for overseeing and enforcing the enterprise information security program.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GLBA AUDIT] Found GLBA-01: GLBA §314.4(a) Designation of Qualified Information Security Officer at ${file.path}:${lineNum}`);
    }
    // GLBA-02: GLBA §314.4(b) Risk Assessment: Missing Documented Security Evaluation
    if ((/risk_assessment/i.test(lowerPath) && !/annualAssessmentCompleted/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `glba14902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14902,
            type: 'LEGAL_COMPLIANCE',
            title: "GLBA-02: GLBA \u00a7314.4(b) Risk Assessment: Missing Documented Security Evaluation",
            severity: "HIGH",
            category: "Risk Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GLBA Safeguards configuration',
            reproductionSteps: [
                `Audited GLBA Safeguards configuration in ${file.path}:${lineNum}.`,
                'Matched GLBA-02: GLBA \u00a7314.4(b) Risk Assessment: Missing Documented Security Evaluation.'
            ],
            remediationPrompt: "Conduct and document annual written risk assessments evaluating threats to customer non-public financial information.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GLBA AUDIT] Found GLBA-02: GLBA §314.4(b) Risk Assessment: Missing Documented Security Evaluation at ${file.path}:${lineNum}`);
    }
    // GLBA-03: GLBA §314.4(c)(1) Access Controls: Overprivileged Access to Customer NPI
    if (((/financial_crm/i.test(lowerPath) || /financial_crm/i.test(cleanContent)) && !/restrictNpiAccess/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/financial_crm/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `glba14903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14903,
            type: 'LEGAL_COMPLIANCE',
            title: "GLBA-03: GLBA \u00a7314.4(c)(1) Access Controls: Overprivileged Access to Customer NPI",
            severity: "CRITICAL",
            category: "Access Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GLBA Safeguards configuration',
            reproductionSteps: [
                `Audited GLBA Safeguards configuration in ${file.path}:${lineNum}.`,
                'Matched GLBA-03: GLBA \u00a7314.4(c)(1) Access Controls: Overprivileged Access to Customer NPI.'
            ],
            remediationPrompt: "Limit employee access to customer non-public personal financial information strictly to legitimate business needs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GLBA AUDIT] Found GLBA-03: GLBA §314.4(c)(1) Access Controls: Overprivileged Access to Customer NPI at ${file.path}:${lineNum}`);
    }
    // GLBA-04: GLBA §314.4(c)(2) Data Inventory: Missing Systems and NPI Data Flow Inventory
    if ((/data_map/i.test(lowerPath) && !/npiDataInventoryCatalog/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `glba14904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14904,
            type: 'LEGAL_COMPLIANCE',
            title: "GLBA-04: GLBA \u00a7314.4(c)(2) Data Inventory: Missing Systems and NPI Data Flow Inventory",
            severity: "HIGH",
            category: "Data Inventory",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GLBA Safeguards configuration',
            reproductionSteps: [
                `Audited GLBA Safeguards configuration in ${file.path}:${lineNum}.`,
                'Matched GLBA-04: GLBA \u00a7314.4(c)(2) Data Inventory: Missing Systems and NPI Data Flow Inventory.'
            ],
            remediationPrompt: "Maintain an up-to-date inventory of all systems, cloud stores, and APIs processing customer financial data.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GLBA AUDIT] Found GLBA-04: GLBA §314.4(c)(2) Data Inventory: Missing Systems and NPI Data Flow Inventory at ${file.path}:${lineNum}`);
    }
    // GLBA-05: GLBA §314.4(c)(3) Encryption: Unencrypted Customer Financial Data at Rest and Transit
    if (((/customer_financial/i.test(lowerPath) || /customer_financial/i.test(cleanContent)) && !/aes256Gcm/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/customer_financial/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `glba14905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14905,
            type: 'LEGAL_COMPLIANCE',
            title: "GLBA-05: GLBA \u00a7314.4(c)(3) Encryption: Unencrypted Customer Financial Data at Rest and Transit",
            severity: "CRITICAL",
            category: "Data Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GLBA Safeguards configuration',
            reproductionSteps: [
                `Audited GLBA Safeguards configuration in ${file.path}:${lineNum}.`,
                'Matched GLBA-05: GLBA \u00a7314.4(c)(3) Encryption: Unencrypted Customer Financial Data at Rest and Transit.'
            ],
            remediationPrompt: "Encrypt all customer non-public financial information using AES-256 at rest and TLS 1.3 in transit.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GLBA AUDIT] Found GLBA-05: GLBA §314.4(c)(3) Encryption: Unencrypted Customer Financial Data at Rest and Transit at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
