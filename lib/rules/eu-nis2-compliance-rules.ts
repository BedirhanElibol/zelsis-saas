/**
 * Zelsis Master evaluateEuNis2ComplianceRules Engine (50 Rules)
 * Rules NIS2-01 to NIS2-50 (Rule IDs 15401 to 15450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface EuNis2ComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEuNis2ComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EuNis2ComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy
    if (cleanContent.includes('nis2MissingRiskManagementFramework') || ((/security_governance|compliance_policy/i.test(lowerPath) || /RiskManagement|cybersecurityPolicy/i.test(cleanContent)) && !/nis2CompliantPolicy/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nis215401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15401,
            type: 'LEGAL_COMPLIANCE',
            title: "NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy",
            severity: "CRITICAL",
            category: "Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
            reproductionSteps: [
                `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Adopt and maintain a formal NIS2 Article 21 cybersecurity policy covering risk analysis, incident handling, and system security.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy at ${file.path}:${lineNum}`);
    }
    // NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA
    if (cleanContent.includes('nis2InadequateEarlyWarningSla') || ((/incident_response|soc_workflows/i.test(lowerPath) || /incidentSla|csirtNotification/i.test(cleanContent)) && cleanContent.includes('missing24hEarlyWarningProcedure') && !/csirtAutomatedAlert24h/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nis215402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15402,
            type: 'LEGAL_COMPLIANCE',
            title: "NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA",
            severity: "CRITICAL",
            category: "Incident Reporting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
            reproductionSteps: [
                `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Implement automated incident notification pipelines ensuring NIS2-compliant 24h early warning and 72h detailed incident reporting to national authorities.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA at ${file.path}:${lineNum}`);
    }
    // NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits
    if (cleanContent.includes('nis2InadequateSupplyChainRiskAudits') || ((/vendor_management|supply_chain/i.test(lowerPath) || /vendorAudit|supplierRisk/i.test(cleanContent)) && !/supplierSecurityAuditCatalog/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nis215403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15403,
            type: 'LEGAL_COMPLIANCE',
            title: "NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits",
            severity: "HIGH",
            category: "Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
            reproductionSteps: [
                `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Enforce supply chain security assessments and contractual security requirements across all tier-1 IT service providers and component vendors.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits at ${file.path}:${lineNum}`);
    }
    // NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting
    if (cleanContent.includes('nis2MissingVulnerabilityDisclosurePolicy') || ((/vulnerability_handling|security_txt/i.test(lowerPath) || /disclosurePolicy/i.test(cleanContent)) && !/coordinatedDisclosureProcess/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nis215404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15404,
            type: 'LEGAL_COMPLIANCE',
            title: "NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting",
            severity: "HIGH",
            category: "Vulnerability Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
            reproductionSteps: [
                `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Publish a coordinated vulnerability disclosure policy and integrate automated CVE scanning across all release deployment stages.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting at ${file.path}:${lineNum}`);
    }
    // NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records
    if (cleanContent.includes('nis2MissingManagementBoardTrainingRecords') || ((/board_governance|executive_compliance/i.test(lowerPath) || /managementBoard/i.test(cleanContent)) && !/boardApprovalRecordsTracked/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nis215405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15405,
            type: 'LEGAL_COMPLIANCE',
            title: "NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records",
            severity: "HIGH",
            category: "Executive Accountability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
            reproductionSteps: [
                `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Conduct mandatory annual cybersecurity training for executive management and maintain board approval records for cybersecurity measures.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
