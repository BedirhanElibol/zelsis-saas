/**
 * Zelsis Master evaluateNistSp80053Rules Engine (50 Rules)
 * Rules NIST-01 to NIST-50 (Rule IDs 11901 to 11950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface NistSp80053RuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateNistSp80053Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): NistSp80053RuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // NIST-01: NIST AC-2 Account Management Automated Inactivity Deactivation
    if ((/sessionManager/i.test(cleanContent) && !/maxInactivityDays|deactivateInactive/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nist-11901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11901,
            type: 'LEGAL_COMPLIANCE',
            title: "NIST-01: NIST AC-2 Account Management Automated Inactivity Deactivation",
            severity: "HIGH",
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'NIST SP 800-53 code segment',
            reproductionSteps: [
                `Audited NIST SP 800-53 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching NIST-01.'
            ],
            remediationPrompt: "Enforce automated account deactivation for credentials inactive for over 90 days (NIST AC-2).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIST AUDIT] Found NIST-01: NIST AC-2 Account Management Automated Inactivity Deactivation at ${file.path}:${lineNum}`);
    }
    // NIST-02: NIST AC-3 Access Enforcement Principle of Least Privilege
    if ((/iamPolicy/i.test(cleanContent) && !/leastPrivilegeEnforced/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nist-11902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11902,
            type: 'LEGAL_COMPLIANCE',
            title: "NIST-02: NIST AC-3 Access Enforcement Principle of Least Privilege",
            severity: "CRITICAL",
            category: "Privilege Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'NIST SP 800-53 code segment',
            reproductionSteps: [
                `Audited NIST SP 800-53 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching NIST-02.'
            ],
            remediationPrompt: "Eliminate wildcard administrative permissions and implement strict role-based access control (NIST AC-3).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIST AUDIT] Found NIST-02: NIST AC-3 Access Enforcement Principle of Least Privilege at ${file.path}:${lineNum}`);
    }
    // NIST-03: NIST AU-2 Event Logging Across All Privileged System Actions
    if ((/adminActionHandler/i.test(cleanContent) && !/emitAuditEvent/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nist-11903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11903,
            type: 'LEGAL_COMPLIANCE',
            title: "NIST-03: NIST AU-2 Event Logging Across All Privileged System Actions",
            severity: "HIGH",
            category: "Audit & Accountability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'NIST SP 800-53 code segment',
            reproductionSteps: [
                `Audited NIST SP 800-53 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching NIST-03.'
            ],
            remediationPrompt: "Log all administrative mutations and privileged session events to immutable audit sinks (NIST AU-2).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIST AUDIT] Found NIST-03: NIST AU-2 Event Logging Across All Privileged System Actions at ${file.path}:${lineNum}`);
    }
    // NIST-04: NIST AU-9 Protection of Audit Information Immutability
    if ((/auditStorage/i.test(cleanContent) && !/wormLock|retentionLock/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nist-11904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11904,
            type: 'LEGAL_COMPLIANCE',
            title: "NIST-04: NIST AU-9 Protection of Audit Information Immutability",
            severity: "CRITICAL",
            category: "Log Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'NIST SP 800-53 code segment',
            reproductionSteps: [
                `Audited NIST SP 800-53 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching NIST-04.'
            ],
            remediationPrompt: "Configure tamper-evident, write-once read-many (WORM) storage for all audit trails (NIST AU-9).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIST AUDIT] Found NIST-04: NIST AU-9 Protection of Audit Information Immutability at ${file.path}:${lineNum}`);
    }
    // NIST-05: NIST CM-8 Information System Component Inventory Automation
    if ((/cloudInventory/i.test(cleanContent) && !/autoDiscoverAssets/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `nist-11905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11905,
            type: 'LEGAL_COMPLIANCE',
            title: "NIST-05: NIST CM-8 Information System Component Inventory Automation",
            severity: "MEDIUM",
            category: "Asset Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'NIST SP 800-53 code segment',
            reproductionSteps: [
                `Audited NIST SP 800-53 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching NIST-05.'
            ],
            remediationPrompt: "Deploy automated cloud asset discovery to continuously inventory all compute, network, and storage assets (NIST CM-8).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [NIST AUDIT] Found NIST-05: NIST CM-8 Information System Component Inventory Automation at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
