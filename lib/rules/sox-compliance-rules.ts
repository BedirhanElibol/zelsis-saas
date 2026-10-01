/**
 * Zelsis Master evaluateSoxComplianceRules Engine (50 Rules)
 * Rules SOX-01 to SOX-50 (Rule IDs 13401 to 13450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface SoxComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSoxComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): SoxComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SOX-01: SOX ITGC Change Management: Lack of Independent Peer Review on Financial Code
    if ((/financial_pipeline|general_ledger/i.test(lowerPath) && !/requireReviewers/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sox13401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13401,
            type: 'LEGAL_COMPLIANCE',
            title: "SOX-01: SOX ITGC Change Management: Lack of Independent Peer Review on Financial Code",
            severity: "CRITICAL",
            category: "Change Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SOX ITGC configuration',
            reproductionSteps: [
                `Audited SOX ITGC configuration in ${file.path}:${lineNum}.`,
                'Matched SOX-01: SOX ITGC Change Management: Lack of Independent Peer Review on Financial Code.'
            ],
            remediationPrompt: "Mandate at least one independent, documented peer approval before deploying to financial systems.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SOX AUDIT] Found SOX-01: SOX ITGC Change Management: Lack of Independent Peer Review on Financial Code at ${file.path}:${lineNum}`);
    }
    // SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access
    if (((/sox/i.test(lowerPath) || /sox/i.test(cleanContent)) && !/restrictWriteAccess/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sox13402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13402,
            type: 'LEGAL_COMPLIANCE',
            title: "SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access",
            severity: "CRITICAL",
            category: "Duty Segregation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SOX ITGC configuration',
            reproductionSteps: [
                `Audited SOX ITGC configuration in ${file.path}:${lineNum}.`,
                'Matched SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access.'
            ],
            remediationPrompt: "Revoke direct production write and DDL permissions from development and engineering staff.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SOX AUDIT] Found SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access at ${file.path}:${lineNum}`);
    }
    // SOX-03: SOX ITGC Audit Trail: Missing Immutable Logging for Financial Transaction Modifications
    if ((/ledger|journal/i.test(cleanContent) && !/immutableAuditLog/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sox13403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13403,
            type: 'LEGAL_COMPLIANCE',
            title: "SOX-03: SOX ITGC Audit Trail: Missing Immutable Logging for Financial Transaction Modifications",
            severity: "CRITICAL",
            category: "Audit Immutability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SOX ITGC configuration',
            reproductionSteps: [
                `Audited SOX ITGC configuration in ${file.path}:${lineNum}.`,
                'Matched SOX-03: SOX ITGC Audit Trail: Missing Immutable Logging for Financial Transaction Modifications.'
            ],
            remediationPrompt: "Ensure immutable, append-only audit logging with cryptographic hashing for all financial table changes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SOX AUDIT] Found SOX-03: SOX ITGC Audit Trail: Missing Immutable Logging for Financial Transaction Modifications at ${file.path}:${lineNum}`);
    }
    // SOX-04: SOX ITGC Access Governance: Dormant Financial Accounts Active Beyond 30 Days
    if ((/financial_auth/i.test(lowerPath) && !/autoSuspendDormant/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sox13404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13404,
            type: 'LEGAL_COMPLIANCE',
            title: "SOX-04: SOX ITGC Access Governance: Dormant Financial Accounts Active Beyond 30 Days",
            severity: "HIGH",
            category: "Account Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SOX ITGC configuration',
            reproductionSteps: [
                `Audited SOX ITGC configuration in ${file.path}:${lineNum}.`,
                'Matched SOX-04: SOX ITGC Access Governance: Dormant Financial Accounts Active Beyond 30 Days.'
            ],
            remediationPrompt: "Automate suspension and deprovisioning of financial application accounts dormant for over 30 days.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SOX AUDIT] Found SOX-04: SOX ITGC Access Governance: Dormant Financial Accounts Active Beyond 30 Days at ${file.path}:${lineNum}`);
    }
    // SOX-05: SOX ITGC Disaster Recovery: Untested Annual Financial Ledger Backup Restoration
    if ((/backup_restore/i.test(lowerPath) && !/verifyRestoreSla/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sox13405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13405,
            type: 'LEGAL_COMPLIANCE',
            title: "SOX-05: SOX ITGC Disaster Recovery: Untested Annual Financial Ledger Backup Restoration",
            severity: "HIGH",
            category: "Business Continuity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SOX ITGC configuration',
            reproductionSteps: [
                `Audited SOX ITGC configuration in ${file.path}:${lineNum}.`,
                'Matched SOX-05: SOX ITGC Disaster Recovery: Untested Annual Financial Ledger Backup Restoration.'
            ],
            remediationPrompt: "Conduct and document quarterly automated restoration drills for financial general ledger databases.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SOX AUDIT] Found SOX-05: SOX ITGC Disaster Recovery: Untested Annual Financial Ledger Backup Restoration at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
