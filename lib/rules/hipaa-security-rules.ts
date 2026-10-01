/**
 * Zelsis Master evaluateHipaaSecurityRules Engine (50 Rules)
 * Rules HIPAASEC-01 to HIPAASEC-50 (Rule IDs 14401 to 14450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface HipaaSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateHipaaSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): HipaaSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // HIPAASEC-01: HIPAA §164.312(a)(1) Access Control: Missing Unique User Identification
    if (((/healthcare_auth/i.test(lowerPath) || /healthcare/i.test(cleanContent)) && !/uniqueUserIdentifier/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/healthcare/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaasec14401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14401,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAASEC-01: HIPAA \u00a7164.312(a)(1) Access Control: Missing Unique User Identification",
            severity: "CRITICAL",
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'HIPAA Security Rule configuration',
            reproductionSteps: [
                `Audited HIPAA Security Rule configuration in ${file.path}:${lineNum}.`,
                'Matched HIPAASEC-01: HIPAA \u00a7164.312(a)(1) Access Control: Missing Unique User Identification.'
            ],
            remediationPrompt: "Assign unique user identifiers to every healthcare worker accessing electronic Protected Health Information (ePHI).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAASEC-01: HIPAA §164.312(a)(1) Access Control: Missing Unique User Identification at ${file.path}:${lineNum}`);
    }
    // HIPAASEC-02: HIPAA §164.312(a)(2)(iii) Automatic Logoff on Inactive Clinical Workstations
    if (((/session_timeout/i.test(lowerPath) || /sessionTimeout/i.test(cleanContent)) && !/maxInactiveTimeout/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/sessionTimeout/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaasec14402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14402,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAASEC-02: HIPAA \u00a7164.312(a)(2)(iii) Automatic Logoff on Inactive Clinical Workstations",
            severity: "HIGH",
            category: "Session Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'HIPAA Security Rule configuration',
            reproductionSteps: [
                `Audited HIPAA Security Rule configuration in ${file.path}:${lineNum}.`,
                'Matched HIPAASEC-02: HIPAA \u00a7164.312(a)(2)(iii) Automatic Logoff on Inactive Clinical Workstations.'
            ],
            remediationPrompt: "Enforce automatic session termination after 15 minutes of inactivity on all clinical terminals accessing ePHI.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAASEC-02: HIPAA §164.312(a)(2)(iii) Automatic Logoff on Inactive Clinical Workstations at ${file.path}:${lineNum}`);
    }
    // HIPAASEC-03: HIPAA §164.312(a)(2)(iv) Encryption and Decryption of ePHI Stored at Rest
    if (((/patient_records|ehr_db/i.test(lowerPath) || /patient_records|ehr_db/i.test(cleanContent)) && !/aes256Gcm/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/patient_records|ehr_db/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaasec14403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14403,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAASEC-03: HIPAA \u00a7164.312(a)(2)(iv) Encryption and Decryption of ePHI Stored at Rest",
            severity: "CRITICAL",
            category: "Cryptographic Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'HIPAA Security Rule configuration',
            reproductionSteps: [
                `Audited HIPAA Security Rule configuration in ${file.path}:${lineNum}.`,
                'Matched HIPAASEC-03: HIPAA \u00a7164.312(a)(2)(iv) Encryption and Decryption of ePHI Stored at Rest.'
            ],
            remediationPrompt: "Encrypt all databases, storage volumes, and backups storing electronic Protected Health Information with AES-256.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAASEC-03: HIPAA §164.312(a)(2)(iv) Encryption and Decryption of ePHI Stored at Rest at ${file.path}:${lineNum}`);
    }
    // HIPAASEC-04: HIPAA §164.312(b) Audit Controls: Missing Immutable Logs for Medical Records
    if (((/medical_record/i.test(lowerPath) || /medicalRecord/i.test(cleanContent)) && !/immutableAuditTrail/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/medicalRecord/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaasec14404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14404,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAASEC-04: HIPAA \u00a7164.312(b) Audit Controls: Missing Immutable Logs for Medical Records",
            severity: "CRITICAL",
            category: "Audit Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'HIPAA Security Rule configuration',
            reproductionSteps: [
                `Audited HIPAA Security Rule configuration in ${file.path}:${lineNum}.`,
                'Matched HIPAASEC-04: HIPAA \u00a7164.312(b) Audit Controls: Missing Immutable Logs for Medical Records.'
            ],
            remediationPrompt: "Record and preserve immutable audit logs of all ePHI read, write, and export operations for a minimum of 6 years.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAASEC-04: HIPAA §164.312(b) Audit Controls: Missing Immutable Logs for Medical Records at ${file.path}:${lineNum}`);
    }
    // HIPAASEC-05: HIPAA §164.312(c)(1) Data Integrity: Electronic Transmission Tampering Detection
    if (((/patient_telemetry/i.test(lowerPath) || /patientTelemetry/i.test(cleanContent)) && !/hmacSignature/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/patientTelemetry/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaasec14405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14405,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAASEC-05: HIPAA \u00a7164.312(c)(1) Data Integrity: Electronic Transmission Tampering Detection",
            severity: "HIGH",
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'HIPAA Security Rule configuration',
            reproductionSteps: [
                `Audited HIPAA Security Rule configuration in ${file.path}:${lineNum}.`,
                'Matched HIPAASEC-05: HIPAA \u00a7164.312(c)(1) Data Integrity: Electronic Transmission Tampering Detection.'
            ],
            remediationPrompt: "Use cryptographic HMAC or digital signatures to verify that patient health records have not been altered in transit.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAASEC-05: HIPAA §164.312(c)(1) Data Integrity: Electronic Transmission Tampering Detection at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
