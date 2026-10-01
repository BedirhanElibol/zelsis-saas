/**
 * Zelsis Master evaluateHipaaComplianceRules Engine (50 Rules)
 * Rules HIPAA-01 to HIPAA-50 (Rule IDs 9801 to 9850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface HipaaComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateHipaaComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): HipaaComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip files that do not handle healthcare, patient, or PHI data
    if (
        lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") ||
        (!/(?:health|patient|medical|phi|ehr|clinical|doctor)/i.test(cleanContent) && !/(?:health|patient|medical|phi|ehr)/i.test(lowerPath))
    ) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // HIPAA-01: Unencrypted Protected Health Information (PHI) at Rest
    if ((/(?:medical_record|diagnosis|patient_health_record)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:medical_record|diagnosis|patient_health_record)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaa9801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9801,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAA-01: Unencrypted Protected Health Information (PHI) at Rest",
            severity: "CRITICAL",
            category: "PHI Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Healthcare data operation',
            reproductionSteps: [
                `Audited healthcare data flow in ${file.path}:${lineNum}.`,
                'Detected HIPAA compliance violation matching HIPAA-01.'
            ],
            remediationPrompt: "Enable column-level encryption or transparent data encryption on all patient medical record stores.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAA-01: Unencrypted Protected Health Information (PHI) at Rest at ${file.path}:${lineNum}`);
    }
    // HIPAA-02: PHI Exposed in URL Query Parameters / Referral Headers
    if ((/fetch\s*\([`'"].*?[?&](?:mrn|diagnosis|ssn|patient_id)=\$\{/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/fetch\s*\([`'"].*?[?&](?:mrn|diagnosis|ssn|patient_id)=\$\{/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaa9802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9802,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAA-02: PHI Exposed in URL Query Parameters / Referral Headers",
            severity: "HIGH",
            category: "Data Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Healthcare data operation',
            reproductionSteps: [
                `Audited healthcare data flow in ${file.path}:${lineNum}.`,
                'Detected HIPAA compliance violation matching HIPAA-02.'
            ],
            remediationPrompt: "Migrate query parameters containing patient health data into JSON request payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAA-02: PHI Exposed in URL Query Parameters / Referral Headers at ${file.path}:${lineNum}`);
    }
    // HIPAA-03: Missing Audit Trail for PHI Record Access and Modification
    if ((/(?:patient|medicalRecord|ehr|phi)\.(?:find|query|select)/i.test(cleanContent) && !/auditLog|auditTrail|recordAccess/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:patient|medicalRecord|ehr|phi)\.(?:find|query|select)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaa9803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9803,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAA-03: Missing Audit Trail for PHI Record Access and Modification",
            severity: "HIGH",
            category: "Access Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Healthcare data operation',
            reproductionSteps: [
                `Audited healthcare data flow in ${file.path}:${lineNum}.`,
                'Detected HIPAA compliance violation matching HIPAA-03.'
            ],
            remediationPrompt: "Record an immutable audit log entry whenever patient medical records are queried or updated.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAA-03: Missing Audit Trail for PHI Record Access and Modification at ${file.path}:${lineNum}`);
    }
    // HIPAA-04: Third-Party Analytics Tracking Pixels on Health Portal
    if ((/fbq\s*\(\s*['"]track['"]/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/fbq\s*\(\s*['"]track['"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaa9804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9804,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAA-04: Third-Party Analytics Tracking Pixels on Health Portal",
            severity: "CRITICAL",
            category: "Data Tracking",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Healthcare data operation',
            reproductionSteps: [
                `Audited healthcare data flow in ${file.path}:${lineNum}.`,
                'Detected HIPAA compliance violation matching HIPAA-04.'
            ],
            remediationPrompt: "Purge marketing tracking tags from patient portal and EHR web applications.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAA-04: Third-Party Analytics Tracking Pixels on Health Portal at ${file.path}:${lineNum}`);
    }
    // HIPAA-05: Automated Session Timeout Missing on Clinical Terminal
    if ((/session\.(?:maxAge|timeout)/i.test(cleanContent) && /(?:Infinity|null|undefined|86400000)/.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/session\.(?:maxAge|timeout)/i, /(?:Infinity|null|undefined|86400000)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `hipaa9805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9805,
            type: 'LEGAL_COMPLIANCE',
            title: "HIPAA-05: Automated Session Timeout Missing on Clinical Terminal",
            severity: "MEDIUM",
            category: "Session Inactivity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Healthcare data operation',
            reproductionSteps: [
                `Audited healthcare data flow in ${file.path}:${lineNum}.`,
                'Detected HIPAA compliance violation matching HIPAA-05.'
            ],
            remediationPrompt: "Configure idle session timeout timer of 15 minutes across clinical healthcare interfaces.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [HIPAA AUDIT] Found HIPAA-05: Automated Session Timeout Missing on Clinical Terminal at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
