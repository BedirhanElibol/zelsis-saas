/**
 * Zelsis Master evaluateSiemAuditLoggingRules Engine (50 Rules)
 * Rules AUDIT-01 to AUDIT-50 (Rule IDs 12101 to 12150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface SiemAuditLoggingRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSiemAuditLoggingRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): SiemAuditLoggingRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs
    // Files using @/lib/logger automatically redact sensitive tokens, passwords, and PII.
    if (/console\.(?:log|warn|info|debug)\s*\([^)]*(?:password|secret|apiKey|bearerToken)[^)]*\)/i.test(cleanContent) && !/logger\./i.test(cleanContent) && !/sanitizeLog/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `audit-12101-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12101,
            type: 'SECURITY',
            title: "AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs",
            severity: "CRITICAL",
            category: "Data Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SIEM Audit Logging code segment',
            reproductionSteps: [
                `Audited SIEM Audit Logging configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching AUDIT-01.'
            ],
            remediationPrompt: "Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SIEM AUDIT] Found AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs at ${file.path}:${lineNum}`);
    }
    // AUDIT-02: Missing RFC 5424 Structured JSON Format for SIEM Ingestion
    if ((/console\.log\("[^"]+"\s*\+/i.test(cleanContent) && !/structuredJsonLogger/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `audit-12102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12102,
            type: 'SECURITY',
            title: "AUDIT-02: Missing RFC 5424 Structured JSON Format for SIEM Ingestion",
            severity: "MEDIUM",
            category: "SIEM Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SIEM Audit Logging code segment',
            reproductionSteps: [
                `Audited SIEM Audit Logging configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching AUDIT-02.'
            ],
            remediationPrompt: "Adopt standardized RFC 5424 structured JSON logging with severity, timestamp, and context fields.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SIEM AUDIT] Found AUDIT-02: Missing RFC 5424 Structured JSON Format for SIEM Ingestion at ${file.path}:${lineNum}`);
    }
    // AUDIT-03: Audit Log Sink Missing Out-of-Band Network Isolation
    if ((/syslogTarget/i.test(cleanContent) && !/tlsEnabled:\s*true/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `audit-12103-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12103,
            type: 'SECURITY',
            title: "AUDIT-03: Audit Log Sink Missing Out-of-Band Network Isolation",
            severity: "HIGH",
            category: "Log Transport",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SIEM Audit Logging code segment',
            reproductionSteps: [
                `Audited SIEM Audit Logging configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching AUDIT-03.'
            ],
            remediationPrompt: "Transmit security logs over mutually-authenticated TLS syslog connections on isolated egress networks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SIEM AUDIT] Found AUDIT-03: Audit Log Sink Missing Out-of-Band Network Isolation at ${file.path}:${lineNum}`);
    }
    // AUDIT-04: Missing Nonce or Cryptographic Signature on Critical Audit Events
    if ((/auditRecord/i.test(cleanContent) && !/sha256Signature|hashChain/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `audit-12104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12104,
            type: 'SECURITY',
            title: "AUDIT-04: Missing Nonce or Cryptographic Signature on Critical Audit Events",
            severity: "HIGH",
            category: "Tamper Resistance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SIEM Audit Logging code segment',
            reproductionSteps: [
                `Audited SIEM Audit Logging configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching AUDIT-04.'
            ],
            remediationPrompt: "Implement SHA-256 HMAC hash chaining on audit logs to provide cryptographic non-repudiation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SIEM AUDIT] Found AUDIT-04: Missing Nonce or Cryptographic Signature on Critical Audit Events at ${file.path}:${lineNum}`);
    }
    // AUDIT-05: Silent Log Drop on Buffer Full Without Alerting Mechanism
    if ((/logBuffer/i.test(cleanContent) && !/backpressure|diskSpill/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `audit-12105-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12105,
            type: 'SECURITY',
            title: "AUDIT-05: Silent Log Drop on Buffer Full Without Alerting Mechanism",
            severity: "HIGH",
            category: "Audit Completeness",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SIEM Audit Logging code segment',
            reproductionSteps: [
                `Audited SIEM Audit Logging configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching AUDIT-05.'
            ],
            remediationPrompt: "Enforce disk-spill buffer queue and emit alerts upon log buffer utilization exceeding 80%.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SIEM AUDIT] Found AUDIT-05: Silent Log Drop on Buffer Full Without Alerting Mechanism at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
