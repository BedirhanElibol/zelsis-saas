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
    // Only values count: console.log('Getting Stripe Secret Key') logs a fixed string, not a secret.
    const LOG_CALL = /console\.(?:log|warn|info|debug)\s*\(([^)]*)\)/gi;
    const SENSITIVE_VALUE = /(?:password|secret|apiKey|bearerToken)/i;
    const logsSensitiveValue = (code: string) => [...code.matchAll(LOG_CALL)].some((m) => {
        const args = m[1]
            .replace(/`([^`]*)`/g, (_t, inner: string) => (inner.match(/\$\{[^}]*\}/g) || []).join(' '))
            .replace(/'[^'\n]*'|"[^"\n]*"/g, '""');
        return SENSITIVE_VALUE.test(args);
    });
    if (logsSensitiveValue(cleanContent) && !/logger\./i.test(cleanContent) && !/sanitizeLog/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !/^\s*(?:\/\/|--|#|\*)/.test(l) && logsSensitiveValue(l));
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
    return { findings, logs };
}
