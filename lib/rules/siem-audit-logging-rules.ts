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
    const SENSITIVE_VALUE = /(?<!has|is|hide)(?:password|secret|apiKey|bearerToken)/i;
    const extractLogCalls = (code: string): string[] => {
        const regex = /console\.(?:log|warn|info|debug)\s*\(/gi;
        const calls: string[] = [];
        let match: RegExpExecArray | null;
        while ((match = regex.exec(code)) !== null) {
            const startIdx = match.index + match[0].length;
            let depth = 1;
            let inSingle = false;
            let inDouble = false;
            let inBacktick = false;
            let i = startIdx;
            while (i < code.length && depth > 0) {
                const ch = code[i];
                const prev = i > 0 ? code[i - 1] : '';
                if (prev !== '\\') {
                    if (!inDouble && !inBacktick && ch === "'") inSingle = !inSingle;
                    else if (!inSingle && !inBacktick && ch === '"') inDouble = !inDouble;
                    else if (!inSingle && !inDouble && ch === '`') inBacktick = !inBacktick;
                    else if (!inSingle && !inDouble && !inBacktick) {
                        if (ch === '(') depth++;
                        else if (ch === ')') depth--;
                    }
                }
                if (depth === 0) break;
                i++;
            }
            calls.push(code.slice(startIdx, i));
        }
        return calls;
    };
    const logsSensitiveValue = (code: string) => extractLogCalls(code).some((callContent) => {
        const cleaned = callContent
            // Ignore ternaries returning fixed status indicators or booleans where the variable is only checked for presence
            .replace(/[\w$.]+\s*\?\s*(?:['"][^'"]*['"]|true|false|null)\s*:\s*(?:['"][^'"]*['"]|true|false|null)/g, '""')
            .replace(/(?:Boolean\s*\([^)]*\)|!![\w$.]+)/g, '""');
        const args = cleaned
            .replace(/`([^`]*)`/g, (_t, inner: string) => (inner.match(/\$\{[^}]*\}/g) || []).join(' '))
            .replace(/'[^'\n]*'|"[^"\n]*"/g, '""');
        return SENSITIVE_VALUE.test(args);
    });
    // Docs, API collections (Postman JSON) and dev scripts that print a seeded test password do not log user data
    const notAppCode = /\.(?:json|mdx?|txt|html)$/i.test(file.path) || /(?:^|\/)(?:scripts?|docs?|bin)\//i.test(file.path.replace(/\\/g, '/')) || /(?:\.register|\.setup|\.seed)\.[cm]?[jt]s$/i.test(file.path);
    if (!notAppCode && logsSensitiveValue(cleanContent) && !/logger\./i.test(cleanContent) && !/sanitizeLog/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !/^\s*(?:\/\/|--|#|\*)/.test(l) && logsSensitiveValue(l));
        if (matchLineIdx !== -1) {
        const lineNum = matchLineIdx + 1;
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
    }
    return { findings, logs };
}
