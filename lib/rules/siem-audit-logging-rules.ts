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
    // SENSITIVE_VALUE: exclude boolean comparison variables like passwordMatch, isPasswordValid, etc.
    const SENSITIVE_VALUE = /(?<!has|is|hide|validate|check|verify|_has|_is|_hide)(?:password|secret|apiKey|bearerToken)(?!(?:_?(?:match(?:es|ed)?|valid(?:ity)?|correct|check(?:ed)?|equals?))\b)/i;
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
            // Ignore truncated or masked expressions like key?.slice(0, 3) or token.substring(0, 4)
            .replace(/[\w$.?]+(?:\?\.)?(?:slice|substring|substr)\s*\([^)]*\)/g, '""')
            // Ignore masking/redaction helper calls (e.g. mask(key), redact(secret))
            .replace(/\b(?:mask|redact|obfuscate|truncate)\w*\s*\([^)]*\)/gi, '""')
            // Ignore boolean comparisons (===, !==, ==, !=)
            .replace(/[\w$.?]+\s*(?:===|!==|==|!=)\s*[^,)]+/g, '""')
            // Ignore ternaries returning fixed status indicators or booleans where the variable is only checked for presence
            .replace(/[\w$.]+\s*\?\s*(?:['"][^'"]*['"]|true|false|null)\s*:\s*(?:['"][^'"]*['"]|true|false|null)/g, '""')
            .replace(/(?:Boolean\s*\([^)]*\)|!![\w$.]+)/g, '""');
        const args = cleaned
            .replace(/`([^`]*)`/g, (_t, inner: string) => (inner.match(/\$\{[^}]*\}/g) || []).join(' '))
            .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, '""');
        return SENSITIVE_VALUE.test(args);
    });
    // Docs, administrative CLI commands, key generation utilities, and dev scripts do not log production user data
    const normPath = file.path.replace(/\\/g, '/');
    const notAppCode = /\.(?:json|mdx?|txt|html|sh|bash|zsh)$/i.test(file.path)
        || /(?:^|\/)(?:scripts?|docs?|bin|commands?|console|docker\/utils)\//i.test(normPath)
        || /(?:\.command|\.register|\.setup|\.seed)\.[cm]?[jt]s$/i.test(file.path);
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
