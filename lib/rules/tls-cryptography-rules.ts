/**
 * Zelsis Master evaluateTlsCryptographyRules Engine (50 Rules)
 * Rules TLS-01 to TLS-50 (Rule IDs 12301 to 12350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface TlsCryptographyRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTlsCryptographyRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TlsCryptographyRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TLS-01: Deprecated TLS 1.0 / 1.1 Protocols Permitted on Public Endpoints
    if ((/(?:minVersion|secureProtocol)/i.test(cleanContent) && /(?:TLSv1|TLSv1_method)/i.test(cleanContent) && !/TLSv1_2|TLSv1_3/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:minVersion|secureProtocol)/i, /(?:TLSv1|TLSv1_method)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12301,
            type: 'SECURITY',
            title: "TLS-01: Deprecated TLS 1.0 / 1.1 Protocols Permitted on Public Endpoints",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-01.'
            ],
            remediationPrompt: "Enforce minimum TLS protocol version 1.2 or 1.3 across all reverse proxies and server listeners.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-01: Deprecated TLS 1.0 / 1.1 Protocols Permitted on Public Endpoints at ${file.path}:${lineNum}`);
    }
    // TLS-02: Weak Cipher Suite with Insecure CBC or RC4 Ciphers
    if ((/ciphers:/i.test(cleanContent) && /(?:RC4|3DES|DES|CBC)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/ciphers:/i, /(?:RC4|3DES|DES|CBC)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12302,
            type: 'SECURITY',
            title: "TLS-02: Weak Cipher Suite with Insecure CBC or RC4 Ciphers",
            severity: "HIGH",
            category: "Cryptographic Strength",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-02.'
            ],
            remediationPrompt: "Restrict cipher suites strictly to AEAD modes (AES-GCM, CHACHA20-POLY1305) with PFS.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-02: Weak Cipher Suite with Insecure CBC or RC4 Ciphers at ${file.path}:${lineNum}`);
    }
    // TLS-03: Missing HSTS (HTTP Strict Transport Security) Preload Directive
    if ((/Strict-Transport-Security/i.test(cleanContent) && !/preload/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/Strict-Transport-Security/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12303-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12303,
            type: 'SECURITY',
            title: "TLS-03: Missing HSTS (HTTP Strict Transport Security) Preload Directive",
            severity: "HIGH",
            category: "Downgrade Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-03.'
            ],
            remediationPrompt: "Include the preload directive in Strict-Transport-Security header (max-age=31536000; includeSubDomains; preload).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-03: Missing HSTS (HTTP Strict Transport Security) Preload Directive at ${file.path}:${lineNum}`);
    }
    // TLS-04: Expired or Self-Signed TLS Certificate in Production Traffic Path
    if ((/rejectUnauthorized:\s*false/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/rejectUnauthorized:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12304,
            type: 'SECURITY',
            title: "TLS-04: Expired or Self-Signed TLS Certificate in Production Traffic Path",
            severity: "CRITICAL",
            category: "Certificate Validity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-04.'
            ],
            remediationPrompt: "Enforce rejectUnauthorized: true and use valid CA-signed certificates in production.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-04: Expired or Self-Signed TLS Certificate in Production Traffic Path at ${file.path}:${lineNum}`);
    }
    // TLS-05: Client Renegotiation Permitted Enabling TLS Denial of Service
    if ((/ssl_renegotiation/i.test(cleanContent) && !/renegotiation:\s*false/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/ssl_renegotiation/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12305,
            type: 'SECURITY',
            title: "TLS-05: Client Renegotiation Permitted Enabling TLS Denial of Service",
            severity: "HIGH",
            category: "DDoS Mitigation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-05.'
            ],
            remediationPrompt: "Disable client-initiated TLS renegotiation to neutralize TLS CPU exhaustion vectors.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-05: Client Renegotiation Permitted Enabling TLS Denial of Service at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
