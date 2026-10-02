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
    // A floor of TLS 1.0/1.1 set explicitly: Node minVersion/secureProtocol, Python ssl constants, Go MinVersion, nginx ssl_protocols.
    const legacyTlsLine = /\bminVersion\s*:\s*['"`]TLSv1(?:\.1)?['"`]|\bsecureProtocol\s*:\s*['"`](?:TLSv1|TLSv1_1|SSLv3)_(?:server_|client_)?method['"`]|\bssl\.PROTOCOL_(?:TLSv1|TLSv1_1|SSLv3)\b(?!_)|\bminimum_version\s*=\s*ssl\.TLSVersion\.TLSv1(?:_1)?\b(?!_)|\bMinVersion\s*:\s*tls\.VersionTLS1[01]\b|^\s*ssl_protocols\b[^;]*\bTLSv1(?:\.1)?(?=[\s;])/;
    const legacyTlsIdx = lines.findIndex(l => !/^\s*(?:\/\/|#|\*)/.test(l) && legacyTlsLine.test(l));
    if (legacyTlsIdx !== -1) {
        const matchLineIdx = legacyTlsIdx;
        const lineNum = matchLineIdx + 1;
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
    // Only a cipher string that *enables* a broken suite (RC4, 3DES/DES, NULL, EXPORT); `!RC4` exclusions are fine.
    const cipherStringRe = /(?:\bciphers\s*[:=]\s*|\bset_ciphers\s*\(\s*|^\s*ssl_ciphers\s+)['"`]([^'"`]+)['"`]/i;
    const enablesBrokenCipher = (spec: string) => spec.split(/[:\s,]+/).some(t => t && !/^[!-]/.test(t) && /(?:^|[-_+])(?:RC4|3DES|DES|NULL|EXPORT|EXP)(?:$|[-_])/i.test(t));
    const weakCipherIdx = lines.findIndex(l => {
        if (/^\s*(?:\/\/|#|\*)/.test(l)) return false;
        const m = l.match(cipherStringRe);
        return !!m && enablesBrokenCipher(m[1]);
    });
    if (weakCipherIdx !== -1) {
        const matchLineIdx = weakCipherIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `tls12302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12302,
            type: 'SECURITY',
            title: "TLS-02: Weak Cipher Suite Enabled (RC4 / 3DES / NULL / EXPORT)",
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
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-02: Weak Cipher Suite Enabled (RC4 / 3DES / NULL / EXPORT) at ${file.path}:${lineNum}`);
    }
    // TLS-04: Expired or Self-Signed TLS Certificate in Production Traffic Path
    if ((/rejectUnauthorized:\s*false/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/rejectUnauthorized:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tls12304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12304,
            type: 'SECURITY',
            title: "TLS-04: TLS Certificate Verification Disabled (rejectUnauthorized: false)",
            severity: "HIGH",
            category: "Certificate Validity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'TLS Cryptography configuration',
            reproductionSteps: [
                `Audited TLS Cryptography configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching TLS-04.'
            ],
            remediationPrompt: "Remove rejectUnauthorized: false. If the server uses a private or self-signed CA, pass that CA via the `ca` option instead of disabling verification.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TLS AUDIT] Found TLS-04: TLS Certificate Verification Disabled (rejectUnauthorized: false) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
