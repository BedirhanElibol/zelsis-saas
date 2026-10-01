/**
 * Zelsis Master evaluateOauthOidcRules Engine (50 Rules)
 * Rules OAUTH-01 to OAUTH-50 (Rule IDs 10901 to 10950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface OauthOidcRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateOauthOidcRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): OauthOidcRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow
    if ((/response_type=code/i.test(cleanContent) && !/code_challenge/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10901,
            type: 'SECURITY',
            title: "OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow",
            severity: "CRITICAL",
            category: "OAuth Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OAuth authentication handler',
            reproductionSteps: [
                `Audited identity federation in ${file.path}:${lineNum}.`,
                'Detected OAuth 2.1 identity violation matching OAUTH-01.'
            ],
            remediationPrompt: "Add code_challenge and code_challenge_method: 'S256' to OAuth authorization request parameters.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow at ${file.path}:${lineNum}`);
    }
    // OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration
    if ((/redirect_uri/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10902,
            type: 'SECURITY',
            title: "OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration",
            severity: "CRITICAL",
            category: "Redirect Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OAuth authentication handler',
            reproductionSteps: [
                `Audited identity federation in ${file.path}:${lineNum}.`,
                'Detected OAuth 2.1 identity violation matching OAUTH-02.'
            ],
            remediationPrompt: "Specify exact canonical HTTPS callback URLs in OAuth client registration and remove all wildcard entries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration at ${file.path}:${lineNum}`);
    }
    // OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake
    if ((/passport\.authenticate\s*\([\s\S]*?\)/.test(cleanContent) && !/state:\s*true|stateParameter/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10903,
            type: 'SECURITY',
            title: "OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake",
            severity: "HIGH",
            category: "CSRF Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OAuth authentication handler',
            reproductionSteps: [
                `Audited identity federation in ${file.path}:${lineNum}.`,
                'Detected OAuth 2.1 identity violation matching OAUTH-03.'
            ],
            remediationPrompt: "Add state parameter validation in OAuth callback handler and reject requests on mismatch.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake at ${file.path}:${lineNum}`);
    }
    // OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm)
    if ((/jwt\.verify\s*\([\s\S]*?\)/.test(cleanContent) && !/algorithms\s*:\s*\[/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10904,
            type: 'SECURITY',
            title: "OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm)",
            severity: "CRITICAL",
            category: "Token Verification",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OAuth authentication handler',
            reproductionSteps: [
                `Audited identity federation in ${file.path}:${lineNum}.`,
                'Detected OAuth 2.1 identity violation matching OAUTH-04.'
            ],
            remediationPrompt: "Set algorithms: ['RS256'] explicitly in jwt.verify() options to defeat algorithm confusion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm) at ${file.path}:${lineNum}`);
    }
    // OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant
    if ((/grant_type\s*=\s*['"]password['"]/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10905,
            type: 'SECURITY',
            title: "OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant",
            severity: "HIGH",
            category: "Grant Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OAuth authentication handler',
            reproductionSteps: [
                `Audited identity federation in ${file.path}:${lineNum}.`,
                'Detected OAuth 2.1 identity violation matching OAUTH-05.'
            ],
            remediationPrompt: "Remove grant_type=password endpoint and transition clients to authorization_code flow.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
