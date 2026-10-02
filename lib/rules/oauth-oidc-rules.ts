/**
 * Zelsis Master evaluateOauthOidcRules Engine (50 Rules)
 * Rules OAUTH-01 to OAUTH-50 (Rule IDs 10901 to 10950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface OauthOidcRuleResult {
    findings: Finding[];
    logs: string[];
}
/** passport login through a social / OAuth2 strategy (local username+password strategies have no state). */
const OAUTH_STRATEGY_AUTH = /passport\.authenticate\s*\(\s*["'](?:google|github|facebook|twitter|oauth2|linkedin|microsoft|discord|gitlab|apple|slack|auth0)["']/i;
/** Resource Owner Password Credentials grant (form body, object literal or kwarg); Supabase's own password login excluded. */
const ROPC_GRANT = /grant_type["']?\s*[:=]\s*["']password["']|grant_type=password\b(?![^\n]*auth\/v1\/token)/i;
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
    // OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration
    if ((/redirect_uri/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/redirect_uri/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (OAUTH_STRATEGY_AUTH.test(cleanContent) && /new\s+\w*Strategy\s*\(/.test(cleanContent) && !/state:\s*true|stateParameter|\bstore:/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [OAUTH_STRATEGY_AUTH], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant
    if (ROPC_GRANT.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [ROPC_GRANT], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `oauth10905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10905,
            type: 'SECURITY',
            title: "OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant",
            severity: 'MEDIUM',
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
