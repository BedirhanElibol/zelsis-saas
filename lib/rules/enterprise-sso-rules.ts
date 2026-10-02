/**
 * Zelsis Master evaluateEnterpriseSsoRules Engine (50 Rules)
 * Rules SSO-01 to SSO-50 (Rule IDs 12801 to 12850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface EnterpriseSsoRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEnterpriseSsoRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EnterpriseSsoRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SSO-02: Missing SAML Response Audience and Recipient EntityID Validation
    // node-saml / passport-saml: `audience: false` explicitly turns off the AudienceRestriction check, so an
    // assertion the IdP issued for ANY other service provider is accepted here.
    const usesNodeSaml = /@node-saml\/|passport-saml|\bnew\s+SAML\s*\(|\b(?:Multi)?SamlStrategy\b/.test(cleanContent);
    const samlAudienceOffIdx = !usesNodeSaml ? -1 : lines.findIndex(l => /\baudience\s*:\s*false\b/.test(l));
    if (samlAudienceOffIdx !== -1) {
        const matchLineIdx = samlAudienceOffIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `sso12802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12802,
            type: 'SECURITY',
            title: "SSO-02: SAML Audience Validation Disabled (audience: false)",
            severity: "HIGH",
            category: "Audience Verification",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-02.'
            ],
            remediationPrompt: "Set `audience` to your service provider EntityID (the issuer configured at the IdP) so assertions minted for other applications are rejected.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-02: SAML Audience Validation Disabled (audience: false) at ${file.path}:${lineNum}`);
    }
    // SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache)
    // node-saml / passport-saml with InResponseTo checking switched off: responses are not tied to a request this
    // SP issued, so a captured SAMLResponse can be replayed until it expires. ('ifPresent' still allows IdP-initiated SSO.)
    const samlInResponseToOffIdx = !usesNodeSaml ? -1 : lines.findIndex(l => /\bvalidateInResponseTo\s*:\s*(?:false\b|['"`]never['"`]|ValidateInResponseTo\.never\b)/.test(l));
    if (samlInResponseToOffIdx !== -1) {
        const matchLineIdx = samlInResponseToOffIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `sso12803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12803,
            type: 'SECURITY',
            title: "SSO-03: SAML InResponseTo Validation Disabled (Response Replay)",
            severity: "MEDIUM",
            category: "Replay Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-03.'
            ],
            remediationPrompt: "Set validateInResponseTo to 'always' (or 'ifPresent' when IdP-initiated login is required) and back it with a shared cacheProvider (e.g. Redis) so each request ID is accepted once.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-03: SAML InResponseTo Validation Disabled (Response Replay) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
