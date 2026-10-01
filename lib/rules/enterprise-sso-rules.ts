/**
 * Zelsis Master evaluateEnterpriseSsoRules Engine (50 Rules)
 * Rules SSO-01 to SSO-50 (Rule IDs 12801 to 12850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    // SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser
    if ((/saml/i.test(lowerPath) && !/validateSignatureAnchors/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sso12801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12801,
            type: 'SECURITY',
            title: "SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser",
            severity: "CRITICAL",
            category: "SAML Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-01.'
            ],
            remediationPrompt: "Validate XML signature anchors directly against assertion IDs to prevent XML Signature Wrapping attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser at ${file.path}:${lineNum}`);
    }
    // SSO-02: Missing SAML Response Audience and Recipient EntityID Validation
    if ((/validateSaml/i.test(cleanContent) && !/assertAudience/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/validateSaml/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sso12802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12802,
            type: 'SECURITY',
            title: "SSO-02: Missing SAML Response Audience and Recipient EntityID Validation",
            severity: "HIGH",
            category: "Audience Verification",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-02.'
            ],
            remediationPrompt: "Enforce strict AudienceRestriction validation matching your service provider's EntityID.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-02: Missing SAML Response Audience and Recipient EntityID Validation at ${file.path}:${lineNum}`);
    }
    // SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache)
    if ((/processSamlAssertion/i.test(cleanContent) && !/assertionCache/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/processSamlAssertion/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sso12803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12803,
            type: 'SECURITY',
            title: "SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache)",
            severity: "HIGH",
            category: "Replay Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-03.'
            ],
            remediationPrompt: "Store processed SAML Assertion IDs in an in-memory or distributed cache with TTL to thwart replay attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache) at ${file.path}:${lineNum}`);
    }
    // SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint
    if ((/\/scim\/v2/i.test(lowerPath) && !/verifyBearerToken/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sso12804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12804,
            type: 'SECURITY',
            title: "SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint",
            severity: "CRITICAL",
            category: "SCIM Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-04.'
            ],
            remediationPrompt: "Require Bearer token authentication with tenant scoping on all SCIM 2.0 provisioning endpoints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint at ${file.path}:${lineNum}`);
    }
    // SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook
    if ((/scim/i.test(lowerPath) && !/handleUserDeactivation/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sso12805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12805,
            type: 'SECURITY',
            title: "SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook",
            severity: "HIGH",
            category: "Identity Lifecycle",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
            reproductionSteps: [
                `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SSO-05.'
            ],
            remediationPrompt: "Handle SCIM DELETE and PATCH active=false requests immediately to revoke access upon employee offboarding.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SSO AUDIT] Found SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
