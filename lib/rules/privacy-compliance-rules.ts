/**
 * Zelsis Master evaluatePrivacyComplianceRules Engine (50 Rules)
 * Rules PRIVACY-01 to PRIVACY-50 (Rule IDs 8201 to 8250).
 * Removed as unsound (ids never reused): 8206, 8221, 8223, 8227, 8228, 8230, 8234, 8236, 8244, 8247, 8248 (keyed on
 * made-up identifiers), 8210, 8222, 8232, 8235, 8245, 8249 (line-1 / file-level or absence-of-X), 8229, 8239, 8243
 * (wrong premise: OAuth scopes, permission prompts and public profiles are product choices, not code defects).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface PrivacyComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluatePrivacyComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): PrivacyComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // PRIVACY-01: Plaintext PII Logged to Standard Output / Console
    if (/console\.(?:log|info|warn|error)\s*\([^)]*(?:password|creditCard|ssn|rawSecret|userSecret)[^)]*\)/i.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/console\.(?:log|info|warn|error)\s*\([^)]*(?:password|creditCard|ssn|rawSecret|userSecret)[^)]*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `privacy01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8201,
            type: 'LEGAL_COMPLIANCE',
            title: "PRIVACY-01: Plaintext PII Logged to Standard Output / Console",
            severity: 'HIGH',
            category: "Telemetry & Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected PRIVACY-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Plaintext PII Logged to Standard Output / Console: Fines up to \u20ac20M or 4% global turnover under GDPR Art. 83"
            ],
            remediationPrompt: "Application logger must apply automated regex redaction masking emails, phones, and credit cards before logging.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚖️ HIGH: PRIVACY-01 finding in ${file.path}:${lineNum}`);
    }
    // PRIVACY-07: Unmasked PII Forwarded to Third-Party Error Trackers (Sentry)
    if (/Sentry\.init\s*\(\{[\s\S]*?sendDefaultPii:\s*true/i.test(cleanContent) && !/beforeSend/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/Sentry\.init\s*\(\{[\s\S]*?sendDefaultPii:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `privacy07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8207,
            type: 'LEGAL_COMPLIANCE',
            title: "PRIVACY-07: Unmasked PII Forwarded to Third-Party Error Trackers (Sentry)",
            severity: 'HIGH',
            category: "Telemetry & Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected PRIVACY-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unmasked PII Forwarded to Third-Party Error Trackers (Sentry): Exposure of customer health/financial data to third-party processors without DPA"
            ],
            remediationPrompt: "Error monitoring SDKs must configure beforeSend hooks to scrub user emails, passwords, and sensitive cookies.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚖️ HIGH: PRIVACY-07 finding in ${file.path}:${lineNum}`);
    }
    // PRIVACY-15: Unprotected Exposure of Customer PII in URL Query Strings
    // router.push(`...?email=${...}`), router.replace / redirect(...) or window.location.href = `...`
    const piiInUrl = /(?:\b(?:router\.(?:push|replace)|redirect)\s*\(\s*|window\.location\.href\s*=\s*)`[^`]*[?&]email=\$\{/i;
    if (piiInUrl.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [piiInUrl], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `privacy15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8215,
            type: 'LEGAL_COMPLIANCE',
            title: "PRIVACY-15: Unprotected Exposure of Customer PII in URL Query Strings",
            severity: 'MEDIUM',
            category: "Transmission Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected PRIVACY-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unprotected Exposure of Customer PII in URL Query Strings: Data leakage into browser history, proxy server logs, and referrer headers"
            ],
            remediationPrompt: "Personal identifiers must be passed in encrypted request bodies or retrieved from authenticated session tokens.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚖️ MEDIUM: PRIVACY-15 finding in ${file.path}:${lineNum}`);
    }
    // PRIVACY-25: Insecure Session Recording Tools Capturing Form Input PII
    // Real session-replay APIs that take maskAllInputs (posthog.init(key, {...}), Sentry replayIntegration /
    // new Replay); LogRocket.init takes the app id first, so `LogRocket.init({` never occurs
    if (/(?:LogRocket\.init|FullStory\.init|posthog\.init|replayIntegration|new\s+(?:Sentry\.)?Replay)\s*\([\s\S]{0,600}?maskAllInputs\s*:\s*false/.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/maskAllInputs\s*:\s*false/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `privacy25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8225,
            type: 'LEGAL_COMPLIANCE',
            title: "PRIVACY-25: Insecure Session Recording Tools Capturing Form Input PII",
            severity: 'MEDIUM',
            category: "Session Replay Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected PRIVACY-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Session Recording Tools Capturing Form Input PII: Massive PII exposure into third-party session recording vendors (FullStory/Hotjar)"
            ],
            remediationPrompt: "Session recording scripts must enable strict masking rules (data-mask-all) on all inputs and sensitive text.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚖️ MEDIUM: PRIVACY-25 finding in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
