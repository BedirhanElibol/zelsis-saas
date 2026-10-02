/**
 * Zelsis Master Enterprise Secret Signatures Evaluator (100 Rules)
 * Rules SEC-SECRET-01 to SEC-SECRET-100 (Rule IDs 5001 to 5100).
 *
 * Implements high-precision pattern recognition for SaaS, cloud, payment,
 * and database credentials matching TruffleHog & GitGuardian industry standards.
 *
 * F-12 Remediation: Accurate line matching via pattern-based line finding.
 * F-16 Remediation: Scans unstripped content (including comments), line-level placeholder checks.
 * F-17 Remediation: Masks sensitive secrets in snippets (replaces token with prefix****suffix).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface SecretRuleResult {
    findings: Finding[];
    logs: string[];
}
export function isDummyPlaceholder(line: string): boolean {
    if (!line || typeof line !== 'string')
        return false;
    return /placeholder|ghp_x{8,}|EXAMPLE|dummy|test_secret_12345|\bx{10,}\b|00000000/i.test(line);
}
export function maskSecretInLine(line: string, pattern: RegExp): string {
    if (!line)
        return '[REDACTED_SECRET]';
    try {
        return line.replace(pattern, (match) => {
            if (match.length <= 6)
                return '****';
            const prefix = match.slice(0, 4);
            const suffix = match.slice(-2);
            return `${prefix}****${suffix}`;
        });
    }
    catch {
        return line;
    }
}
export function evaluateSecretRules(file: CodeFile, lines: string[], rawContentOrClean: string, findingCounter: {
    count: number;
}): SecretRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential rule catalogs, mocks, and schema definitions
    if (lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const contentToScan = rawContentOrClean || file.content;
    const ts = new Date().toLocaleTimeString();
    // SEC-SECRET-01: AWS Access Key ID Exposure
    const pattern01 = /\bAKIA[0-9A-Z]{16}\b/i;
    if (pattern01.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern01.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5001,
                type: 'SECURITY',
                title: 'SEC-SECRET-01: AWS Access Key ID Exposure',
                severity: 'CRITICAL',
                category: "Cloud Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern01),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching AWS Access Key ID Exposure signature: AWS IAM Access Key ID (AKIA...) exposed in source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-01: AWS Access Key ID Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-02: AWS Secret Access Key Exposure
    const pattern02 = /aws_secret_access_key\s*=\s*["\'][A-Za-z0-9\/+=]{40}["\']/i;
    if (pattern02.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern02.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5002,
                type: 'SECURITY',
                title: 'SEC-SECRET-02: AWS Secret Access Key Exposure',
                severity: 'CRITICAL',
                category: "Cloud Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern02),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching AWS Secret Access Key Exposure signature: AWS Secret Access Key exposed in configuration or code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-02: AWS Secret Access Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-03: GitHub Classic Personal Access Token
    const pattern03 = /\bghp_[a-zA-Z0-9]{36}\b/i;
    if (pattern03.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern03.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5003,
                type: 'SECURITY',
                title: 'SEC-SECRET-03: GitHub Classic Personal Access Token',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern03),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitHub Classic Personal Access Token signature: Classic GitHub PAT (ghp_...) committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-03: GitHub Classic Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-04: GitHub Fine-Grained Personal Access Token
    const pattern04 = /\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b/i;
    if (pattern04.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern04.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5004,
                type: 'SECURITY',
                title: 'SEC-SECRET-04: GitHub Fine-Grained Personal Access Token',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern04),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitHub Fine-Grained Personal Access Token signature: Fine-grained GitHub token (github_pat_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-04: GitHub Fine-Grained Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-05: GitHub OAuth Access Token
    const pattern05 = /\bgho_[a-zA-Z0-9]{36}\b/i;
    if (pattern05.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern05.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5005,
                type: 'SECURITY',
                title: 'SEC-SECRET-05: GitHub OAuth Access Token',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern05),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitHub OAuth Access Token signature: GitHub OAuth access token (gho_...) committed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-05: GitHub OAuth Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-06: GitHub App Installation Token
    const pattern06 = /\bgh[us]_[a-zA-Z0-9]{36}\b/i;
    if (pattern06.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern06.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5006,
                type: 'SECURITY',
                title: 'SEC-SECRET-06: GitHub App Installation Token',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern06),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitHub App Installation Token signature: GitHub App token (ghu_ / ghs_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-06: GitHub App Installation Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-07: Slack Incoming Webhook URL
    const pattern07 = /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9A-Za-z]{24}/i;
    if (pattern07.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern07.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5007,
                type: 'SECURITY',
                title: 'SEC-SECRET-07: Slack Incoming Webhook URL',
                severity: 'CRITICAL',
                category: "SaaS Webhooks",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern07),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Slack Incoming Webhook URL signature: Slack Incoming Webhook URL exposed in client or public repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-07: Slack Incoming Webhook URL detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-08: Slack Bot User OAuth Token
    const pattern08 = /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/i;
    if (pattern08.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern08.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5008,
                type: 'SECURITY',
                title: 'SEC-SECRET-08: Slack Bot User OAuth Token',
                severity: 'CRITICAL',
                category: "SaaS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern08),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Slack Bot User OAuth Token signature: Slack bot user token (xoxb-...) exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-08: Slack Bot User OAuth Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-09: Slack User Token
    const pattern09 = /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/i;
    if (pattern09.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern09.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5009,
                type: 'SECURITY',
                title: 'SEC-SECRET-09: Slack User Token',
                severity: 'CRITICAL',
                category: "SaaS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern09),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Slack User Token signature: Slack user OAuth token (xoxp-...) exposed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-09: Slack User Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-10: Stripe Live Secret Key Exposure
    const pattern10 = /\bsk_live_[0-9a-zA-Z]{24,}\b/i;
    if (pattern10.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern10.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5010,
                type: 'SECURITY',
                title: 'SEC-SECRET-10: Stripe Live Secret Key Exposure',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern10),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Stripe Live Secret Key Exposure signature: Stripe production secret key (sk_live_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-10: Stripe Live Secret Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-11: Stripe Live Restricted Key Exposure
    const pattern11 = /\brk_live_[0-9a-zA-Z]{24,}\b/i;
    if (pattern11.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern11.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5011,
                type: 'SECURITY',
                title: 'SEC-SECRET-11: Stripe Live Restricted Key Exposure',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern11),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Stripe Live Restricted Key Exposure signature: Stripe restricted live key (rk_live_...) exposed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-11: Stripe Live Restricted Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-12: Stripe Webhook Signing Secret
    const pattern12 = /\bwhsec_[0-9a-zA-Z]{32,}\b/i;
    if (pattern12.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern12.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5012,
                type: 'SECURITY',
                title: 'SEC-SECRET-12: Stripe Webhook Signing Secret',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern12),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Stripe Webhook Signing Secret signature: Stripe webhook secret (whsec_...) hardcoded in source."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-12: Stripe Webhook Signing Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-13: OpenAI API Secret Key Exposure
    const pattern13 = /\bsk-[a-zA-Z0-9]{48}\b|\bsk-proj-[a-zA-Z0-9_-]{48,}\b/i;
    if (pattern13.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern13.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5013,
                type: 'SECURITY',
                title: 'SEC-SECRET-13: OpenAI API Secret Key Exposure',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern13),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching OpenAI API Secret Key Exposure signature: OpenAI API key (sk-... / sk-proj-...) committed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-13: OpenAI API Secret Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-14: Anthropic API Secret Key Exposure
    const pattern14 = /\bsk-ant-api03-[a-zA-Z0-9_-]{93,}\b/i;
    if (pattern14.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern14.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5014,
                type: 'SECURITY',
                title: 'SEC-SECRET-14: Anthropic API Secret Key Exposure',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern14),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Anthropic API Secret Key Exposure signature: Anthropic Claude API key (sk-ant-...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-14: Anthropic API Secret Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-15: Google Gemini / AI Studio API Key
    const pattern15 = /\bAIzaSy[0-9A-Za-z-_]{33}\b/i;
    if (pattern15.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern15.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5015,
                type: 'SECURITY',
                title: 'SEC-SECRET-15: Google Gemini / AI Studio API Key',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern15),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Google Gemini / AI Studio API Key signature: Google AI Studio API key (AIzaSy...) hardcoded in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-15: Google Gemini / AI Studio API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-16: Google Cloud Service Account JSON Key
    const pattern16 = /"type":\s*"service_account"[\s\S]*"private_key":\s*"-----BEGIN/i;
    if (pattern16.test(contentToScan)) {
        // Multi-line signature (service account JSON): point at the private_key line
        const matchLineIdx = lines.findIndex(l => /"private_key":\s*"-----BEGIN/i.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5016,
                type: 'SECURITY',
                title: 'SEC-SECRET-16: Google Cloud Service Account JSON Key',
                severity: 'CRITICAL',
                category: "Cloud Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", /-----BEGIN[^"]*/),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Google Cloud Service Account JSON Key signature: GCP Service Account private key JSON committed in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-16: Google Cloud Service Account JSON Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-17: Google Cloud OAuth Client Secret
    const pattern17 = /client_secret\s*=\s*["\'][a-zA-Z0-9_-]{24,}["\']/i;
    if (pattern17.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern17.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5017,
                type: 'SECURITY',
                title: 'SEC-SECRET-17: Google Cloud OAuth Client Secret',
                severity: 'CRITICAL',
                category: "Cloud Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern17),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Google Cloud OAuth Client Secret signature: Google OAuth 2.0 client secret hardcoded in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-17: Google Cloud OAuth Client Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-18: Supabase Service Role Secret Key
    const pattern18 = /SUPABASE_SERVICE_ROLE_KEY\s*=\s*["\']eyJh[a-zA-Z0-9_-]+\.eyJh[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["\']/i;
    if (pattern18.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern18.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5018,
                type: 'SECURITY',
                title: 'SEC-SECRET-18: Supabase Service Role Secret Key',
                severity: 'CRITICAL',
                category: "Database Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern18),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Supabase Service Role Secret Key signature: Supabase service_role JWT key exposed in client bundle."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-18: Supabase Service Role Secret Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-19: Polar.sh Webhook Secret Exposure
    const pattern19 = /\bpolar_whsec_[a-zA-Z0-9_-]{20,}\b/i;
    if (pattern19.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern19.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5019,
                type: 'SECURITY',
                title: 'SEC-SECRET-19: Polar.sh Webhook Secret Exposure',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern19),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Polar.sh Webhook Secret Exposure signature: Polar.sh webhook signing secret (polar_whsec_...) hardcoded."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-19: Polar.sh Webhook Secret Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-20: Polar.sh Access Token Exposure
    const pattern20 = /\bpolar_at_[a-zA-Z0-9_-]{20,}\b/i;
    if (pattern20.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern20.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5020,
                type: 'SECURITY',
                title: 'SEC-SECRET-20: Polar.sh Access Token Exposure',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern20),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Polar.sh Access Token Exposure signature: Polar.sh API access token (polar_at_...) committed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-20: Polar.sh Access Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-21: Twilio Account SID & Auth Token
    const pattern21 = /\bAC[a-f0-9]{32}\b/i;
    if (pattern21.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern21.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5021,
                type: 'SECURITY',
                title: 'SEC-SECRET-21: Twilio Account SID & Auth Token',
                severity: 'CRITICAL',
                category: "Communication SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern21),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Twilio Account SID & Auth Token signature: Twilio Account SID (AC...) and Auth Token in source."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-21: Twilio Account SID & Auth Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-22: SendGrid Mail API Key Exposure
    const pattern22 = /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/i;
    if (pattern22.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern22.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5022,
                type: 'SECURITY',
                title: 'SEC-SECRET-22: SendGrid Mail API Key Exposure',
                severity: 'CRITICAL',
                category: "Email SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern22),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching SendGrid Mail API Key Exposure signature: SendGrid API key (SG...) hardcoded in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-22: SendGrid Mail API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-23: Mailgun API Private Key Exposure
    const pattern23 = /\bkey-[0-9a-zA-Z]{32}\b/i;
    if (pattern23.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern23.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5023,
                type: 'SECURITY',
                title: 'SEC-SECRET-23: Mailgun API Private Key Exposure',
                severity: 'CRITICAL',
                category: "Email SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern23),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Mailgun API Private Key Exposure signature: Mailgun private API key (key-...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-23: Mailgun API Private Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-24: Resend Email API Key Exposure
    const pattern24 = /\bre_[a-zA-Z0-9]{24,}\b/i;
    if (pattern24.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern24.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5024,
                type: 'SECURITY',
                title: 'SEC-SECRET-24: Resend Email API Key Exposure',
                severity: 'CRITICAL',
                category: "Email SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern24),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Resend Email API Key Exposure signature: Resend API key (re_...) committed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-24: Resend Email API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-25: Postmark Server API Token
    const pattern25 = /postmark_server_token\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern25.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern25.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5025,
                type: 'SECURITY',
                title: 'SEC-SECRET-25: Postmark Server API Token',
                severity: 'CRITICAL',
                category: "Email SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern25),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Postmark Server API Token signature: Postmark server token exposed in configuration or code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-25: Postmark Server API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-26: NPM Automation & Publishing Token
    const pattern26 = /\bnpm_[a-zA-Z0-9]{36}\b/i;
    if (pattern26.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern26.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5026,
                type: 'SECURITY',
                title: 'SEC-SECRET-26: NPM Automation & Publishing Token',
                severity: 'CRITICAL',
                category: "Package Registry",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern26),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching NPM Automation & Publishing Token signature: NPM automation token (npm_...) committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-26: NPM Automation & Publishing Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-27: PyPI Package Upload API Token
    const pattern27 = /\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}\b/i;
    if (pattern27.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern27.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5027,
                type: 'SECURITY',
                title: 'SEC-SECRET-27: PyPI Package Upload API Token',
                severity: 'CRITICAL',
                category: "Package Registry",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern27),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching PyPI Package Upload API Token signature: PyPI authentication token (pypi-...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-27: PyPI Package Upload API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-28: HuggingFace User Access Token
    const pattern28 = /\bhf_[a-zA-Z0-9]{34,}\b/i;
    if (pattern28.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern28.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5028,
                type: 'SECURITY',
                title: 'SEC-SECRET-28: HuggingFace User Access Token',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern28),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching HuggingFace User Access Token signature: HuggingFace user access token (hf_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-28: HuggingFace User Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-29: Datadog API Key Exposure
    const pattern29 = /datadog_api_key\s*=\s*["\'][a-f0-9]{32}["\']/i;
    if (pattern29.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern29.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5029,
                type: 'SECURITY',
                title: 'SEC-SECRET-29: Datadog API Key Exposure',
                severity: 'CRITICAL',
                category: "Monitoring SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern29),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Datadog API Key Exposure signature: Datadog API key committed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-29: Datadog API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-30: Sentry Authentication Token
    const pattern30 = /\bsntrys_[a-zA-Z0-9]{64}\b/i;
    if (pattern30.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern30.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5030,
                type: 'SECURITY',
                title: 'SEC-SECRET-30: Sentry Authentication Token',
                severity: 'CRITICAL',
                category: "Monitoring SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern30),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Sentry Authentication Token signature: Sentry auth token (sntrys_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-30: Sentry Authentication Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-31: Cloudflare Global API Key
    const pattern31 = /cloudflare_global_api_key\s*=\s*["\'][0-9a-f]{37}["\']/i;
    if (pattern31.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern31.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5031,
                type: 'SECURITY',
                title: 'SEC-SECRET-31: Cloudflare Global API Key',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern31),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Cloudflare Global API Key signature: Cloudflare Global API Key exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-31: Cloudflare Global API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-32: Cloudflare Scoped API Token
    const pattern32 = /cloudflare_api_token\s*=\s*["\'][a-zA-Z0-9_-]{40}["\']/i;
    if (pattern32.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern32.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5032,
                type: 'SECURITY',
                title: 'SEC-SECRET-32: Cloudflare Scoped API Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern32),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Cloudflare Scoped API Token signature: Cloudflare API token exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-32: Cloudflare Scoped API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-33: Algolia Admin API Key Exposure
    const pattern33 = /algolia_admin_key\s*=\s*["\'][a-f0-9]{32}["\']/i;
    if (pattern33.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern33.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5033,
                type: 'SECURITY',
                title: 'SEC-SECRET-33: Algolia Admin API Key Exposure',
                severity: 'CRITICAL',
                category: "Search SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern33),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Algolia Admin API Key Exposure signature: Algolia Admin API key exposed in frontend bundle."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-33: Algolia Admin API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-34: DigitalOcean Personal Access Token
    const pattern34 = /\bdop_v1_[a-f0-9]{64}\b/i;
    if (pattern34.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern34.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5034,
                type: 'SECURITY',
                title: 'SEC-SECRET-34: DigitalOcean Personal Access Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern34),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching DigitalOcean Personal Access Token signature: DigitalOcean PAT (dop_v1_...) exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-34: DigitalOcean Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-35: Heroku API Key Exposure
    const pattern35 = /heroku_api_key\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern35.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern35.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5035,
                type: 'SECURITY',
                title: 'SEC-SECRET-35: Heroku API Key Exposure',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern35),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Heroku API Key Exposure signature: Heroku platform API key exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-35: Heroku API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-36: Vercel Personal Access Token
    const pattern36 = /vercel_token\s*=\s*["\'][a-zA-Z0-9_-]{24,}["\']/i;
    if (pattern36.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern36.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5036,
                type: 'SECURITY',
                title: 'SEC-SECRET-36: Vercel Personal Access Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern36),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Vercel Personal Access Token signature: Vercel API token exposed in configuration or code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-36: Vercel Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-37: Netlify Personal Access Token
    const pattern37 = /netlify_token\s*=\s*["\'][a-zA-Z0-9_-]{40,}["\']/i;
    if (pattern37.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern37.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5037,
                type: 'SECURITY',
                title: 'SEC-SECRET-37: Netlify Personal Access Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern37),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Netlify Personal Access Token signature: Netlify personal access token exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-37: Netlify Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-38: Shopify Admin API Access Token
    const pattern38 = /\bshpat_[a-fA-F0-9]{32}\b/i;
    if (pattern38.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern38.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5038,
                type: 'SECURITY',
                title: 'SEC-SECRET-38: Shopify Admin API Access Token',
                severity: 'CRITICAL',
                category: "E-Commerce SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern38),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Shopify Admin API Access Token signature: Shopify admin token (shpat_...) committed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-38: Shopify Admin API Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-39: Square Production Access Token
    const pattern39 = /\bsq0atp-[0-9A-Za-z-_]{22}\b/i;
    if (pattern39.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern39.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5039,
                type: 'SECURITY',
                title: 'SEC-SECRET-39: Square Production Access Token',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern39),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Square Production Access Token signature: Square production token (sq0atp-...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-39: Square Production Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-40: GitLab Personal Access Token
    const pattern40 = /\bglpat-[0-9a-zA-Z_-]{20}\b/i;
    if (pattern40.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern40.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5040,
                type: 'SECURITY',
                title: 'SEC-SECRET-40: GitLab Personal Access Token',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern40),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitLab Personal Access Token signature: GitLab PAT (glpat-...) committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-40: GitLab Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-41: Bitbucket App Password Exposure
    const pattern41 = /bitbucket_app_password\s*=\s*["\'][a-zA-Z0-9]{20,}["\']/i;
    if (pattern41.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern41.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5041,
                type: 'SECURITY',
                title: 'SEC-SECRET-41: Bitbucket App Password Exposure',
                severity: 'CRITICAL',
                category: "VCS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern41),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Bitbucket App Password Exposure signature: Bitbucket app password exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-41: Bitbucket App Password Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-42: Atlassian / Jira API Token
    const pattern42 = /atlassian_api_token\s*=\s*["\'][a-zA-Z0-9]{24,}["\']/i;
    if (pattern42.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern42.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5042,
                type: 'SECURITY',
                title: 'SEC-SECRET-42: Atlassian / Jira API Token',
                severity: 'CRITICAL',
                category: "SaaS Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern42),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Atlassian / Jira API Token signature: Atlassian API token committed in configuration files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-42: Atlassian / Jira API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-43: Discord Bot Token Exposure
    const pattern43 = /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b/i;
    if (pattern43.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern43.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5043,
                type: 'SECURITY',
                title: 'SEC-SECRET-43: Discord Bot Token Exposure',
                severity: 'CRITICAL',
                category: "Communication SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern43),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Discord Bot Token Exposure signature: Discord bot token committed into source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-43: Discord Bot Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-44: Telegram Bot API Token
    const pattern44 = /\b[0-9]{9,10}:[a-zA-Z0-9_-]{35}\b/i;
    if (pattern44.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern44.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5044,
                type: 'SECURITY',
                title: 'SEC-SECRET-44: Telegram Bot API Token',
                severity: 'CRITICAL',
                category: "Communication SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern44),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Telegram Bot API Token signature: Telegram bot token exposed in source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-44: Telegram Bot API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-45: RSA Private Key Block Exposure
    const pattern45 = /-----BEGIN RSA PRIVATE KEY-----/i;
    if (pattern45.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern45.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5045,
                type: 'SECURITY',
                title: 'SEC-SECRET-45: RSA Private Key Block Exposure',
                severity: 'CRITICAL',
                category: "Cryptographic Keys",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern45),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching RSA Private Key Block Exposure signature: Plaintext RSA Private Key block committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-45: RSA Private Key Block Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-46: OpenSSH Private Key Block Exposure
    const pattern46 = /-----BEGIN OPENSSH PRIVATE KEY-----/i;
    if (pattern46.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern46.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5046,
                type: 'SECURITY',
                title: 'SEC-SECRET-46: OpenSSH Private Key Block Exposure',
                severity: 'CRITICAL',
                category: "Cryptographic Keys",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern46),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching OpenSSH Private Key Block Exposure signature: Plaintext OpenSSH Private Key block exposed in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-46: OpenSSH Private Key Block Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-47: EC Private Key Block Exposure
    const pattern47 = /-----BEGIN EC PRIVATE KEY-----/i;
    if (pattern47.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern47.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5047,
                type: 'SECURITY',
                title: 'SEC-SECRET-47: EC Private Key Block Exposure',
                severity: 'CRITICAL',
                category: "Cryptographic Keys",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern47),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching EC Private Key Block Exposure signature: Plaintext EC Private Key block committed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-47: EC Private Key Block Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-48: PGP Private Key Block Exposure
    const pattern48 = /-----BEGIN PGP PRIVATE KEY BLOCK-----/i;
    if (pattern48.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern48.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5048,
                type: 'SECURITY',
                title: 'SEC-SECRET-48: PGP Private Key Block Exposure',
                severity: 'CRITICAL',
                category: "Cryptographic Keys",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern48),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching PGP Private Key Block Exposure signature: Plaintext PGP Private Key block committed in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-48: PGP Private Key Block Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-49: Generic Private Key Block Exposure
    const pattern49 = /-----BEGIN PRIVATE KEY-----/i;
    if (pattern49.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern49.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5049,
                type: 'SECURITY',
                title: 'SEC-SECRET-49: Generic Private Key Block Exposure',
                severity: 'CRITICAL',
                category: "Cryptographic Keys",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern49),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Generic Private Key Block Exposure signature: Generic PEM Private Key block exposed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-49: Generic Private Key Block Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-50: Postman API Access Key Exposure
    const pattern50 = /\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b/i;
    if (pattern50.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern50.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5050,
                type: 'SECURITY',
                title: 'SEC-SECRET-50: Postman API Access Key Exposure',
                severity: 'CRITICAL',
                category: "Developer Tooling",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern50),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Postman API Access Key Exposure signature: Postman API Key (PMAK-...) committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-50: Postman API Access Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-51: PlanetScale Database Password
    const pattern51 = /\bpscale_pw_[a-zA-Z0-9_-]{32,}\b/i;
    if (pattern51.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern51.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5051,
                type: 'SECURITY',
                title: 'SEC-SECRET-51: PlanetScale Database Password',
                severity: 'CRITICAL',
                category: "Database Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern51),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching PlanetScale Database Password signature: PlanetScale database token or password in source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-51: PlanetScale Database Password detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-52: Neon Database Connection Secret
    const pattern52 = /postgres:\/\/[^:]+:[^@]+@ep-[a-z0-9-]+\.[a-z0-9-]+\.neon\.tech/i;
    if (pattern52.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern52.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5052,
                type: 'SECURITY',
                title: 'SEC-SECRET-52: Neon Database Connection Secret',
                severity: 'CRITICAL',
                category: "Database Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern52),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Neon Database Connection Secret signature: Neon serverless Postgres connection string with password in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-52: Neon Database Connection Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-53: Upstash Redis REST Token
    const pattern53 = /upstash_token\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern53.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern53.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5053,
                type: 'SECURITY',
                title: 'SEC-SECRET-53: Upstash Redis REST Token',
                severity: 'CRITICAL',
                category: "Database Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern53),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Upstash Redis REST Token signature: Upstash Redis REST API token exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-53: Upstash Redis REST Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-54: Pinecone Vector DB API Key
    const pattern54 = /pinecone_api_key\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern54.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern54.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5054,
                type: 'SECURITY',
                title: 'SEC-SECRET-54: Pinecone Vector DB API Key',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern54),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Pinecone Vector DB API Key signature: Pinecone vector database API key exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-54: Pinecone Vector DB API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-55: Weaviate Cloud API Key
    const pattern55 = /weaviate_api_key\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern55.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern55.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5055,
                type: 'SECURITY',
                title: 'SEC-SECRET-55: Weaviate Cloud API Key',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern55),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Weaviate Cloud API Key signature: Weaviate Cloud Services API key committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-55: Weaviate Cloud API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-56: Qdrant Vector Database API Key
    const pattern56 = /qdrant_api_key\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern56.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern56.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5056,
                type: 'SECURITY',
                title: 'SEC-SECRET-56: Qdrant Vector Database API Key',
                severity: 'CRITICAL',
                category: "AI Model Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern56),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Qdrant Vector Database API Key signature: Qdrant cloud API key exposed in configuration."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-56: Qdrant Vector Database API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-57: LaunchDarkly SDK Key Exposure
    const pattern57 = /launchdarkly_sdk_key\s*=\s*["\']sdk-[a-f0-9-]{36}["\']/i;
    if (pattern57.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern57.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5057,
                type: 'SECURITY',
                title: 'SEC-SECRET-57: LaunchDarkly SDK Key Exposure',
                severity: 'CRITICAL',
                category: "Feature Flag SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern57),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching LaunchDarkly SDK Key Exposure signature: LaunchDarkly server SDK key committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-57: LaunchDarkly SDK Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-58: Segment Write Key Exposure
    const pattern58 = /segment_write_key\s*=\s*["\'][a-zA-Z0-9]{32}["\']/i;
    if (pattern58.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern58.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5058,
                type: 'SECURITY',
                title: 'SEC-SECRET-58: Segment Write Key Exposure',
                severity: 'CRITICAL',
                category: "Analytics SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern58),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Segment Write Key Exposure signature: Segment analytics write key exposed in private server files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-58: Segment Write Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-59: Intercom Access Token Exposure
    const pattern59 = /intercom_access_token\s*=\s*["\'][a-zA-Z0-9]{40,}["\']/i;
    if (pattern59.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern59.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5059,
                type: 'SECURITY',
                title: 'SEC-SECRET-59: Intercom Access Token Exposure',
                severity: 'CRITICAL',
                category: "Customer SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern59),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Intercom Access Token Exposure signature: Intercom API access token committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-59: Intercom Access Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-60: Contentful Management Token
    const pattern60 = /contentful_management_token\s*=\s*["\']CFPAT-[a-zA-Z0-9_-]{43}["\']/i;
    if (pattern60.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern60.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5060,
                type: 'SECURITY',
                title: 'SEC-SECRET-60: Contentful Management Token',
                severity: 'CRITICAL',
                category: "CMS SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern60),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Contentful Management Token signature: Contentful Content Management API (CMA) token in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-60: Contentful Management Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-61: Auth0 Management API Client Secret
    const pattern61 = /auth0_client_secret\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern61.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern61.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5061,
                type: 'SECURITY',
                title: 'SEC-SECRET-61: Auth0 Management API Client Secret',
                severity: 'CRITICAL',
                category: "Identity Provider",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern61),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Auth0 Management API Client Secret signature: Auth0 Management API client secret exposed in source."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-61: Auth0 Management API Client Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-62: Okta API Token Exposure
    const pattern62 = /okta_api_token\s*=\s*["\'][a-zA-Z0-9_-]{42}["\']/i;
    if (pattern62.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern62.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5062,
                type: 'SECURITY',
                title: 'SEC-SECRET-62: Okta API Token Exposure',
                severity: 'CRITICAL',
                category: "Identity Provider",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern62),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Okta API Token Exposure signature: Okta administrator API token exposed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-62: Okta API Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-63: Grafana Service Account Token
    const pattern63 = /\bglsa_[a-zA-Z0-9]{32}\b/i;
    if (pattern63.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern63.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5063,
                type: 'SECURITY',
                title: 'SEC-SECRET-63: Grafana Service Account Token',
                severity: 'CRITICAL',
                category: "Monitoring SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern63),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Grafana Service Account Token signature: Grafana service account API token exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-63: Grafana Service Account Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-64: HashiCorp Vault Token Exposure
    const pattern64 = /\bhv[bs]\.[a-zA-Z0-9_-]{24}\b/i;
    if (pattern64.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern64.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5064,
                type: 'SECURITY',
                title: 'SEC-SECRET-64: HashiCorp Vault Token Exposure',
                severity: 'CRITICAL',
                category: "Secret Management",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern64),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching HashiCorp Vault Token Exposure signature: HashiCorp Vault client token (hvb. / hvs.) committed in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-64: HashiCorp Vault Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-65: Docker Hub Personal Access Token
    const pattern65 = /\bdckr_pat_[a-zA-Z0-9_-]{27}\b/i;
    if (pattern65.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern65.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5065,
                type: 'SECURITY',
                title: 'SEC-SECRET-65: Docker Hub Personal Access Token',
                severity: 'CRITICAL',
                category: "Container Registry",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern65),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Docker Hub Personal Access Token signature: Docker Hub PAT (dckr_pat_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-65: Docker Hub Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-66: Kubernetes Service Account Token
    const pattern66 = /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\/token/i;
    if (pattern66.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern66.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5066,
                type: 'SECURITY',
                title: 'SEC-SECRET-66: Kubernetes Service Account Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern66),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Kubernetes Service Account Token signature: Kubernetes bearer token or serviceaccount secret in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-66: Kubernetes Service Account Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-67: HubSpot Private App Access Token
    const pattern67 = /\bpat-na1-[a-z0-9-]{36}\b/i;
    if (pattern67.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern67.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5067,
                type: 'SECURITY',
                title: 'SEC-SECRET-67: HubSpot Private App Access Token',
                severity: 'CRITICAL',
                category: "CRM SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern67),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching HubSpot Private App Access Token signature: HubSpot private app token (pat-na1-...) committed in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-67: HubSpot Private App Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-68: Linear API Access Key Exposure
    const pattern68 = /\blin_api_[a-zA-Z0-9]{40}\b/i;
    if (pattern68.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern68.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5068,
                type: 'SECURITY',
                title: 'SEC-SECRET-68: Linear API Access Key Exposure',
                severity: 'CRITICAL',
                category: "Productivity SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern68),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Linear API Access Key Exposure signature: Linear personal API key (lin_api_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-68: Linear API Access Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-69: Notion Integration Secret Token
    const pattern69 = /\bsecret_[a-zA-Z0-9]{43}\b/i;
    if (pattern69.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern69.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5069,
                type: 'SECURITY',
                title: 'SEC-SECRET-69: Notion Integration Secret Token',
                severity: 'CRITICAL',
                category: "Productivity SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern69),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Notion Integration Secret Token signature: Notion internal integration secret (secret_...) exposed."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-69: Notion Integration Secret Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-70: Asana Personal Access Token
    const pattern70 = /asana_personal_token\s*=\s*["\'][0-9]\/[0-9a-f]{32}["\']/i;
    if (pattern70.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern70.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5070,
                type: 'SECURITY',
                title: 'SEC-SECRET-70: Asana Personal Access Token',
                severity: 'CRITICAL',
                category: "Productivity SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern70),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Asana Personal Access Token signature: Asana personal access token exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-70: Asana Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-71: ClickUp Personal API Key
    const pattern71 = /\bpk_[0-9]+_[a-zA-Z0-9]{32}\b/i;
    if (pattern71.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern71.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5071,
                type: 'SECURITY',
                title: 'SEC-SECRET-71: ClickUp Personal API Key',
                severity: 'CRITICAL',
                category: "Productivity SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern71),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching ClickUp Personal API Key signature: ClickUp personal API token (pk_...) committed to files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-71: ClickUp Personal API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-72: Airtable Personal Access Token
    const pattern72 = /\bpat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}\b/i;
    if (pattern72.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern72.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5072,
                type: 'SECURITY',
                title: 'SEC-SECRET-72: Airtable Personal Access Token',
                severity: 'CRITICAL',
                category: "Database SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern72),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Airtable Personal Access Token signature: Airtable PAT (pat[a-zA-Z0-9]{14}...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-72: Airtable Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-73: Snyk API Token Exposure
    const pattern73 = /snyk_api_token\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern73.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern73.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5073,
                type: 'SECURITY',
                title: 'SEC-SECRET-73: Snyk API Token Exposure',
                severity: 'CRITICAL',
                category: "Security Tooling",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern73),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Snyk API Token Exposure signature: Snyk personal API token exposed in configuration or code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-73: Snyk API Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-74: SonarCloud User Token
    const pattern74 = /sonarcloud_token\s*=\s*["\'][a-f0-9]{40}["\']/i;
    if (pattern74.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern74.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5074,
                type: 'SECURITY',
                title: 'SEC-SECRET-74: SonarCloud User Token',
                severity: 'CRITICAL',
                category: "Security Tooling",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern74),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching SonarCloud User Token signature: SonarCloud project or user token exposed in repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-74: SonarCloud User Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-75: PayPal Live Client Secret
    const pattern75 = /paypal_client_secret\s*=\s*["\'][a-zA-Z0-9_-]{40,}["\']/i;
    if (pattern75.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern75.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5075,
                type: 'SECURITY',
                title: 'SEC-SECRET-75: PayPal Live Client Secret',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern75),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching PayPal Live Client Secret signature: PayPal live client secret exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-75: PayPal Live Client Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-76: Coinbase Commerce API Key
    const pattern76 = /coinbase_commerce_key\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern76.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern76.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5076,
                type: 'SECURITY',
                title: 'SEC-SECRET-76: Coinbase Commerce API Key',
                severity: 'CRITICAL',
                category: "Payment Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern76),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Coinbase Commerce API Key signature: Coinbase Commerce secret API key committed to files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-76: Coinbase Commerce API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-77: Fastly API Token Exposure
    const pattern77 = /fastly_api_token\s*=\s*["\'][a-zA-Z0-9_-]{32}["\']/i;
    if (pattern77.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern77.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5077,
                type: 'SECURITY',
                title: 'SEC-SECRET-77: Fastly API Token Exposure',
                severity: 'CRITICAL',
                category: "CDN Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern77),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Fastly API Token Exposure signature: Fastly purge / admin API token exposed in source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-77: Fastly API Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-78: Fly.io API Access Token
    const pattern78 = /FlyV1\s+[a-zA-Z0-9_-]{43}\b/i;
    if (pattern78.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern78.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5078,
                type: 'SECURITY',
                title: 'SEC-SECRET-78: Fly.io API Access Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern78),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Fly.io API Access Token signature: Fly.io personal access token (FlyV1 ...) in files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-78: Fly.io API Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-79: Render API Access Key
    const pattern79 = /\brnd_[a-zA-Z0-9]{32}\b/i;
    if (pattern79.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern79.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5079,
                type: 'SECURITY',
                title: 'SEC-SECRET-79: Render API Access Key',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern79),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Render API Access Key signature: Render API access key (rnd_...) exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-79: Render API Access Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-80: Railway API Access Token
    const pattern80 = /railway_api_token\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern80.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern80.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5080,
                type: 'SECURITY',
                title: 'SEC-SECRET-80: Railway API Access Token',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern80),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Railway API Access Token signature: Railway deployment API token committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-80: Railway API Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-81: Koyeb API Token Exposure
    const pattern81 = /koyeb_token\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern81.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern81.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5081,
                type: 'SECURITY',
                title: 'SEC-SECRET-81: Koyeb API Token Exposure',
                severity: 'CRITICAL',
                category: "Cloud Infrastructure",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern81),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Koyeb API Token Exposure signature: Koyeb deployment API token exposed in source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-81: Koyeb API Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-82: Supabase Database Direct Password
    const pattern82 = /postgres:\/\/postgres:[^@]+@db\.[a-z0-9]+\.supabase\.co:5432/i;
    if (pattern82.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern82.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5082,
                type: 'SECURITY',
                title: 'SEC-SECRET-82: Supabase Database Direct Password',
                severity: 'CRITICAL',
                category: "Database Credentials",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern82),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Supabase Database Direct Password signature: Supabase postgres direct connection string with raw password."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-82: Supabase Database Direct Password detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-83: Firebase Cloud Messaging Server Key
    const pattern83 = /\bAAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}\b/i;
    if (pattern83.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern83.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5083,
                type: 'SECURITY',
                title: 'SEC-SECRET-83: Firebase Cloud Messaging Server Key',
                severity: 'CRITICAL',
                category: "Push Notifications",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern83),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Firebase Cloud Messaging Server Key signature: Firebase legacy FCM server key exposed in client code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-83: Firebase Cloud Messaging Server Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-84: OneSignal REST API Key
    const pattern84 = /onesignal_api_key\s*=\s*["\'][a-zA-Z0-9]{48}["\']/i;
    if (pattern84.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern84.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5084,
                type: 'SECURITY',
                title: 'SEC-SECRET-84: OneSignal REST API Key',
                severity: 'CRITICAL',
                category: "Push Notifications",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern84),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching OneSignal REST API Key signature: OneSignal App REST API key committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-84: OneSignal REST API Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-85: Mixpanel Project Secret Key
    const pattern85 = /mixpanel_project_secret\s*=\s*["\'][a-f0-9]{32}["\']/i;
    if (pattern85.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern85.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5085,
                type: 'SECURITY',
                title: 'SEC-SECRET-85: Mixpanel Project Secret Key',
                severity: 'CRITICAL',
                category: "Analytics SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern85),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Mixpanel Project Secret Key signature: Mixpanel project secret exposed in client application."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-85: Mixpanel Project Secret Key detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-86: Amplitude Secret Key Exposure
    const pattern86 = /amplitude_secret_key\s*=\s*["\'][a-f0-9]{32}["\']/i;
    if (pattern86.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern86.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5086,
                type: 'SECURITY',
                title: 'SEC-SECRET-86: Amplitude Secret Key Exposure',
                severity: 'CRITICAL',
                category: "Analytics SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern86),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Amplitude Secret Key Exposure signature: Amplitude secret key committed into source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-86: Amplitude Secret Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-87: Customer.io API Key Exposure
    const pattern87 = /customerio_api_key\s*=\s*["\'][a-f0-9]{32}["\']/i;
    if (pattern87.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern87.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5087,
                type: 'SECURITY',
                title: 'SEC-SECRET-87: Customer.io API Key Exposure',
                severity: 'CRITICAL',
                category: "Marketing SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern87),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Customer.io API Key Exposure signature: Customer.io App API key exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-87: Customer.io API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-88: Braze Rest API Key Exposure
    const pattern88 = /braze_api_key\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern88.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern88.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5088,
                type: 'SECURITY',
                title: 'SEC-SECRET-88: Braze Rest API Key Exposure',
                severity: 'CRITICAL',
                category: "Marketing SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern88),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Braze Rest API Key Exposure signature: Braze REST API key committed in configuration files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-88: Braze Rest API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-89: Zendesk API Access Token
    const pattern89 = /zendesk_token\s*=\s*["\'][a-zA-Z0-9_-]{40}["\']/i;
    if (pattern89.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern89.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5089,
                type: 'SECURITY',
                title: 'SEC-SECRET-89: Zendesk API Access Token',
                severity: 'CRITICAL',
                category: "Customer SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern89),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Zendesk API Access Token signature: Zendesk agent API token exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-89: Zendesk API Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-90: Freshdesk API Key Exposure
    const pattern90 = /freshdesk_api_key\s*=\s*["\'][a-zA-Z0-9_-]{20}["\']/i;
    if (pattern90.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern90.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5090,
                type: 'SECURITY',
                title: 'SEC-SECRET-90: Freshdesk API Key Exposure',
                severity: 'CRITICAL',
                category: "Customer SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern90),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Freshdesk API Key Exposure signature: Freshdesk helpdesk API key committed to repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-90: Freshdesk API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-91: Intercom Webhook Secret
    const pattern91 = /intercom_webhook_secret\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    if (pattern91.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern91.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5091,
                type: 'SECURITY',
                title: 'SEC-SECRET-91: Intercom Webhook Secret',
                severity: 'CRITICAL',
                category: "Customer SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern91),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Intercom Webhook Secret signature: Intercom webhook signing secret exposed in code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-91: Intercom Webhook Secret detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-92: GitGuardian API Key Exposure
    const pattern92 = /gitguardian_api_key\s*=\s*["\'][a-zA-Z0-9_-]{40}["\']/i;
    if (pattern92.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern92.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5092,
                type: 'SECURITY',
                title: 'SEC-SECRET-92: GitGuardian API Key Exposure',
                severity: 'CRITICAL',
                category: "Security Tooling",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern92),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching GitGuardian API Key Exposure signature: GitGuardian personal API key exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-92: GitGuardian API Key Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-93: Checkov Bridgecrew API Token
    const pattern93 = /bridgecrew_api_token\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern93.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern93.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5093,
                type: 'SECURITY',
                title: 'SEC-SECRET-93: Checkov Bridgecrew API Token',
                severity: 'CRITICAL',
                category: "Security Tooling",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern93),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Checkov Bridgecrew API Token signature: Bridgecrew / Checkov API token committed to files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-93: Checkov Bridgecrew API Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-94: CircleCI Personal Access Token
    const pattern94 = /circleci_token\s*=\s*["\'][a-f0-9]{40}["\']/i;
    if (pattern94.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern94.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5094,
                type: 'SECURITY',
                title: 'SEC-SECRET-94: CircleCI Personal Access Token',
                severity: 'CRITICAL',
                category: "CI/CD Platform",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern94),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching CircleCI Personal Access Token signature: CircleCI personal access token exposed in repository."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-94: CircleCI Personal Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-95: Travis CI API Access Token
    const pattern95 = /travis_api_token\s*=\s*["\'][a-zA-Z0-9]{22}["\']/i;
    if (pattern95.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern95.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5095,
                type: 'SECURITY',
                title: 'SEC-SECRET-95: Travis CI API Access Token',
                severity: 'CRITICAL',
                category: "CI/CD Platform",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern95),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Travis CI API Access Token signature: Travis CI authentication token committed to files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-95: Travis CI API Access Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-96: Semaphore CI Auth Token
    const pattern96 = /semaphore_token\s*=\s*["\'][a-zA-Z0-9]{32}["\']/i;
    if (pattern96.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern96.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5096,
                type: 'SECURITY',
                title: 'SEC-SECRET-96: Semaphore CI Auth Token',
                severity: 'CRITICAL',
                category: "CI/CD Platform",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern96),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Semaphore CI Auth Token signature: Semaphore CI access token exposed in source files."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-96: Semaphore CI Auth Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-97: Codecov Upload Token Exposure
    const pattern97 = /codecov_token\s*=\s*["\'][a-f0-9-]{36}["\']/i;
    if (pattern97.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern97.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5097,
                type: 'SECURITY',
                title: 'SEC-SECRET-97: Codecov Upload Token Exposure',
                severity: 'CRITICAL',
                category: "Testing SaaS",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern97),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Codecov Upload Token Exposure signature: Codecov repository upload token committed to repo."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-97: Codecov Upload Token Exposure detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-98: SonarQube Authentication Token
    const pattern98 = /sonarqube_token\s*=\s*["\'][a-f0-9]{40}["\']/i;
    if (pattern98.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern98.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5098,
                type: 'SECURITY',
                title: 'SEC-SECRET-98: SonarQube Authentication Token',
                severity: 'CRITICAL',
                category: "Code Quality",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern98),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching SonarQube Authentication Token signature: SonarQube analysis token committed into source code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-98: SonarQube Authentication Token detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-99: JWT Hardcoded Secret Key Constant
    const pattern99 = /const\s+JWT_SECRET\s*=\s*["\'][a-zA-Z0-9!@#$%^&*()_+=-]{8,}["\']/i;
    if (pattern99.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern99.test(l) && !isDummyPlaceholder(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5099,
                type: 'SECURITY',
                title: 'SEC-SECRET-99: JWT Hardcoded Secret Key Constant',
                severity: 'CRITICAL',
                category: "Authentication",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern99),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching JWT Hardcoded Secret Key Constant signature: Hardcoded JWT signing secret string in application code."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-99: JWT Hardcoded Secret Key Constant detected (${file.path}:${lineNum})`);
        }
    }
    // SEC-SECRET-100: Generic High-Entropy Hex/Base64 API Key
    const pattern100 = /(?:api_secret|app_secret|secret_key)\s*=\s*["\'][a-zA-Z0-9_-]{32,}["\']/i;
    // Generic names carry no vendor prefix, so require a random-looking value: mixed letters + digits,
    // Shannon entropy >= 3.5 bits/char, and none of the dev-default / template wording
    const isRandomSecretValue = (line: string): boolean => {
        const value = /["']([a-zA-Z0-9_-]{32,})["']/.exec(line)?.[1] ?? '';
        if (!/[a-zA-Z]/.test(value) || !/\d/.test(value)) return false;
        if (/insecure|change|your|replace|example|sample|secret|default|development|local/i.test(value)) return false;
        const freq = new Map<string, number>();
        for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
        let bits = 0;
        for (const n of freq.values()) bits -= (n / value.length) * Math.log2(n / value.length);
        return bits >= 3.5;
    };
    const isTemplateFile = /\.(?:example|sample|template|dist)(?:\.[a-z]+)?$/.test(lowerPath);
    if (!isTemplateFile && pattern100.test(contentToScan)) {
        const matchLineIdx = lines.findIndex(l => pattern100.test(l) && !isDummyPlaceholder(l) && isRandomSecretValue(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `secret-${Date.now()}-${findingCounter.count++}`,
                ruleId: 5100,
                type: 'SECURITY',
                title: 'SEC-SECRET-100: Generic High-Entropy Hex/Base64 API Key',
                severity: 'CRITICAL',
                category: "Secret Isolation",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: maskSecretInLine(lines[matchLineIdx] || "[REDACTED_SECRET]", pattern100),
                reproductionSteps: [
                    `Scanned source code at ${file.path}:${lineNum}.`,
                    "Detected unredacted secret token matching Generic High-Entropy Hex/Base64 API Key signature: High-entropy 32-64 character secret token in variable."
                ],
                remediationPrompt: "Revoke exposed credential immediately. Move token into server-side environment variables and verify .gitignore prevents re-committing.",
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-SECRET-100: Generic High-Entropy Hex/Base64 API Key detected (${file.path}:${lineNum})`);
        }
    }
    return { findings, logs };
}
