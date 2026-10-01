/**
 * Zelsis Master evaluateZeroTrustRules Engine (55 Rules)
 * Rules ZERO-AUTH-01 to ZERO-AUTH-55 (Rule IDs 8101 to 8155).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { RATE_LIMIT_GUARD, SERVER_HANDLER, WEBHOOK_VERIFY, isOutboundWebhookSender } from './shared/stack-signals';
import { locateMatchLine } from './shared/locate';
export interface ZeroTrustRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateZeroTrustRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ZeroTrustRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // ZERO-AUTH-01: Missing Mutual TLS (mTLS) in Service-to-Service Communication
    if (/internalServiceFetch|callPaymentGatewayInternal/i.test(cleanContent) && /http:\/\/(?:10\.|192\.168\.|service-)/i.test(cleanContent) && !/https:\/\/|cert|agent: httpsAgent/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/internalServiceFetch|callPaymentGatewayInternal/i, /http:\/\/(?:10\.|192\.168\.|service-)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8101,
            type: 'SECURITY',
            title: "ZERO-AUTH-01: Missing Mutual TLS (mTLS) in Service-to-Service Communication",
            severity: 'HIGH',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Mutual TLS (mTLS) in Service-to-Service Communication: Internal microservices communicating over plaintext HTTP or standard TLS without bidirectional client certificate validation."
            ],
            remediationPrompt: "Enable strict mTLS on all inter-service endpoints with client certificate verification.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-01 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-02: Excessive JWT Token Expiration Lifespan (>1 Hour)
    if (/jwt\.sign\s*\([\s\S]*?expiresIn:\s*["\'](?:[2-9]\d{1,}d|[1-9]\d{2,}d|[2-9]\d{1,}h|[1-9]\d{2,}h|30d|60d|90d|365d)["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/jwt\.sign\s*\([\s\S]*?expiresIn:\s*["\'](?:[2-9]\d{1,}d|[1-9]\d{2,}d|[2-9]\d{1,}h|[1-9]\d{2,}h|30d|60d|90d|365d)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8102,
            type: 'SECURITY',
            title: "ZERO-AUTH-02: Excessive JWT Token Expiration Lifespan (>1 Hour)",
            severity: 'HIGH',
            category: "Token Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Excessive JWT Token Expiration Lifespan (>1 Hour): Issuing access tokens with expiration lifespans of days or weeks without refresh token rotation."
            ],
            remediationPrompt: "Shorten JWT access token expiration to 15 minutes and implement refresh token rotation.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-02 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-03: Cryptographic Timing Attack in Token & Signature Verification
    if (/(?:userProvidedToken|apiToken|webhookSignature)\s*===\s*(?:expectedToken|secretHash|actualSignature)/i.test(cleanContent) && !/timingSafeEqual/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:userProvidedToken|apiToken|webhookSignature)\s*===\s*(?:expectedToken|secretHash|actualSignature)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8103,
            type: 'SECURITY',
            title: "ZERO-AUTH-03: Cryptographic Timing Attack in Token & Signature Verification",
            severity: 'HIGH',
            category: "Cryptographic Failures",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Cryptographic Timing Attack in Token & Signature Verification: Comparing authentication tokens, HMAC signatures, or password hashes using standard equality operators (=== / ==)."
            ],
            remediationPrompt: "Replace standard equality operators with crypto.timingSafeEqual for all secret and token comparisons.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-03 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-04: Hardcoded Authentication Bypass Headers (x-bypass-auth)
    if (/req\.headers\.get\s*\(\s*["\']x-bypass-auth["\']\s*\)|headers\[["\']x-bypass-auth["\']\]/i.test(cleanContent) && !/NODE_ENV === ["\']test["\']/i.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/req\.headers\.get\s*\(\s*["\']x-bypass-auth["\']\s*\)|headers\[["\']x-bypass-auth["\']\]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8104,
            type: 'SECURITY',
            title: "ZERO-AUTH-04: Hardcoded Authentication Bypass Headers (x-bypass-auth)",
            severity: 'CRITICAL',
            category: "Backdoors & Auth",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Hardcoded Authentication Bypass Headers (x-bypass-auth): Leaving development backdoor headers (e.g. x-bypass-auth: true, x-dev-admin) active in production middleware."
            ],
            remediationPrompt: "Remove all x-bypass-auth and test header overrides from middleware and route guards.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-04 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-05: Broken Object Property Level Authorization (BOPLA / Mass Assignment)
    if (/(?:prisma\.[a-zA-Z0-9_]+\.update|User\.findByIdAndUpdate)\s*\(\s*\{[\s\S]*?data:\s*req\.body\b/i.test(cleanContent) && !/pick|whitelist|schema\.parse/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:prisma\.[a-zA-Z0-9_]+\.update|User\.findByIdAndUpdate)\s*\(\s*\{[\s\S]*?data:\s*req\.body\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8105,
            type: 'SECURITY',
            title: "ZERO-AUTH-05: Broken Object Property Level Authorization (BOPLA / Mass Assignment)",
            severity: 'HIGH',
            category: "Authorization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Broken Object Property Level Authorization (BOPLA / Mass Assignment): Passing raw request bodies directly to ORM update methods without filtering mutable fields, allowing role escalation."
            ],
            remediationPrompt: "Explicitly whitelist allowed update fields with Zod; never pass req.body directly to database update calls.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-05 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-06: Missing Refresh Token Rotation and Replay Detection
    if (/handleRefreshTokenReuse/i.test(cleanContent) && !/revokeTokenFamily|deleteMany/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/handleRefreshTokenReuse/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8106,
            type: 'SECURITY',
            title: "ZERO-AUTH-06: Missing Refresh Token Rotation and Replay Detection",
            severity: 'HIGH',
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Refresh Token Rotation and Replay Detection: Reusing refresh tokens without invalidating previous tokens or failing to revoke token families upon reuse detection."
            ],
            remediationPrompt: "Implement refresh token rotation and immediately revoke the token family if an old token is reused.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-06 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-07: Plaintext API Secret Keys Stored in Database
    if (/(?:prisma\.[a-zA-Z0-9_]+\.create|db\.insert)\s*\(\s*\{[\s\S]*?apiKey:\s*rawKey\b/i.test(cleanContent) && !/sha256|hashApiKey|bcrypt/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:prisma\.[a-zA-Z0-9_]+\.create|db\.insert)\s*\(\s*\{[\s\S]*?apiKey:\s*rawKey\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8107,
            type: 'SECURITY',
            title: "ZERO-AUTH-07: Plaintext API Secret Keys Stored in Database",
            severity: 'CRITICAL',
            category: "Credential Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Plaintext API Secret Keys Stored in Database: Storing user API tokens or webhook secrets in plaintext database columns without one-way hashing."
            ],
            remediationPrompt: "Hash API keys with SHA-256 before saving to the database, displaying raw keys only once upon generation.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-07 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-08: Lack of Step-Up Multi-Factor Authentication for Sensitive Actions
    if (/app\/api\/(?:v\d+\/)?user\/(?:disable-mfa|change-password|delete-account)\/route\.(?:ts|js)$/i.test(file.path) && !/verifyPassword|verifyTotp|stepUpAuth/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/zero-auth-08|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8108,
            type: 'SECURITY',
            title: "ZERO-AUTH-08: Lack of Step-Up Multi-Factor Authentication for Sensitive Actions",
            severity: 'HIGH',
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Step-Up Multi-Factor Authentication for Sensitive Actions: Allowing destructive actions (password change, 2FA disable, billing modifications) without re-authenticating user."
            ],
            remediationPrompt: "Require recent password confirmation or 2FA token verification before allowing critical account changes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-08 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-09: Session Fixation Vulnerability on Login State Transition
    if (!lowerPath.endsWith('.tsx') && !lowerPath.endsWith('.jsx') && /handleLoginSuccess/i.test(cleanContent) && !/regenerateSession|destroyOldSession/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/handleLoginSuccess/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8109,
            type: 'SECURITY',
            title: "ZERO-AUTH-09: Session Fixation Vulnerability on Login State Transition",
            severity: 'HIGH',
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Session Fixation Vulnerability on Login State Transition: Retaining existing unauthenticated session identifier after user completes successful login."
            ],
            remediationPrompt: "Regenerate session identifiers upon user login and purge old session tokens from storage.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-09 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-10: Missing Rate Limiting on Authentication & Token Exchange Routes
    if (/app\/api\/(?:v\d+\/)?(?:auth\/)?(?:login|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|magic-link|otp|verify-otp|token)(?:\/|$|\b).*route\.(?:ts|js)$/i.test(file.path) && /export\s+async\s+function\s+POST/i.test(cleanContent) && !RATE_LIMIT_GUARD.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+async\s+function\s+POST/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8110,
            type: 'SECURITY',
            title: "ZERO-AUTH-10: Missing Rate Limiting on Authentication & Token Exchange Routes",
            severity: 'CRITICAL',
            category: "Brute Force Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Rate Limiting on Authentication & Token Exchange Routes: Login, signup, forgot-password, and OAuth callback routes accessible without IP and identifier throttling."
            ],
            remediationPrompt: "Apply strict rate limiting to all authentication and password reset endpoints.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-10 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-11: Insecure Transmission of Bearer Tokens in URL Query Parameters
    if (/const\s+token\s*=\s*(?:searchParams\.get|req\.query)\s*\(\s*["\'](?:access_token|bearer_token|auth_token)["\']\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+token\s*=\s*(?:searchParams\.get|req\.query)\s*\(\s*["\'](?:access_token|bearer_token|auth_token)["\']\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8111,
            type: 'SECURITY',
            title: "ZERO-AUTH-11: Insecure Transmission of Bearer Tokens in URL Query Parameters",
            severity: 'HIGH',
            category: "Token Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Transmission of Bearer Tokens in URL Query Parameters: Accepting authentication tokens via URL query parameters (?access_token=...), leaking tokens in logs and browser history."
            ],
            remediationPrompt: "Pass authentication tokens exclusively in Authorization headers or HttpOnly cookies, never in URLs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-11 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-12: Missing Device Fingerprint / IP Anomaly Detection on Session Resume
    if (/resumeSessionState/i.test(cleanContent) && !/fingerprint|ipMatch|detectAnomaly/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/resumeSessionState/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8112,
            type: 'SECURITY',
            title: "ZERO-AUTH-12: Missing Device Fingerprint / IP Anomaly Detection on Session Resume",
            severity: 'MEDIUM',
            category: "Session Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Device Fingerprint / IP Anomaly Detection on Session Resume: Permitting session resumption from entirely new geographic countries or device user-agents without challenge."
            ],
            remediationPrompt: "Flag sudden geographic or device shifts in active sessions and trigger step-up verification.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-12 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-13: Permissive CORS Credentials with Wildcard Origins
    if (/["\']?Access-Control-Allow-Credentials["\']?\s*:\s*["\']true["\']/i.test(cleanContent) && /["\']?Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/["\']?Access-Control-Allow-Credentials["\']?\s*:\s*["\']true["\']/i, /["\']?Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8113,
            type: 'SECURITY',
            title: "ZERO-AUTH-13: Permissive CORS Credentials with Wildcard Origins",
            severity: 'CRITICAL',
            category: "Network & CORS",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Permissive CORS Credentials with Wildcard Origins: Configuring Access-Control-Allow-Credentials: true alongside wildcard (*) origins or reflected Origin headers."
            ],
            remediationPrompt: "Restrict Access-Control-Allow-Origin to an explicit whitelist when Access-Control-Allow-Credentials is true.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-13 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-14: Missing Replay Attack Prevention (Nonce / Timestamp) on Webhooks
    if (/verifyWebhookSignature/i.test(cleanContent) && !/timestamp|tolerance|Math\.abs\s*\(\s*Date\.now/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/verifyWebhookSignature/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8114,
            type: 'SECURITY',
            title: "ZERO-AUTH-14: Missing Replay Attack Prevention (Nonce / Timestamp) on Webhooks",
            severity: 'HIGH',
            category: "Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Replay Attack Prevention (Nonce / Timestamp) on Webhooks: Validating webhook signatures without verifying timestamp freshness (e.g. timestamp within 5 minutes)."
            ],
            remediationPrompt: "Validate webhook timestamp headers and reject requests older than 5 minutes to prevent replay attacks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-14 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-15: Over-Scoped Microservice Service Account IAM Permissions
    if (/GRANT\s+ALL\s+PRIVILEGES\s+ON\s+ALL\s+TABLES\s+TO\s+(?:svc_|microservice_)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/GRANT\s+ALL\s+PRIVILEGES\s+ON\s+ALL\s+TABLES\s+TO\s+(?:svc_|microservice_)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8115,
            type: 'SECURITY',
            title: "ZERO-AUTH-15: Over-Scoped Microservice Service Account IAM Permissions",
            severity: 'HIGH',
            category: "Least Privilege",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Over-Scoped Microservice Service Account IAM Permissions: Granting microservices full administrator or wildcard database permissions rather than table-scoped access."
            ],
            remediationPrompt: "Scope microservice database credentials to only the specific tables required for their function.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-15 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-16: Lack of Automated Revocation on Password Reset
    if (/executePasswordReset/i.test(cleanContent) && !/tokenVersion|token_version|revokeSessions/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/executePasswordReset/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8116,
            type: 'SECURITY',
            title: "ZERO-AUTH-16: Lack of Automated Revocation on Password Reset",
            severity: 'HIGH',
            category: "Session Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Automated Revocation on Password Reset: Failing to terminate all active sessions and invalidate outstanding JWTs when a user resets their password."
            ],
            remediationPrompt: "Increment user token version or purge active session tokens upon successful password reset.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-16 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-17: Weak Default Password Policy in User Registration
    if (/password:\s*z\.string\(\)\.min\s*\(\s*[1-5]\s*\)/i.test(cleanContent) && !/test|mock|spec/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/password:\s*z\.string\(\)\.min\s*\(\s*[1-5]\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8117,
            type: 'SECURITY',
            title: "ZERO-AUTH-17: Weak Default Password Policy in User Registration",
            severity: 'MEDIUM',
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Weak Default Password Policy in User Registration: Accepting short (<8 characters) passwords without complexity checks or breached password list screening (HIBP)."
            ],
            remediationPrompt: "Enforce minimum 10-character password length and check against HaveIBeenPwned breached lists.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-17 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-18: Missing Cross-Site Request Forgery (CSRF) Protection on Cookie-Based Auth
    if (/cookies\(\)\.get\s*\(\s*["\']session["\']\s*\)/i.test(cleanContent) && /export\s+async\s+function\s+(?:POST|PUT|DELETE)/i.test(cleanContent) && !/csrf|origin|referer|sec-fetch-site/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/cookies\(\)\.get\s*\(\s*["\']session["\']\s*\)/i, /export\s+async\s+function\s+(?:POST|PUT|DELETE)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8118,
            type: 'SECURITY',
            title: "ZERO-AUTH-18: Missing Cross-Site Request Forgery (CSRF) Protection on Cookie-Based Auth",
            severity: 'HIGH',
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Cross-Site Request Forgery (CSRF) Protection on Cookie-Based Auth: Mutating POST/PUT/DELETE routes using cookie authentication without SameSite=Strict or anti-CSRF tokens."
            ],
            remediationPrompt: "Configure session cookies with SameSite=Lax or Strict and require custom headers on mutating requests.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-18 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-19: Unverified Email Verification Tokens (Missing Expiration / Reusable)
    if (/verifyMagicLinkToken/i.test(cleanContent) && !/deleteToken|isUsed|markedUsed/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/verifyMagicLinkToken/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8119,
            type: 'SECURITY',
            title: "ZERO-AUTH-19: Unverified Email Verification Tokens (Missing Expiration / Reusable)",
            severity: 'HIGH',
            category: "Account Lifecycle",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Email Verification Tokens (Missing Expiration / Reusable): Email confirmation or magic link tokens lacking short expiration (<15 min) or single-use consumption flags."
            ],
            remediationPrompt: "Set a 15-minute expiration on magic link and email verification tokens, and invalidate upon first use.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-19 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-20: Missing OAuth State Parameter (CSRF in OAuth Flow)
    if (/const\s+authUrl\s*=\s*`https:\/\/[^`]*\/oauth\/authorize\?[^`]*client_id=[^`]*`/i.test(cleanContent) && !/state=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+authUrl\s*=\s*`https:\/\/[^`]*\/oauth\/authorize\?[^`]*client_id=[^`]*`/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8120,
            type: 'SECURITY',
            title: "ZERO-AUTH-20: Missing OAuth State Parameter (CSRF in OAuth Flow)",
            severity: 'CRITICAL',
            category: "OAuth & OIDC",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing OAuth State Parameter (CSRF in OAuth Flow): Initiating OAuth 2.0 / OIDC authorization requests without cryptographic state or PKCE challenge parameters."
            ],
            remediationPrompt: "Implement cryptographic state and PKCE challenge verification in all OAuth authorization flows.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-20 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-21: Unrestricted API Key Scope (Full Account Access by Default)
    if (/createApiKey/i.test(cleanContent) && !/allowedScopes|scopes/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/createApiKey/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8121,
            type: 'SECURITY',
            title: "ZERO-AUTH-21: Unrestricted API Key Scope (Full Account Access by Default)",
            severity: 'HIGH',
            category: "API Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unrestricted API Key Scope (Full Account Access by Default): Generated API keys possessing full read/write access across all resources without customizable scopes."
            ],
            remediationPrompt: "Allow users to define granular scopes for API keys and enforce scope checks in route middleware.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-21 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-22: Lack of Constant-Time Password Hash Verification
    if (/(?:storedPasswordHash|user\.passwordHash)\s*===\s*(?:inputHash|hashedAttempt)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:storedPasswordHash|user\.passwordHash)\s*===\s*(?:inputHash|hashedAttempt)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8122,
            type: 'SECURITY',
            title: "ZERO-AUTH-22: Lack of Constant-Time Password Hash Verification",
            severity: 'HIGH',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Constant-Time Password Hash Verification: Comparing password hashes or salts with standard string equality instead of bcrypt.compare or argon2.verify."
            ],
            remediationPrompt: "Verify user passwords using argon2.verify or bcrypt.compare to eliminate timing vulnerabilities.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-22 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-23: Missing Secure Context Requirement on WebAuthn Credentials
    if (/navigator\.credentials\.create\s*\(/i.test(cleanContent) && !/isSecureContext|https:\/\//i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/navigator\.credentials\.create\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8123,
            type: 'SECURITY',
            title: "ZERO-AUTH-23: Missing Secure Context Requirement on WebAuthn Credentials",
            severity: 'HIGH',
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Secure Context Requirement on WebAuthn Credentials: Attempting WebAuthn or passkey registration over unencrypted HTTP or untrusted origins."
            ],
            remediationPrompt: "Enforce HTTPS and validate relying party ID before initiating WebAuthn credential registration.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-23 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-24: Insecure OAuth Redirect URI Matching (Wildcard / Subdomain Match)
    if (/redirectUri\.includes\s*\(\s*["\']example\.com["\']\s*\)|redirectUri\.startsWith\s*\(\s*["\']http/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/redirectUri\.includes\s*\(\s*["\']example\.com["\']\s*\)|redirectUri\.startsWith\s*\(\s*["\']http/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8124,
            type: 'SECURITY',
            title: "ZERO-AUTH-24: Insecure OAuth Redirect URI Matching (Wildcard / Subdomain Match)",
            severity: 'CRITICAL',
            category: "OAuth & OIDC",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure OAuth Redirect URI Matching (Wildcard / Subdomain Match): Matching OAuth redirect_uri parameters using wildcards (*.example.com) or partial substring matches."
            ],
            remediationPrompt: "Use exact string equality to match OAuth redirect URIs; reject wildcards and partial matches.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-24 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-25: Missing Audit Trail for Administrative Privilege Changes
    if (/role:\s*["\']ADMIN["\']/i.test(cleanContent) && !/auditLog|logger\.warn/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/role:\s*["\']ADMIN["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8125,
            type: 'SECURITY',
            title: "ZERO-AUTH-25: Missing Audit Trail for Administrative Privilege Changes",
            severity: 'MEDIUM',
            category: "Governance & Audit",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Audit Trail for Administrative Privilege Changes: Changing user roles to ADMIN or adding team members without generating persistent audit log events."
            ],
            remediationPrompt: "Emit audit log events whenever user roles or organization permissions are modified.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-25 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-26: Default Admin Credentials in Database Seed Scripts
    if (/seed\.(?:ts|js|sql)$/i.test(file.path) && /password:\s*["\'](?:admin|admin123|password|root|123456)["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/password:\s*["\'](?:admin|admin123|password|root|123456)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8126,
            type: 'SECURITY',
            title: "ZERO-AUTH-26: Default Admin Credentials in Database Seed Scripts",
            severity: 'HIGH',
            category: "Credential Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Default Admin Credentials in Database Seed Scripts: Database seeds populating default accounts with predictable credentials (admin / admin123, password)."
            ],
            remediationPrompt: "Remove hardcoded credentials from database seed files; generate cryptographically random initial passwords.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-26 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-27: Missing Certificate Pinning on High-Risk External API Calls
    if (/callCoreBankingApi|connectPciProvider/i.test(cleanContent) && !/checkServerIdentity|fingerprint/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/callCoreBankingApi|connectPciProvider/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8127,
            type: 'SECURITY',
            title: "ZERO-AUTH-27: Missing Certificate Pinning on High-Risk External API Calls",
            severity: 'MEDIUM',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Certificate Pinning on High-Risk External API Calls: Connecting to core banking or identity providers without verifying specific certificate public key pins."
            ],
            remediationPrompt: "Pin public key certificates for critical banking and payment gateway API clients.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-27 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-28: Unencrypted Session Storage in Distributed Cache (Redis)
    if (/redisStore\s*=\s*new\s+RedisStore\s*\(\{[\s\S]*?tls:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/redisStore\s*=\s*new\s+RedisStore\s*\(\{[\s\S]*?tls:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8128,
            type: 'SECURITY',
            title: "ZERO-AUTH-28: Unencrypted Session Storage in Distributed Cache (Redis)",
            severity: 'HIGH',
            category: "Data at Rest",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unencrypted Session Storage in Distributed Cache (Redis): Storing user session payloads in Redis without encryption or TLS in transit."
            ],
            remediationPrompt: "Enable TLS for Redis connections and encrypt sensitive session state before caching.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-28 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-29: Missing Account Lockout after Consecutive Authentication Failures
    if (/handleFailedLoginAttempt/i.test(cleanContent) && !/failedAttempts|isLocked/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/handleFailedLoginAttempt/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8129,
            type: 'SECURITY',
            title: "ZERO-AUTH-29: Missing Account Lockout after Consecutive Authentication Failures",
            severity: 'MEDIUM',
            category: "Brute Force Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Account Lockout after Consecutive Authentication Failures: Allowing unlimited consecutive incorrect password attempts on single user accounts without temporary lock."
            ],
            remediationPrompt: "Implement temporary account locking or progressive backoff after 5 consecutive failed logins.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-29 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-30: Lack of Scope Validation on Service-to-Service JWTs
    if (/verifyInterServiceToken/i.test(cleanContent) && !/audience|aud/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/verifyInterServiceToken/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8130,
            type: 'SECURITY',
            title: "ZERO-AUTH-30: Lack of Scope Validation on Service-to-Service JWTs",
            severity: 'HIGH',
            category: "Microservices Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Scope Validation on Service-to-Service JWTs: Accepting internal service JWTs without verifying that the caller token contains the specific required audience (aud)."
            ],
            remediationPrompt: "Validate audience (aud) and issuer (iss) claims on all inter-service JWT tokens.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-30 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-31: Insecure JWT Storage in Browser LocalStorage
    if (/localStorage\.setItem\s*\(\s*["\'](?:jwt|token|access_token|authToken)["\']\s*,\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && !/test|mock|spec/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/localStorage\.setItem\s*\(\s*["\'](?:jwt|token|access_token|authToken)["\']\s*,\s*[a-zA-Z0-9_]+\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8131,
            type: 'SECURITY',
            title: "ZERO-AUTH-31: Insecure JWT Storage in Browser LocalStorage",
            severity: 'HIGH',
            category: "Client Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure JWT Storage in Browser LocalStorage: Persisting sensitive authentication tokens in window.localStorage where they are vulnerable to XSS theft."
            ],
            remediationPrompt: "Migrate auth tokens from localStorage to Secure, HttpOnly, SameSite cookies to prevent XSS theft.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-31 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-32: Missing Re-Authentication for API Key Generation
    if (/app\/api\/(?:v\d+\/)?api-keys\/generate\/route\.(?:ts|js)$/i.test(file.path) && !/verifyRecentPassword|requireMfaConfirmation/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/zero-auth-32|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8132,
            type: 'SECURITY',
            title: "ZERO-AUTH-32: Missing Re-Authentication for API Key Generation",
            severity: 'MEDIUM',
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Re-Authentication for API Key Generation: Allowing users to generate new API keys or download backup recovery codes without recent password confirmation."
            ],
            remediationPrompt: "Require password confirmation before generating new API keys or exporting credentials.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-32 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-33: Unchecked Client IP Forwarding Header Spoofing
    if (/req\.headers\.get\s*\(\s*["\']x-client-ip["\']\s*\)/i.test(cleanContent) && !/NODE_ENV !== ["\']production["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/req\.headers\.get\s*\(\s*["\']x-client-ip["\']\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8133,
            type: 'SECURITY',
            title: "ZERO-AUTH-33: Unchecked Client IP Forwarding Header Spoofing",
            severity: 'HIGH',
            category: "Network Identity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Client IP Forwarding Header Spoofing: Trusting raw client headers (X-Forwarded-For, X-Real-IP) without validating trusted proxy hops."
            ],
            remediationPrompt: "Configure trusted proxy subnet CIDRs; do not blindly trust raw X-Forwarded-For headers from untrusted clients.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-33 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-34: Missing Strict Algorithm Verification in JWT Decoder
    if (/jwt\.verify\s*\(\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && !/algorithms/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/jwt\.verify\s*\(\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8134,
            type: 'SECURITY',
            title: "ZERO-AUTH-34: Missing Strict Algorithm Verification in JWT Decoder",
            severity: 'CRITICAL',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Strict Algorithm Verification in JWT Decoder: Calling jwt.verify() without specifying an explicit algorithms array (allowing 'none' or HMAC confusion)."
            ],
            remediationPrompt: "Specify explicit algorithms whitelist in jwt.verify options to prevent algorithm confusion attacks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-34 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-35: Lack of Mutual Authentication on WebSocket Handshake
    if (/new\s+WebSocketServer\s*\(\{[\s\S]*?verifyClient:\s*(?:undefined|null|false)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+WebSocketServer\s*\(\{[\s\S]*?verifyClient:\s*(?:undefined|null|false)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8135,
            type: 'SECURITY',
            title: "ZERO-AUTH-35: Lack of Mutual Authentication on WebSocket Handshake",
            severity: 'HIGH',
            category: "Real-Time Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Mutual Authentication on WebSocket Handshake: Upgrading HTTP connections to WebSockets without verifying authentication tickets or session cookies."
            ],
            remediationPrompt: "Verify session tokens or signed tickets during the WebSocket HTTP upgrade handshake.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-35 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-36: Unchecked Authorization on Static Asset Storage URLs
    if (/downloadInvoiceRoute|streamCustomerTaxFile/i.test(cleanContent) && !/getSignedUrl|verifyOwnership/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/downloadInvoiceRoute|streamCustomerTaxFile/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8136,
            type: 'SECURITY',
            title: "ZERO-AUTH-36: Unchecked Authorization on Static Asset Storage URLs",
            severity: 'HIGH',
            category: "Object Storage Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Authorization on Static Asset Storage URLs: Serving private customer invoices, contracts, or exports via permanent, unauthenticated public bucket URLs."
            ],
            remediationPrompt: "Generate short-lived presigned URLs (max 15 min) for all private customer document downloads.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-36 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-37: Missing Session Invalidation on User Account Deactivation
    if (/deactivateUserAccount/i.test(cleanContent) && !/purgeSessions|redis\.del/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/deactivateUserAccount/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8137,
            type: 'SECURITY',
            title: "ZERO-AUTH-37: Missing Session Invalidation on User Account Deactivation",
            severity: 'HIGH',
            category: "Lifecycle Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Session Invalidation on User Account Deactivation: Deactivating or banning a user account without immediately terminating active Redis sessions or revoking tokens."
            ],
            remediationPrompt: "Purge active Redis sessions immediately when a user account is suspended, banned, or deleted.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-37 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-38: Insecure SSO SAML Assertion Validation (Missing Signature / Recipient Check)
    if (/parseSamlResponse/i.test(cleanContent) && !/validateSignature|cert/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/parseSamlResponse/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8138,
            type: 'SECURITY',
            title: "ZERO-AUTH-38: Insecure SSO SAML Assertion Validation (Missing Signature / Recipient Check)",
            severity: 'CRITICAL',
            category: "Federated Identity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure SSO SAML Assertion Validation (Missing Signature / Recipient Check): Parsing SAML assertions without validating XML digital signatures, Recipient URL, or AudienceRestriction."
            ],
            remediationPrompt: "Enforce cryptographic signature and audience restriction validation on all SAML assertions.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-38 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-39: Weak Ephemeral Key Generation for Diffie-Hellman Key Exchange
    if (/crypto\.createDiffieHellman\s*\(\s*(?:512|1024)\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/crypto\.createDiffieHellman\s*\(\s*(?:512|1024)\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8139,
            type: 'SECURITY',
            title: "ZERO-AUTH-39: Weak Ephemeral Key Generation for Diffie-Hellman Key Exchange",
            severity: 'HIGH',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Weak Ephemeral Key Generation for Diffie-Hellman Key Exchange: Using custom low-entropy prime groups (<2048-bit) for ephemeral Diffie-Hellman key exchanges."
            ],
            remediationPrompt: "Use standard Curve25519 or >=2048-bit prime groups for all Diffie-Hellman key exchanges.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-39 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-40: Missing Concurrent Session Limits for Privileged Accounts
    if (/issueAdminSessionToken/i.test(cleanContent) && !/maxConcurrentSessions|activeSessions/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/issueAdminSessionToken/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8140,
            type: 'SECURITY',
            title: "ZERO-AUTH-40: Missing Concurrent Session Limits for Privileged Accounts",
            severity: 'MEDIUM',
            category: "Session Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Concurrent Session Limits for Privileged Accounts: Allowing unlimited simultaneous active logins on enterprise administrator accounts."
            ],
            remediationPrompt: "Enforce a maximum concurrent session cap for admin accounts and terminate older sessions.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-40 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-41: Lack of Token Introspection on OAuth Resource Servers
    if (/validateOpaqueBearerToken/i.test(cleanContent) && !/introspectEndpoint|rfc7662/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/validateOpaqueBearerToken/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8141,
            type: 'SECURITY',
            title: "ZERO-AUTH-41: Lack of Token Introspection on OAuth Resource Servers",
            severity: 'MEDIUM',
            category: "Microservices Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Token Introspection on OAuth Resource Servers: Resource servers accepting opaque access tokens without querying identity provider introspection endpoints."
            ],
            remediationPrompt: "Implement RFC 7662 token introspection to verify opaque access tokens on resource servers.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-41 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-42: Unprotected GraphQL Introspection in Production Environments
    if (/new\s+ApolloServer\s*\(\{[\s\S]*?introspection:\s*true/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+ApolloServer\s*\(\{[\s\S]*?introspection:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8142,
            type: 'SECURITY',
            title: "ZERO-AUTH-42: Unprotected GraphQL Introspection in Production Environments",
            severity: 'LOW',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unprotected GraphQL Introspection in Production Environments: Leaving GraphQL schema introspection queries enabled in production, exposing entire API model definitions."
            ],
            remediationPrompt: "Disable GraphQL schema introspection in production to prevent schema harvesting.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ LOW: ZERO-AUTH-42 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-43: Missing Identity Verification on Webhook Receiver Endpoints
    const isUiComponent = /\.[jt]sx$/i.test(file.path) && !/export\s+(?:async\s+)?function\s+(?:action|POST|PUT|PATCH|DELETE)\b/.test(cleanContent);
    const isWebhookHandler = (/webhook/i.test(file.path) && /\.(?:[cm]?[jt]sx?|py|rb|php)$/i.test(file.path) && !isUiComponent && SERVER_HANDLER.test(cleanContent)) ||
        /\.(?:post|all)\s*\(\s*['"`][^'"`]*webhook/i.test(cleanContent);
    if (isWebhookHandler && !isOutboundWebhookSender(cleanContent) && !(WEBHOOK_VERIFY.test(cleanContent) && /secret|signature/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/zero-auth-43|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8143,
            type: 'SECURITY',
            title: "ZERO-AUTH-43: Missing Identity Verification on Webhook Receiver Endpoints",
            severity: 'CRITICAL',
            category: "API Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Identity Verification on Webhook Receiver Endpoints: Payment or third-party webhook handlers executing database state changes without verifying HMAC signatures."
            ],
            remediationPrompt: "Verify provider HMAC signatures on all webhook endpoints before executing state changes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-43 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-44: Insecure Cross-Origin Resource Sharing on Private API Subnets
    if (/app\/api\/internal\/route\.(?:ts|js)$/i.test(file.path) && /Access-Control-Allow-Origin:\s*["\']\*["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/Access-Control-Allow-Origin:\s*["\']\*["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8144,
            type: 'SECURITY',
            title: "ZERO-AUTH-44: Insecure Cross-Origin Resource Sharing on Private API Subnets",
            severity: 'HIGH',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Cross-Origin Resource Sharing on Private API Subnets: Exposing internal management microservices to browser CORS requests with permissive header configurations."
            ],
            remediationPrompt: "Disable CORS headers on private internal microservices intended solely for backend communication.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-44 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-45: Missing Proof Key for Code Exchange (PKCE) in Public OAuth Clients
    if (/new\s+OAuthClient\s*\(\{[\s\S]*?pkce:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+OAuthClient\s*\(\{[\s\S]*?pkce:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8145,
            type: 'SECURITY',
            title: "ZERO-AUTH-45: Missing Proof Key for Code Exchange (PKCE) in Public OAuth Clients",
            severity: 'HIGH',
            category: "OAuth Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Proof Key for Code Exchange (PKCE) in Public OAuth Clients: Single Page Applications (SPAs) or mobile apps executing OAuth authorization code grant without code_verifier / PKCE."
            ],
            remediationPrompt: "Enforce PKCE with S256 challenge on all browser and mobile OAuth authorization flows.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-45 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-46: Unsalted or Weak Hash Algorithms for Internal Verification Tokens
    if (/crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']\s*\)[\s\S]*?update\s*\(\s*resetToken\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']\s*\)[\s\S]*?update\s*\(\s*resetToken\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8146,
            type: 'SECURITY',
            title: "ZERO-AUTH-46: Unsalted or Weak Hash Algorithms for Internal Verification Tokens",
            severity: 'HIGH',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsalted or Weak Hash Algorithms for Internal Verification Tokens: Hashing password reset or email verification tokens with MD5 or SHA-1 instead of SHA-256."
            ],
            remediationPrompt: "Use SHA-256 or SHA-512 with random salts for hashing verification tokens stored in databases.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-46 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-47: Missing Tenant Boundary Enforcement in Background Queue Workers
    if (/processBackgroundJob\s*\(\s*job\s*\)[\s\S]*?db\.[a-zA-Z0-9_]+\.(?:update|delete|find)/i.test(cleanContent) && !/tenant_id|tenantId/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/processBackgroundJob\s*\(\s*job\s*\)[\s\S]*?db\.[a-zA-Z0-9_]+\.(?:update|delete|find)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8147,
            type: 'SECURITY',
            title: "ZERO-AUTH-47: Missing Tenant Boundary Enforcement in Background Queue Workers",
            severity: 'CRITICAL',
            category: "Multi-Tenancy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Tenant Boundary Enforcement in Background Queue Workers: Background job consumers executing multi-tenant tasks without verifying and scoping tenant context in the worker."
            ],
            remediationPrompt: "Bind background worker database queries strictly to the tenant_id encapsulated in the job payload.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-47 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-48: Lack of User-Agent and IP Logging on High-Privilege API Requests
    if (/app\/api\/admin\/.*\/route\.(?:ts|js)$/i.test(file.path) && !/clientIp|userAgent/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/zero-auth-48|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8148,
            type: 'SECURITY',
            title: "ZERO-AUTH-48: Lack of User-Agent and IP Logging on High-Privilege API Requests",
            severity: 'LOW',
            category: "Auditing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of User-Agent and IP Logging on High-Privilege API Requests: Administrative API mutations executed without recording caller IP, user-agent, and auth method in audit logs."
            ],
            remediationPrompt: "Log client IP, user-agent, and actor ID on all administrative and data-modifying API endpoints.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ LOW: ZERO-AUTH-48 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-49: Unverified Password Reset Token Reuse (Missing State Invalidation)
    if (/applyNewPassword/i.test(cleanContent) && !/markTokenUsed|deleteResetToken/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/applyNewPassword/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8149,
            type: 'SECURITY',
            title: "ZERO-AUTH-49: Unverified Password Reset Token Reuse (Missing State Invalidation)",
            severity: 'HIGH',
            category: "Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Password Reset Token Reuse (Missing State Invalidation): Allowing a password reset token to be submitted multiple times before its expiration timestamp."
            ],
            remediationPrompt: "Invalidate password reset tokens immediately upon successful password change.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-49 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-50: Insecure Ephemeral Token Generation using Math.random()
    if (/const\s+(?:token|nonce|sessionId|secretCode)\s*=\s*(?:Math\.random\(\)\.toString|Date\.now\(\)\.toString\(\s*36\s*\)\s*\+\s*Math\.random)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+(?:token|nonce|sessionId|secretCode)\s*=\s*(?:Math\.random\(\)\.toString|Date\.now\(\)\.toString\(\s*36\s*\)\s*\+\s*Math\.random)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8150,
            type: 'SECURITY',
            title: "ZERO-AUTH-50: Insecure Ephemeral Token Generation using Math.random()",
            severity: 'CRITICAL',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Ephemeral Token Generation using Math.random(): Generating session IDs, verification tokens, or nonces using Math.random() instead of crypto.randomBytes."
            ],
            remediationPrompt: "Replace Math.random() with crypto.randomBytes() or crypto.getRandomValues() for all security tokens.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ CRITICAL: ZERO-AUTH-50 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-51: Missing Origin Header Verification on Mutating HTTP Requests
    if (/app\/api\/mutate\/route\.(?:ts|js)$/i.test(file.path) && !/origin|referer/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/zero-auth-51|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth51-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8151,
            type: 'SECURITY',
            title: "ZERO-AUTH-51: Missing Origin Header Verification on Mutating HTTP Requests",
            severity: 'HIGH',
            category: "CSRF Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-51 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Origin Header Verification on Mutating HTTP Requests: API routes processing state mutations without validating that the Origin or Referer header matches trusted hosts."
            ],
            remediationPrompt: "Verify that request Origin or Referer headers match your domain on all mutating API routes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-51 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-52: Lack of Service Account Key Expiration & Mandatory Rotation
    if (/aws_iam_access_key\b/i.test(cleanContent) && !/rotation|expires/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_iam_access_key\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth52-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8152,
            type: 'SECURITY',
            title: "ZERO-AUTH-52: Lack of Service Account Key Expiration & Mandatory Rotation",
            severity: 'MEDIUM',
            category: "Credential Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-52 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Service Account Key Expiration & Mandatory Rotation: Cloud service account keys (AWS IAM access keys, GCP service account JSON) without rotation policies (>90 days)."
            ],
            remediationPrompt: "Rotate service account keys every 90 days or adopt ephemeral IAM roles and Workload Identity.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-52 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-53: Missing Scoped Permissions on CI/CD Deployment Tokens
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /AWS_ACCESS_KEY_ID:\s*\$\{\{\s*secrets\.ROOT_ACCOUNT_AWS_KEY\s*\}\}/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/AWS_ACCESS_KEY_ID:\s*\$\{\{\s*secrets\.ROOT_ACCOUNT_AWS_KEY\s*\}\}/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth53-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8153,
            type: 'SECURITY',
            title: "ZERO-AUTH-53: Missing Scoped Permissions on CI/CD Deployment Tokens",
            severity: 'HIGH',
            category: "Supply Chain & CI/CD",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-53 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Scoped Permissions on CI/CD Deployment Tokens: Using account-wide administrative tokens in GitHub Actions or GitLab CI instead of repository-scoped tokens."
            ],
            remediationPrompt: "Use short-lived OIDC tokens in CI/CD workflows instead of long-lived administrator API keys.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-53 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-54: Insecure Session Invalidation across Multiple Browser Tabs
    if (/handleClientLogout/i.test(cleanContent) && !/BroadcastChannel|localStorage\.setItem\(["\']logout-event["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/handleClientLogout/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth54-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8154,
            type: 'SECURITY',
            title: "ZERO-AUTH-54: Insecure Session Invalidation across Multiple Browser Tabs",
            severity: 'LOW',
            category: "Client State",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-54 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Session Invalidation across Multiple Browser Tabs: Logging out in one browser tab leaving active authenticated state cached in other open browser tabs."
            ],
            remediationPrompt: "Use BroadcastChannel to synchronize user logout across all active browser tabs instantly.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ LOW: ZERO-AUTH-54 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-55: Missing Authentication Header Validation on Internal Gateway Proxies
    if (/gatewayProxyHandler/i.test(cleanContent) && !/verifyToken|authorization/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/gatewayProxyHandler/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth55-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8155,
            type: 'SECURITY',
            title: "ZERO-AUTH-55: Missing Authentication Header Validation on Internal Gateway Proxies",
            severity: 'HIGH',
            category: "API Gateway",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected ZERO-AUTH-55 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Authentication Header Validation on Internal Gateway Proxies: Reverse proxy forwarding unauthenticated requests to internal microservices assuming private network safety."
            ],
            remediationPrompt: "Enforce token verification at the API gateway before forwarding requests to internal services.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-55 finding in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
