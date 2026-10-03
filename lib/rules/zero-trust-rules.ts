/**
 * Zelsis Master evaluateZeroTrustRules Engine (55 Rules)
 * Rules ZERO-AUTH-01 to ZERO-AUTH-55 (Rule IDs 8101 to 8155).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { RATE_LIMIT_GUARD, REQUEST_BODY, SERVER_HANDLER, WEBHOOK_VERIFY, isOutboundWebhookSender } from './shared/stack-signals';
import { locateMatchLine } from './shared/locate';
/** HMAC / signature compared with a plain equality operator (timing side channel). */
const SIGNATURE_PLAIN_EQ = /\b\w*(?:signature|hmac|digest)\w*\s*(?:===|!==)\s*\w*(?:signature|hmac|digest|expected|computed)\w*\b(?!\s*[.(\[])/i;
/** express-session login that stores the user on the pre-login session id. */
const SESSION_LOGIN_ASSIGN = /\breq\.session\.(?:userId|user_id|user|uid|accountId|account|isLoggedIn|loggedIn|authenticated)\s*=(?!=)/;
const PASSWORD_CHECK = /bcrypt\w*\.compare|argon2\.verify|verifyPassword|comparePassword|checkPassword|scrypt/i;
/** Bearer / access token read from the URL query string. */
const TOKEN_FROM_QUERY = /const\s+\w*token\s*=\s*(?:[\w.]*searchParams\.get\s*\(\s*["'](?:access_token|bearer_token|auth_token)["']\s*\)|req\.query\.(?:access_token|bearer_token|auth_token)\b|req\.query\s*\[\s*["'](?:access_token|bearer_token|auth_token)["']\s*\])/i;
/** Stored password (hash) compared with ===, or a plaintext password column. */
const PASSWORD_PLAIN_EQ = /\b(?:user|account|existingUser|dbUser|foundUser|admin|member)\??\.(?:password|passwordHash|password_hash|hashedPassword)\s*(?:===|!==|==|!=)\s*(?!null\b|undefined\b|['"`])(?![\w.]*confirm)[\w.]+|\b(?:storedPasswordHash)\s*===\s*(?:inputHash|hashedAttempt)\b/i;
/** Session cookie read in a route handler (sync or Next 15 async cookies()). */
const SESSION_COOKIE_READ = /(?:cookies\(\)|\(\s*await\s+cookies\(\)\s*\)|cookieStore)\.get\s*\(\s*["']session["']\s*\)/i;
/** Short-lived secret derived from Math.random(). */
const MATH_RANDOM_TOKEN = /const\s+(?:\w*token|\w*Token|nonce|sessionId|secretCode|\w*[sS]ecret|otp|otpCode|verificationCode|inviteCode|resetCode|apiKey)\s*=\s*(?:Math\.random\(\)\.toString|Date\.now\(\)\.toString\(\s*36\s*\)\s*\+\s*Math\.random|Math\.floor\s*\(\s*\d+\s*\+\s*Math\.random\(\))/;
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
    // ZERO-AUTH-02: Excessive JWT Token Expiration Lifespan (>1 Hour)
    // Access-token jwt.sign() whose own options give it a lifetime of 7+ days; refresh tokens are expected to live long and are skipped
    const idx_8102 = (() => {
        const toHours = (v: string): number => {
            const m = /^(\d+)\s*(h|d|w|y)$/i.exec(v.trim());
            if (!m) return 0;
            return Number(m[1]) * ({ h: 1, d: 24, w: 168, y: 8760 } as Record<string, number>)[m[2].toLowerCase()];
        };
        for (const m of cleanContent.matchAll(/\bjwt\.sign\s*\(/g)) {
            let depth = 1;
            let i = m.index! + m[0].length;
            while (i < cleanContent.length && depth > 0) {
                if (cleanContent[i] === '(') depth++;
                else if (cleanContent[i] === ')') depth--;
                i++;
            }
            const call = cleanContent.slice(m.index!, i);
            if (/refresh/i.test(call) || /refresh\w*\s*=\s*(?:await\s+)?$/i.test(cleanContent.slice(Math.max(0, m.index! - 40), m.index!))) continue;
            const exp = /expiresIn\s*:\s*["'`]([^"'`]+)["'`]/.exec(call);
            if (exp && toHours(exp[1]) >= 168) return cleanContent.slice(0, m.index! + exp.index).split('\n').length - 1;
        }
        return -1;
    })();
    if (idx_8102 !== -1) {
        const matchLineIdx = idx_8102;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8102,
            type: 'SECURITY',
            title: "ZERO-AUTH-02: Excessive JWT Token Expiration Lifespan (>1 Hour)",
            severity: 'MEDIUM',
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
        logs.push(`[${ts}] 🛡️ MEDIUM: ZERO-AUTH-02 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-03: Cryptographic Timing Attack in Token & Signature Verification
    if (/(?:userProvidedToken|apiToken|webhookSignature)\s*===\s*(?:expectedToken|secretHash|actualSignature)|createHmac|\.digest\(/i.test(cleanContent) && SIGNATURE_PLAIN_EQ.test(cleanContent) && !/timingSafeEqual|safeCompare|constantTime/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [SIGNATURE_PLAIN_EQ], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8103,
            type: 'SECURITY',
            title: "ZERO-AUTH-03: Cryptographic Timing Attack in Token & Signature Verification",
            severity: 'MEDIUM',
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
    if (/(?:req|request)\.headers\.get\s*\(\s*["\']x-bypass-auth["\']\s*\)|headers\[["\']x-bypass-auth["\']\]/i.test(cleanContent) && !/NODE_ENV === ["\']test["\']/i.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:req|request)\.headers\.get\s*\(\s*["\']x-bypass-auth["\']\s*\)|headers\[["\']x-bypass-auth["\']\]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (/(?:prisma\.[a-zA-Z0-9_]+\.update|User\.findByIdAndUpdate)\s*\(\s*\{[^;]{0,200}?data:\s*req\.body\b/i.test(cleanContent) && !/pick|whitelist|schema\.parse/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/data:\s*req\.body\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // ZERO-AUTH-09: Session Fixation Vulnerability on Login State Transition
    if (!lowerPath.endsWith('.tsx') && !lowerPath.endsWith('.jsx') && (/handleLoginSuccess/i.test(cleanContent) || (SESSION_LOGIN_ASSIGN.test(cleanContent) && PASSWORD_CHECK.test(cleanContent))) && !/regenerateSession|destroyOldSession|session\.regenerate\s*\(/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [SESSION_LOGIN_ASSIGN, /handleLoginSuccess/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (TOKEN_FROM_QUERY.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [TOKEN_FROM_QUERY], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // ZERO-AUTH-13: Permissive CORS Credentials with Wildcard Origins
    if (/["\']?Access-Control-Allow-Credentials["\']?\s*:\s*["\']true["\']/i.test(cleanContent) && /["\']?Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/["\']?Access-Control-Allow-Credentials["\']?\s*:\s*["\']true["\']/i, /["\']?Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8113,
            type: 'SECURITY',
            title: "ZERO-AUTH-13: Permissive CORS Credentials with Wildcard Origins",
            severity: 'MEDIUM',
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
    // ZERO-AUTH-17: Weak Default Password Policy in User Registration
    // Only sign-up / registration schemas: on a login form .min(1) is just the "required" check
    const weakSignupPassword = /^\s*["']?password["']?\s*:\s*z\.string\(\)(?:\.\w+\([^)]*\))*?\.min\s*\(\s*[1-7]\s*[,)]/;
    const idx_8117 = /test|mock|spec/i.test(lowerPath) ? -1 : lines.findIndex((l, i) => weakSignupPassword.test(l) &&
        (/sign-?up|register|registration|create-account/i.test(lowerPath) || /(?:sign_?up|register|registration|createAccount|createUser)\w*\s*=\s*z\.object/i.test(lines.slice(Math.max(0, i - 6), i + 1).join('\n'))));
    if (idx_8117 !== -1) {
        const matchLineIdx = idx_8117;
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
    if (SESSION_COOKIE_READ.test(cleanContent) && /export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)/i.test(cleanContent) && !/csrf|origin|referer|sec-fetch-site/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8118,
            type: 'SECURITY',
            title: "ZERO-AUTH-18: Missing Cross-Site Request Forgery (CSRF) Protection on Cookie-Based Auth",
            severity: 'MEDIUM',
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
    // ZERO-AUTH-20: Missing OAuth State Parameter (CSRF in OAuth Flow)
    if (/const\s+\w+\s*=\s*`https:\/\/[^`]*\/oauth2?\/(?:v\d+\/)?authorize\?[^`]*client_id=[^`]*`/i.test(cleanContent) && !/state=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+\w+\s*=\s*`https:\/\/[^`]*\/oauth2?\/(?:v\d+\/)?authorize\?[^`]*client_id=[^`]*`/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8120,
            type: 'SECURITY',
            title: "ZERO-AUTH-20: Missing OAuth State Parameter (CSRF in OAuth Flow)",
            severity: 'HIGH',
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
    // ZERO-AUTH-22: Lack of Constant-Time Password Hash Verification
    if (PASSWORD_PLAIN_EQ.test(cleanContent) && /\.[cm]?[jt]s$|\.py$/.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [PASSWORD_PLAIN_EQ], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // ZERO-AUTH-24: Insecure OAuth Redirect URI Matching (Wildcard / Subdomain Match)
    if (/redirect_?ur[il]\.startsWith\s*\(\s*["\']https?:?(?:\/\/)?["\']\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/redirect_?ur[il]\.startsWith\s*\(\s*["\']https?:?(?:\/\/)?["\']\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // ZERO-AUTH-31: Insecure JWT Storage in Browser LocalStorage
    if (/localStorage\.setItem\s*\(\s*["\'](?:jwt|token|access_token|authToken)["\']\s*,\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && !/test|mock|spec/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/localStorage\.setItem\s*\(\s*["\'](?:jwt|token|access_token|authToken)["\']\s*,\s*[a-zA-Z0-9_]+\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8131,
            type: 'SECURITY',
            title: "ZERO-AUTH-31: Insecure JWT Storage in Browser LocalStorage",
            severity: 'MEDIUM',
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
    // ZERO-AUTH-42: Unprotected GraphQL Introspection in Production Environments
    // Literal `introspection: true` inside the ApolloServer config object (env-conditional values are left alone)
    const idx_8142 = (() => {
        for (const m of cleanContent.matchAll(/new\s+ApolloServer\s*\(\s*\{/g)) {
            let depth = 1;
            let i = m.index! + m[0].length;
            while (i < cleanContent.length && depth > 0) {
                if (cleanContent[i] === '{') depth++;
                else if (cleanContent[i] === '}') depth--;
                i++;
            }
            const body = cleanContent.slice(m.index! + m[0].length, i);
            const at = body.search(/\bintrospection\s*:\s*true\s*[,}\n]/);
            if (at !== -1) return cleanContent.slice(0, m.index! + m[0].length + at).split('\n').length - 1;
        }
        return -1;
    })();
    if (idx_8142 !== -1) {
        const matchLineIdx = idx_8142;
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
    // The handler must consume the event payload; the finding points at the handler declaration
    if (isWebhookHandler && REQUEST_BODY.test(cleanContent) && !isOutboundWebhookSender(cleanContent) && !(WEBHOOK_VERIFY.test(cleanContent) && /secret|signature/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/\.(?:post|all)\s*\(\s*['"`][^'"`]*webhook/i, SERVER_HANDLER], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `zeroauth43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8143,
            type: 'SECURITY',
            title: "ZERO-AUTH-43: Missing Identity Verification on Webhook Receiver Endpoints",
            severity: 'HIGH',
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
        logs.push(`[${ts}] 🛡️ HIGH: ZERO-AUTH-43 finding in ${file.path}:${lineNum}`);
    }
    // ZERO-AUTH-50: Insecure Ephemeral Token Generation using Math.random()
    if (MATH_RANDOM_TOKEN.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [MATH_RANDOM_TOKEN], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    return { findings, logs };
}
