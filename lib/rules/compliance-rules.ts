/**
 * Global Regulatory, Privacy & Legal Pre-Flight Gate Rules (Rules 2001-2006)
 *
 * Rules:
 * 1. COMPL-01 (Rule ID 2001): Accessible Privacy Policy & Terms Routes & Links
 * 2. COMPL-02 (Rule ID 2002): Unconsented Third-Party Tracker & Pixel Script Injection
 * 3. COMPL-03 (Rule ID 2003): Dark Pattern Cookie Banner Prevention
 * 4. COMPL-04 (Rule ID 2004): Consent Disclosure on User Input & Lead Forms
 * 5. COMPL-05 (Rule ID 2005): PII & Secret Leakage in URL Query Parameters
 * 6. COMPL-06 (Rule ID 2006): Raw Cardholder Data Input Exposure (PCI-DSS)
 *
 * Classification: 100% Native English Only
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
export interface ComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
function extractSnippet(lines: string[], lineNum: number): string {
    const targetIdx = Math.max(0, lineNum - 1);
    const start = Math.max(0, targetIdx - 2);
    const end = Math.min(lines.length, targetIdx + 3);
    return lines.slice(start, end).join('\n');
}
export function evaluateComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const ts = new Date().toLocaleTimeString();
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Scope: Only evaluate code and markup files (.tsx, .jsx, .ts, .js, .html)
    const isRelevant = /\.(tsx|jsx|ts|js|html)$/i.test(lowerPath);
    if (!isRelevant)
        return { findings, logs };
    // False-positive guard: Skip internal scanner engines, mock data, and rule definitions
    const isExcluded = lowerPath.includes('lib/rules/') ||
        lowerPath.includes('data/mockdata.ts') ||
        lowerPath.includes('data/workspacefiles.ts') ||
        lowerPath.includes('lib/scanner-engine.ts') ||
        lowerPath.includes('vulnerabilityplayground.tsx') ||
        lowerPath.includes('ruleknowledgebasemodal.tsx') ||
        lowerPath.includes('interactiveanalyzer.tsx') ||
        lowerPath.includes('scratch/') ||
        lowerPath.includes('.agent/') ||
        lowerPath.includes('dist/') ||
        lowerPath.includes('build/') ||
        lowerPath.includes('node_modules/') ||
        lowerPath.includes('.next/');
    if (isExcluded)
        return { findings, logs };
    // ---------------------------------------------------------------------------
    // COMPL-01 (Rule ID 2001): Accessible Privacy Policy & Terms Routes & Links
    // ---------------------------------------------------------------------------
    const isNavOrAuthScope = lowerPath.includes('footer') ||
        lowerPath.includes('auth') ||
        lowerPath.includes('signup') ||
        lowerPath.includes('register') ||
        lowerPath.includes('layout') ||
        lowerPath.includes('nav');
    if (isNavOrAuthScope) {
        const hasDummyLink = /href\s*=\s*["'](#|javascript:void\(0\)|)["']/i.test(cleanContent);
        const mentionsLegal = /(?:privacy|terms|policy|legal)/i.test(cleanContent);
        if (hasDummyLink && mentionsLegal) {
            let matchLineIdx = lines.findIndex(l => {
                const trimmed = l.trim();
                if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                    return false;
                return /href\s*=\s*["'](#|javascript:void\(0\)|)["']/i.test(l) && /(?:privacy|terms|policy|legal)/i.test(l);
            });
            if (matchLineIdx === -1) {
                matchLineIdx = lines.findIndex(l => {
                    const trimmed = l.trim();
                    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                        return false;
                    return /href\s*=\s*["'](#|javascript:void\(0\)|)["']/i.test(l);
                });
            }
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2001,
                type: 'LEGAL_COMPLIANCE',
                title: 'Accessible Privacy Policy & Terms of Service Routes & Links Missing or Inactive',
                severity: 'HIGH',
                category: 'Transparency & Notice',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || '<a href="#">Privacy Policy</a>',
                reproductionSteps: [
                    `Scanned navigation and layout routes in ${file.path}:${lineNum}.`,
                    'Detected inactive or placeholder anchor tag (href="#" or href="javascript:void(0)") referencing legal routes without a valid destination route.'
                ],
                remediationPrompt: `Add dedicated, accessible legal routes at app/privacy/page.tsx and app/terms/page.tsx. Replace all placeholder anchor links with functional Next.js <Link href="/privacy"> and <Link href="/terms"> components in ${file.path}.`,
                status: 'OPEN',
                owner: 'Compliance & Legal',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ HIGH: COMPL-01 Inaccessible Privacy/Terms route in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-02 (Rule ID 2002): Unconsented Third-Party Tracker & Pixel Script Injection
    // ---------------------------------------------------------------------------
    const trackerPattern = /(?:googletagmanager\.com|gtag\s*\(\s*['"]config['"]|connect\.facebook\.net|fbq\s*\(\s*['"]init['"]|analytics\.tiktok\.com|ttq\.(?:load|page)|static\.hotjar\.com|_hjSettings)/i;
    const consentGatePattern = /(?:consent|hasConsented|cookieConsent|CookieBanner|ConsentProvider|ConsentGate|default.*denied|ad_storage.*denied|analytics_storage.*denied)/i;
    const hasTrackerScript = trackerPattern.test(cleanContent) || lines.some(l => {
        const trimmed = l.trim();
        return !trimmed.startsWith('//') && !trimmed.startsWith('*') && !trimmed.startsWith('/*') && trackerPattern.test(l);
    });
    const hasConsentGate = consentGatePattern.test(cleanContent) || consentGatePattern.test(file.content || '');
    if (hasTrackerScript && !hasConsentGate) {
        const matchLineIdx = lines.findIndex(l => {
            const trimmed = l.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                return false;
            return trackerPattern.test(l);
        });
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 2002,
            type: 'LEGAL_COMPLIANCE',
            title: 'Unconsented Third-Party Tracker & Pixel Script Injection (ePrivacy & GDPR Violation)',
            severity: 'CRITICAL',
            category: 'Consent & Tracking',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || 'fbq("init", "123456789");',
            reproductionSteps: [
                `Scanned script execution pathways in ${file.path}:${lineNum}.`,
                'Detected direct loading or execution of third-party analytics/pixel tracker prior to affirmative user consent verification.'
            ],
            remediationPrompt: `Wrap third-party tracking scripts in ${file.path} inside a consent-aware gate component or configure Google Consent Mode v2 default-denied flags (ad_storage='denied', analytics_storage='denied') prior to script execution.`,
            status: 'OPEN',
            owner: 'Compliance & Legal',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: COMPL-02 Unconsented Tracker Script in ${file.path}:${lineNum}`);
    }
    // ---------------------------------------------------------------------------
    // COMPL-03 (Rule ID 2003): Dark Pattern Cookie Banner Prevention
    // ---------------------------------------------------------------------------
    const isTestFile = lowerPath.includes('/test/') ||
        lowerPath.includes('/tests/') ||
        lowerPath.includes('/spec/') ||
        lowerPath.includes('/specs/') ||
        lowerPath.includes('/__tests__/') ||
        lowerPath.startsWith('test/') ||
        lowerPath.startsWith('tests/') ||
        lowerPath.startsWith('spec/') ||
        /\.(test|spec)\.[a-zA-Z0-9]+$/i.test(lowerPath);
    const isHtmlFile = file.path.endsWith('.html');
    const isCookieBannerComponent = !isTestFile &&
        (lowerPath.includes('cookie-banner') ||
            lowerPath.includes('consent-modal') ||
            lowerPath.includes('cookieconsent') ||
            (!isHtmlFile && /CookieBanner|ConsentModal|CookieConsent/i.test(cleanContent)) ||
            (isHtmlFile && /(?:id|class|aria-label)=["'][^"']*(?:cookie-banner|cookie-consent|consent-modal)[^"']*["']/i.test(cleanContent)));
    if (isCookieBannerComponent) {
        const hasAccept = /(?:accept|allow|agree)/i.test(cleanContent);
        const hasDecline = /(?:reject|decline|opt[_-]?out|refuse|deny)/i.test(cleanContent);
        if (hasAccept && !hasDecline) {
            const matchLineIdx = lines.findIndex(l => {
                const trimmed = l.trim();
                if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                    return false;
                return /(?:accept|allow|agree)/i.test(l) && /(?:button|onClick|btn)/i.test(l);
            });
            const fallbackLineIdx = matchLineIdx !== -1 ? matchLineIdx : lines.findIndex(l => {
                const trimmed = l.trim();
                if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                    return false;
                return /(?:accept|allow|agree)/i.test(l);
            });
            const lineNum = fallbackLineIdx !== -1 ? fallbackLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2003,
                type: 'LEGAL_COMPLIANCE',
                title: 'Cookie Consent Banner Dark Pattern: Missing Symmetric Reject / Decline Action',
                severity: 'HIGH',
                category: 'Consent & Tracking',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[fallbackLineIdx] || '<button>Accept All Cookies</button>',
                reproductionSteps: [
                    `Scanned consent banner interface in ${file.path}:${lineNum}.`,
                    'Identified asymmetric consent choices offering an Accept/Allow button but lacking an equally prominent single-click Reject/Decline button.'
                ],
                remediationPrompt: `Refactor cookie banner in ${file.path} to implement equal-choice parity. Provide a visible 'Reject All' or 'Decline Non-Essential' button with identical visual weight, contrast, and single-click interaction as 'Accept All'.`,
                status: 'OPEN',
                owner: 'Compliance & Legal',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ HIGH: COMPL-03 Cookie Banner Dark Pattern in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-04 (Rule ID 2004): Consent Disclosure on User Input & Lead Forms
    // ---------------------------------------------------------------------------
    const isFormFile = /(?:form|newsletter|waitlist|subscribe|contact|lead|signup|register)/i.test(lowerPath) ||
        /<form\b[^>]*>/i.test(cleanContent);
    // Login/Sign-in forms do not require consent checkboxes since consent was granted at signup (F-38)
    const isLoginForm = /(?:login|sign-in|signin|session|authenticate)/i.test(lowerPath) ||
        (/(?:sign\s*in|log\s*in)/i.test(cleanContent) && !/(?:sign\s*up|register|create\s*account|new\s*account|subscribe|waitlist|newsletter)/i.test(cleanContent));
    const hasEmailInput = /<input[^>]+(?:type|name)\s*=\s*["'](?:email|tel)["']/i.test(cleanContent);
    const hasConsentNotice = /(?:privacy\s*policy|terms\s*of\s*service|terms\s*&\s*conditions|agree\s*to\s*(?:our|the)|consent|gdpr|data\s*processing)/i.test(cleanContent);
    if (isFormFile && !isLoginForm && hasEmailInput && !hasConsentNotice) {
        const matchLineIdx = lines.findIndex(l => {
            const trimmed = l.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                return false;
            return /<input[^>]+(?:type|name)\s*=\s*["'](?:email|tel)["']/i.test(l);
        });
        const fallbackLineIdx = matchLineIdx !== -1 ? matchLineIdx : lines.findIndex(l => {
            const trimmed = l.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                return false;
            return /<form\b/i.test(l);
        });
        const lineNum = fallbackLineIdx !== -1 ? fallbackLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 2004,
            type: 'LEGAL_COMPLIANCE',
            title: 'User Data Collection Form Missing Mandatory Privacy Consent Disclosure',
            severity: 'MEDIUM',
            category: 'Data Collection & Forms',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[fallbackLineIdx] || '<input type="email" required />',
            reproductionSteps: [
                `Scanned form markup in ${file.path}:${lineNum}.`,
                'Detected personal data collection fields (email/tel) lacking mandatory affirmative consent statement or Privacy Policy notice adjacent to submission.'
            ],
            remediationPrompt: `Add an explicit consent disclosure adjacent to the form submit button in ${file.path}: 'By submitting, you agree to our Privacy Policy and Terms of Service.' Ensure 'Privacy Policy' links to an active legal route.`,
            status: 'OPEN',
            owner: 'Compliance & Legal',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚠️ MEDIUM: COMPL-04 Missing Form Consent Disclosure in ${file.path}:${lineNum}`);
    }
    // ---------------------------------------------------------------------------
    // COMPL-05 (Rule ID 2005): PII & Secret Leakage in URL Query Parameters
    // ---------------------------------------------------------------------------
    const hasPiiUrlParam = /(?:router\.(?:push|replace)|window\.location(?:\.href)?\s*=|navigate|fetch)\s*\(\s*[`'"][^`'"]*[?&](?:email|phone|password|ssn|token|apiKey|secret)=/i.test(cleanContent) ||
        /(?:router\.(?:push|replace)|navigate)\s*\(\s*[`'"][^`'"]*[?&][^`'"]*\$\{[^}]*(?:email|token|password|secret|phone)[^}]*\}/i.test(cleanContent);
    if (hasPiiUrlParam) {
        const matchLineIdx = lines.findIndex(l => {
            const trimmed = l.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                return false;
            return (/(?:router\.(?:push|replace)|window\.location|navigate|fetch)\s*\(.*[?&](?:email|phone|password|ssn|token|apiKey|secret)=/i.test(l) ||
                /(?:router\.(?:push|replace)|navigate)\s*\(.*[?&].*\$\{[^}]*(?:email|token|password|secret|phone)/i.test(l));
        });
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 2005,
            type: 'LEGAL_COMPLIANCE',
            title: 'PII or Sensitive Authentication Secret Leaked in URL Query Parameters',
            severity: 'HIGH',
            category: 'Privacy by Design',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || "router.push(`/onboarding?email=${email}`);",
            reproductionSteps: [
                `Scanned client navigation and network requests in ${file.path}:${lineNum}.`,
                'Detected sensitive PII or authentication secret serialized into URL search parameters, exposing data to browser histories, server access logs, and HTTP Referer headers.'
            ],
            remediationPrompt: `Refactor navigation in ${file.path} to transmit sensitive parameters via encrypted POST request bodies or server-managed session cookies instead of URL query parameters.`,
            status: 'OPEN',
            owner: 'Compliance & Legal',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚖️ HIGH: COMPL-05 PII Leakage in URL Query Parameters in ${file.path}:${lineNum}`);
    }
    // ---------------------------------------------------------------------------
    // COMPL-06 (Rule ID 2006): Raw Cardholder Data Input Exposure (PCI-DSS)
    // ---------------------------------------------------------------------------
    const hasRawCardInput = /<input[^>]+(?:name|id|autocomplete)\s*=\s*["'](?:card_number|cardnumber|cc-number|cc_num|cvv|cvc|card_cvv|card_expiry|card-expiry|card_exp)["']/i.test(cleanContent) ||
        /<input[^>]+placeholder\s*=\s*["'][^"']*(?:card\s*number|16\s*digits|security\s*code)[^"']*["']/i.test(cleanContent);
    const hasPciProvider = /(?:@stripe\/react-stripe-js|CardElement|PaymentElement|CardNumberElement|CardCvcElement|CardExpiryElement|@polar-sh|paypal|paddle)/i.test(cleanContent);
    if (hasRawCardInput && !hasPciProvider) {
        const matchLineIdx = lines.findIndex(l => {
            const trimmed = l.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                return false;
            return (/<input[^>]+(?:name|id|autocomplete)\s*=\s*["'](?:card_number|cardnumber|cc-number|cc_num|cvv|cvc|card_cvv|card_expiry|card-expiry|card_exp)["']/i.test(l) ||
                /<input[^>]+placeholder\s*=\s*["'][^"']*(?:card\s*number|16\s*digits|security\s*code)[^"']*["']/i.test(l));
        });
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 2006,
            type: 'LEGAL_COMPLIANCE',
            title: 'Raw Cardholder Data Input Element Detected (PCI-DSS SAQ-D Exposure Risk)',
            severity: 'CRITICAL',
            category: 'Payment Card Security',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || '<input name="card_number" placeholder="Card Number" />',
            reproductionSteps: [
                `Scanned payment collection markup in ${file.path}:${lineNum}.`,
                'Detected unhosted HTML cardholder data input element, exposing application to PCI-DSS SAQ-D compliance scope and unencrypted PAN capture risk.'
            ],
            remediationPrompt: `Remove unhosted card input fields in ${file.path}. Use PCI-DSS Level 1 certified hosted fields (such as Stripe Elements <CardElement /> or Polar Checkout) to ensure card numbers are tokenized directly on payment processor infrastructure.`,
            status: 'OPEN',
            owner: 'Compliance & Legal',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: COMPL-06 Raw Cardholder Data Input in ${file.path}:${lineNum}`);
    }
    // ---------------------------------------------------------------------------
    // COMPL-07 (Rule ID 2007): Tamper-Evident Security Audit Logging for Administrative Actions
    // ---------------------------------------------------------------------------
    const isAdminRoute = lowerPath.includes('/api/admin/') || lowerPath.includes('/api/v1/admin/');
    if (isAdminRoute && /\.(?:ts|js)$/i.test(file.path)) {
        const hasAdminMutation = /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(cleanContent);
        const hasAuditLog = /(?:audit_logs|auditLog|recordAudit|logger\.audit|insertAudit)/i.test(cleanContent);
        if (hasAdminMutation && !hasAuditLog) {
            const matchLineIdx = lines.findIndex(l => /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2007,
                type: 'LEGAL_COMPLIANCE',
                title: 'Missing Immutable Security Audit Logging on Administrative Mutation Route',
                severity: 'CRITICAL',
                category: 'Enterprise Governance & Auditability',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned administrative endpoint at ${file.path}:${lineNum}.`,
                    'Detected state mutation handler without recording structured security audit logs, violating SOC 2 Type II CC6.8 and ISO 27001 compliance standards.'
                ],
                remediationPrompt: `Record immutable audit log entry (actor_id, target_id, action, timestamp, IP) in ${file.path}:${lineNum} before returning response.`,
                status: 'OPEN',
                owner: 'Compliance Officer',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ CRITICAL: COMPL-07 Missing audit log on admin route in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-08 (Rule ID 2008): Automated Session Invalidation on Password Reset
    // ---------------------------------------------------------------------------
    const isPasswordResetFile = (lowerPath.includes('password') || lowerPath.includes('reset')) && /\.(?:ts|js)$/i.test(file.path);
    if (isPasswordResetFile) {
        const hasSessionRevoke = /(?:signOut\([^)]*GLOBAL|revokeAll|tokenVersion|session\.destroy|incrementTokenVersion)/i.test(cleanContent);
        if (!hasSessionRevoke) {
            const matchLineIdx = lines.findIndex(l => l.includes('updatePassword') || l.includes('resetPassword'));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2008,
                type: 'LEGAL_COMPLIANCE',
                title: 'Missing Session Revocation / tokenVersion Invalidation on Password Reset',
                severity: 'HIGH',
                category: 'Authentication & Identity Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned password mutation handler at ${file.path}:${lineNum}.`,
                    'Detected password update logic failing to revoke active user sessions or increment tokenVersion, leaving existing authenticated sessions open on adversary devices.'
                ],
                remediationPrompt: `Increment tokenVersion or invoke global session revocation (e.g. supabase.auth.admin.signOut(userId, 'GLOBAL')) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ HIGH: COMPL-08 Password reset missing global session revocation in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-10 (Rule ID 2010): Max Consent Lifetime & Re-consent Policy (12-Month Expiry)
    // ---------------------------------------------------------------------------
    if (cleanContent.includes('consent_status') || cleanContent.includes('zelsis_consent')) {
        const excessiveCookieMaxAgeRegex = /maxAge\s*:\s*(?:[4-9]\d{7,}|[1-9]\d{8,})/;
        if (excessiveCookieMaxAgeRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => excessiveCookieMaxAgeRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2010,
                type: 'LEGAL_COMPLIANCE',
                title: 'Excessive Cookie Consent Duration Detected (>12 Months GDPR/CNIL Cap)',
                severity: 'HIGH',
                category: 'Cookie & Privacy Compliance',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned consent cookie expiration configuration at ${file.path}:${lineNum}.`,
                    'Detected cookie lifetime exceeding 12 months (31,536,000 seconds), violating European Data Protection Board (EDPB) and CNIL consent validity duration caps.'
                ],
                remediationPrompt: `Cap cookie consent maxAge to 31,536,000 seconds (365 days) in ${file.path}:${lineNum} to comply with European regulatory consent guidelines.`,
                status: 'OPEN',
                owner: 'Privacy Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ HIGH: COMPL-10 Excessive consent duration in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-14 (Rule ID 2014): Plaintext Credentials / OTP in Email Payloads
    // ---------------------------------------------------------------------------
    const isEmailOrNotifier = (lowerPath.includes('mail') || lowerPath.includes('email') || lowerPath.includes('notify') || lowerPath.includes('resend')) && /\.(?:ts|js)$/i.test(file.path);
    if (isEmailOrNotifier) {
        const plaintextCredentialInEmailRegex = /(?:sendMail|emails\.send|resend\.emails\.send)\s*\([^)]*(?:password|passwd|api_key|tokenSecret)\s*:/i;
        if (plaintextCredentialInEmailRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => plaintextCredentialInEmailRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2014,
                type: 'LEGAL_COMPLIANCE',
                title: 'Plaintext Password or Permanent Secret Transmitted in Email Payload',
                severity: 'HIGH',
                category: 'Privacy & Credential Protection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned email dispatch handler at ${file.path}:${lineNum}.`,
                    'Detected plaintext password or permanent secret token embedded directly inside outbound email template payload.'
                ],
                remediationPrompt: `Never email plaintext passwords. Use time-limited one-time magic links or password reset tokens with short expiry in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚖️ HIGH: COMPL-14 Plaintext password in email in ${file.path}:${lineNum}`);
        }
    }
    return { findings, logs };
}
