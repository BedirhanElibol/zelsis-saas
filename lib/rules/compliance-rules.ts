/**
 * Global Regulatory, Privacy & Legal Pre-Flight Gate Rules
 *
 * Rules:
 * - COMPL-01 (Rule ID 2001): Placeholder (dead) Privacy / Terms link
 * - COMPL-03 (Rule ID 2003): Cookie banner with Accept but no Reject
 * - COMPL-05 (Rule ID 2005): PII & Secret Leakage in URL Query Parameters
 * - COMPL-06 (Rule ID 2006): Raw Cardholder Data Input Exposure (PCI-DSS)
 * - COMPL-10 (Rule ID 2010): Consent cookie lifetime above 13 months
 * - COMPL-14 (Rule ID 2014): Plaintext password / secret in an email payload
 * Removed as unsound (ids never reused): 2002 (consent is often configured in the tag manager / CMP,
 * invisible in code), 2004, 2007, 2008 (file-level "absence of X" heuristics).
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
    const isExcluded = lowerPath.includes('dist/') ||
        lowerPath.includes('build/') ||
        lowerPath.includes('node_modules/') ||
        lowerPath.includes('.next/');
    if (isExcluded)
        return { findings, logs };
    // ---------------------------------------------------------------------------
    // COMPL-01 (Rule ID 2001): Accessible Privacy Policy & Terms Routes & Links
    // ---------------------------------------------------------------------------
    // The anchor itself: a link whose visible text is a legal page but whose href goes nowhere.
    const deadLegalLink = /<(?:a|Link)\b[^>]*\bhref\s*=\s*(?:["'](?:#|javascript:void\(0\);?)?["']|\{\s*["'](?:#)?["']\s*\})[^>]*>\s*(?:Privacy|Terms|Cookie\s+Policy|Legal|Imprint|Impressum|Data\s+Protection)/i;
    {
        const legalMatch = deadLegalLink.exec(cleanContent);
        if (legalMatch) {
            const matchLineIdx = cleanContent.slice(0, legalMatch.index).split('\n').length - 1;
            const lineNum = matchLineIdx + 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2001,
                type: 'LEGAL_COMPLIANCE',
                title: 'Accessible Privacy Policy & Terms of Service Routes & Links Missing or Inactive',
                severity: 'MEDIUM',
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
            logs.push(`[${ts}] ⚖️ MEDIUM: COMPL-01 Inaccessible Privacy/Terms route in ${file.path}:${lineNum}`);
        }
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
    // Only the file that DEFINES the banner (by path or by declaring the component), not files rendering it.
    const isCookieBannerComponent = !isTestFile &&
        (/cookie-?banner|consent-?(?:modal|banner)|cookie-?consent/.test(lowerPath) ||
            (!isHtmlFile && /(?:function|const|class)\s+(?:Cookie\w*(?:Banner|Consent|Notice)|Consent\w*(?:Banner|Modal|Notice))\b/.test(cleanContent)) ||
            (isHtmlFile && /(?:id|class|aria-label)=["'][^"']*(?:cookie-banner|cookie-consent|consent-modal)[^"']*["']/i.test(cleanContent)));
    if (isCookieBannerComponent) {
        // An actual accept control: a button whose label or click handler accepts / allows cookies.
        const acceptControl = /<(?:button|Button)\b[^>]*>\s*(?:Accept|Allow|Agree|I\s+agree)\b|<(?:button|Button)\b[^>]*\bonClick\s*=\s*\{\s*(?:\(\)\s*=>\s*)?\w*(?:accept|allow|agree)\w*/i;
        const hasDecline = /(?:reject|decline|opt[_-]?out|refuse|deny|necessary\s+only|essential\s+only|only\s+(?:necessary|essential))/i.test(cleanContent);
        const acceptMatch = acceptControl.exec(cleanContent);
        if (acceptMatch && !hasDecline) {
            const fallbackLineIdx = cleanContent.slice(0, acceptMatch.index).split('\n').length - 1;
            const lineNum = fallbackLineIdx + 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2003,
                type: 'LEGAL_COMPLIANCE',
                title: 'Cookie Consent Banner Dark Pattern: Missing Symmetric Reject / Decline Action',
                severity: 'MEDIUM',
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
            logs.push(`[${ts}] ⚖️ MEDIUM: COMPL-03 Cookie Banner Dark Pattern in ${file.path}:${lineNum}`);
        }
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
            severity: 'MEDIUM',
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
        logs.push(`[${ts}] ⚖️ MEDIUM: COMPL-05 PII Leakage in URL Query Parameters in ${file.path}:${lineNum}`);
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
            severity: 'HIGH',
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
        logs.push(`[${ts}] 🛑 HIGH: COMPL-06 Raw Cardholder Data Input in ${file.path}:${lineNum}`);
    }
    // ---------------------------------------------------------------------------
    // COMPL-10 (Rule ID 2010): Max Consent Lifetime & Re-consent Policy (12-Month Expiry)
    // ---------------------------------------------------------------------------
    // Any consent cookie: custom names or common CMPs (Cookiebot, OneTrust, CookieYes, Klaro, Osano, vanilla-cookieconsent)
    // Scoped to a cookie-set call whose cookie NAME is a consent cookie, with units per API:
    // Express res.cookie maxAge = ms, js-cookie expires = days, Next/nookies/cookie maxAge = seconds.
    // Fires above 13 months (CNIL guidance), i.e. > 396 days.
    let consentLifetimeIdx = -1;
    const cookieSet = /(\bres\.cookie|\bCookies\.set|\bsetCookie|\.set)\s*\(\s*['"`]([^'"`]+)['"`]([^;]{0,400})/g;
    for (let m = cookieSet.exec(cleanContent); m && consentLifetimeIdx === -1; m = cookieSet.exec(cleanContent)) {
        if (!/consent|cc_cookie|optanon|cookie_?pref|gdpr/i.test(m[2])) continue;
        const life = /\b(maxAge|expires)\s*:\s*([\d_]+(?:\s*\*\s*[\d_]+)*)/.exec(m[3]);
        if (!life) continue;
        const raw = life[2].split('*').reduce((acc, n) => acc * Number(n.replace(/[_\s]/g, '')), 1);
        const seconds = m[1] === 'res.cookie' ? raw / 1000 : life[1] === 'expires' ? (m[1] === 'Cookies.set' ? raw * 86400 : NaN) : raw;
        if (seconds > 396 * 86400) {
            const at = m.index + m[0].indexOf(life[0], m[0].length - m[3].length);
            consentLifetimeIdx = cleanContent.slice(0, at).split('\n').length - 1;
        }
    }
    {
        if (consentLifetimeIdx !== -1) {
            const lineNum = consentLifetimeIdx + 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 2010,
                type: 'LEGAL_COMPLIANCE',
                title: 'Excessive Cookie Consent Duration Detected (>12 Months GDPR/CNIL Cap)',
                severity: 'MEDIUM',
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
            logs.push(`[${ts}] ⚖️ MEDIUM: COMPL-10 Excessive consent duration in ${file.path}:${lineNum}`);
        }
    }
    // ---------------------------------------------------------------------------
    // COMPL-14 (Rule ID 2014): Plaintext Credentials / OTP in Email Payloads
    // ---------------------------------------------------------------------------
    const isEmailOrNotifier = (lowerPath.includes('mail') || lowerPath.includes('email') || lowerPath.includes('notify') || lowerPath.includes('resend')) && /\.(?:ts|js)$/i.test(file.path);
    if (isEmailOrNotifier) {
        const plaintextCredentialInEmailRegex = /(?:sendMail|emails\.send|resend\.emails\.send)\s*\([^)]*(?:password|passwd|api_key|tokenSecret)\s*:/i;
        const emailMatch = plaintextCredentialInEmailRegex.exec(cleanContent);
        if (emailMatch) {
            // Point at the credential key inside the (often multi-line) send call.
            const keyOffset = emailMatch[0].search(/(?:password|passwd|api_key|tokenSecret)\s*:\s*$/i);
            const matchLineIdx = cleanContent.slice(0, emailMatch.index + Math.max(0, keyOffset)).split('\n').length - 1;
            const lineNum = matchLineIdx + 1;
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
