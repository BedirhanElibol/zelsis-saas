/**
 * Zelsis Master evaluateFintechComplianceRules Engine (50 Rules)
 * Rules FINTECH-01 to FINTECH-50 (Rule IDs 9701 to 9750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { PAYMENT_SDK, REQUEST_BODY, WEBHOOK_VERIFY } from './shared/stack-signals';
import { locateMatchLine } from './shared/locate';
export interface FintechComplianceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateFintechComplianceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): FintechComplianceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // FINTECH-01: Storage of Sensitive Authentication Data (Card CVV / CVC)
    // A persisted CVV: SQL column, Prisma / Drizzle / Mongoose field, or a DB write carrying the CVV.
    const cvvName = String.raw`(?:cvv|cvc|cvv2|card_?cvv|card_?cvc|card_?security_?code)`;
    const cvvPatterns = [
        new RegExp(String.raw`\b(?:CREATE|ALTER)\s+TABLE\b[^;]*?\b${cvvName}\b\s+(?:varchar|text|char|int|integer|smallint|numeric)`, 'i'), // SQL
        new RegExp(String.raw`\b(?:varchar|text|integer|char)\s*\(\s*['"]${cvvName}['"]`, 'i'), // Drizzle
        new RegExp(String.raw`\b${cvvName}\s*:\s*(?:\{\s*type\s*:\s*)?(?:String|Number)\b`), // Mongoose
        new RegExp(String.raw`\.(?:insert|upsert|create|save)\s*\(\s*(?:\{\s*data\s*:\s*)?\{[^}]*\b${cvvName}\b`, 'i'), // DB write
    ];
    if (lowerPath.endsWith('.prisma')) cvvPatterns.push(new RegExp(String.raw`^\s*${cvvName}\s+(?:String|Int)\b`, 'im'));
    const cvvStorage = cvvPatterns.map(re => re.exec(cleanContent)).find(Boolean);
    if (cvvStorage) {
        const matchLineIdx = cleanContent.slice(0, cvvStorage.index + Math.max(0, cvvStorage[0].search(new RegExp(String.raw`\b${cvvName}\b`, 'i')))).split('\n').length - 1;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `fintech9701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9701,
            type: 'LEGAL_COMPLIANCE',
            title: "FINTECH-01: Storage of Sensitive Authentication Data (Card CVV / CVC)",
            severity: "CRITICAL",
            category: "Cardholder Data Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Fintech payment operation',
            reproductionSteps: [
                `Audited payment code in ${file.path}:${lineNum}.`,
                'Detected PCI-DSS compliance violation matching FINTECH-01.'
            ],
            remediationPrompt: "Remove cvc/cvv columns and configure tokenized checkout to avoid receiving raw card security codes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINTECH AUDIT] Found FINTECH-01: Storage of Sensitive Authentication Data (Card CVV / CVC) at ${file.path}:${lineNum}`);
    }
    // FINTECH-02: Unmasked Primary Account Number (PAN) Displayed in UI
    // The raw PAN rendered as JSX text: `>{card.cardNumber}<` (a masking call like {mask(card.cardNumber)} is fine).
    const rawPan = />\s*\{\s*(?:\w+\??\.)*(?:cardNumber|card_number|primaryAccountNumber)\s*\}/.exec(cleanContent);
    if (rawPan) {
        const matchLineIdx = cleanContent.slice(0, rawPan.index).split('\n').length - 1;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `fintech9702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9702,
            type: 'LEGAL_COMPLIANCE',
            title: "FINTECH-02: Unmasked Primary Account Number (PAN) Displayed in UI",
            severity: "HIGH",
            category: "Cardholder Data Display",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Fintech payment operation',
            reproductionSteps: [
                `Audited payment code in ${file.path}:${lineNum}.`,
                'Detected PCI-DSS compliance violation matching FINTECH-02.'
            ],
            remediationPrompt: "Enforce card masking helper: card.slice(-4).padStart(card.length, '*') in frontend and receipt views.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINTECH AUDIT] Found FINTECH-02: Unmasked Primary Account Number (PAN) Displayed in UI at ${file.path}:${lineNum}`);
    }
    // FINTECH-03: Missing Idempotency-Key on Financial Payment Mutation
    // A call that moves money immediately (charges.create, or paymentIntents.create with confirm: true)
    // whose own arguments carry no idempotencyKey: a retried request double-charges the customer.
    let unkeyedChargeIdx = -1;
    const chargeCall = /\bstripe\.(?:charges\.create|paymentIntents\.create)\s*\(/g;
    for (let m = chargeCall.exec(cleanContent); m && unkeyedChargeIdx === -1; m = chargeCall.exec(cleanContent)) {
        let depth = 0, end = cleanContent.length;
        for (let i = m.index + m[0].length - 1; i < cleanContent.length; i++) {
            if (cleanContent[i] === '(') depth++;
            else if (cleanContent[i] === ')' && --depth === 0) { end = i; break; }
        }
        const args = cleanContent.slice(m.index, end);
        const movesMoney = /charges\.create/.test(m[0]) || /\bconfirm\s*:\s*true\b/.test(args);
        if (movesMoney && !/\bidempotencyKey\b/.test(args)) unkeyedChargeIdx = cleanContent.slice(0, m.index).split('\n').length - 1;
    }
    if (unkeyedChargeIdx !== -1) {
        const matchLineIdx = unkeyedChargeIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `fintech9703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9703,
            type: 'LEGAL_COMPLIANCE',
            title: "FINTECH-03: Missing Idempotency-Key on Financial Payment Mutation",
            severity: "MEDIUM",
            category: "Transaction Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Fintech payment operation',
            reproductionSteps: [
                `Audited payment code in ${file.path}:${lineNum}.`,
                'Detected PCI-DSS compliance violation matching FINTECH-03.'
            ],
            remediationPrompt: "Pass idempotencyKey: `charge_${orderId}_${retryCount}` in payment creation requests.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINTECH AUDIT] Found FINTECH-03: Missing Idempotency-Key on Financial Payment Mutation at ${file.path}:${lineNum}`);
    }
    // FINTECH-04: Insecure Webhook Signature Verification on Payment Callback
    const isWebhookCode = lowerPath.includes('webhook') || /\.(?:post|all)\s*\(\s*['"`][^'"`]*webhook/i.test(cleanContent);
    if (isWebhookCode && (PAYMENT_SDK.test(lowerPath + cleanContent) || /(?:payment|billing|checkout|subscription|invoice|order)/i.test(lowerPath + cleanContent)) && REQUEST_BODY.test(cleanContent) && !WEBHOOK_VERIFY.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [PAYMENT_SDK, /(?:payment|billing|checkout|subscription|invoice|order)/i, REQUEST_BODY], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fintech9704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9704,
            type: 'LEGAL_COMPLIANCE',
            title: "FINTECH-04: Insecure Webhook Signature Verification on Payment Callback",
            severity: "CRITICAL",
            category: "Payment Webhook Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Fintech payment operation',
            reproductionSteps: [
                `Audited payment code in ${file.path}:${lineNum}.`,
                'Detected PCI-DSS compliance violation matching FINTECH-04.'
            ],
            remediationPrompt: "Enforce stripe.webhooks.constructEvent or polar HMAC verification before processing event payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINTECH AUDIT] Found FINTECH-04: Insecure Webhook Signature Verification on Payment Callback at ${file.path}:${lineNum}`);
    }
    // FINTECH-05: Plaintext Cardholder Data Logged to Application Telemetry
    // A log call whose ARGUMENTS (string literals removed, so 'card added' text does not count) reference the
    // PAN or CVV as an identifier / property.
    const panLogIdx = lines.findIndex(l => {
        if (/^\s*(?:\/\/|\*)/.test(l)) return false;
        const call = /(?:console\.(?:log|info|debug|warn|error)|logger\.(?:log|info|debug|warn|error))\s*\((.*)/.exec(l);
        if (!call) return false;
        // Drop string literals, then masked forms (x.slice(-4), mask*(x), last4) which are safe to log.
        const args = call[1].replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\$]|\\.)*`/g, '')
            .replace(/(?:String\s*\(\s*)?[\w.]+\s*\)?\s*\.slice\(\s*-4\s*\)|\bmask\w*\s*\([^)]*\)/gi, '');
        return /\b(?:cardNumber|card_number|primaryAccountNumber|cvv|cvc|cvv2|cardCvc|cardCvv)\b/.test(args);
    });
    if (panLogIdx !== -1) {
        const matchLineIdx = panLogIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `fintech9705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9705,
            type: 'LEGAL_COMPLIANCE',
            title: "FINTECH-05: Plaintext Cardholder Data Logged to Application Telemetry",
            severity: "HIGH",
            category: "Audit Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Fintech payment operation',
            reproductionSteps: [
                `Audited payment code in ${file.path}:${lineNum}.`,
                'Detected PCI-DSS compliance violation matching FINTECH-05.'
            ],
            remediationPrompt: "Scrub payment request payloads before passing them to application logging frameworks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINTECH AUDIT] Found FINTECH-05: Plaintext Cardholder Data Logged to Application Telemetry at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
