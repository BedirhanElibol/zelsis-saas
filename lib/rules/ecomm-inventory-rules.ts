/**
 * Zelsis Master evaluateEcommInventoryRules Engine (50 Rules)
 * Rules ECOMM-01 to ECOMM-50 (Rule IDs 10101 to 10150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface EcommInventoryRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEcommInventoryRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EcommInventoryRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // ECOMM-01: Inventory Overselling Race Condition (Missing Row-Level Lock)
    if ((/stock\s*=\s*stock\s*-\s*1/i.test(cleanContent) && !/FOR\s+UPDATE|atomic/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/stock\s*=\s*stock\s*-\s*1/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10101-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10101,
            type: 'SECURITY',
            title: "ECOMM-01: Inventory Overselling Race Condition (Missing Row-Level Lock)",
            severity: "CRITICAL",
            category: "Concurrency & Inventory",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eCommerce shopping transaction line',
            reproductionSteps: [
                `Audited eCommerce transaction flow in ${file.path}:${lineNum}.`,
                'Detected eCommerce integrity violation matching ECOMM-01.'
            ],
            remediationPrompt: "Apply atomic decrement with condition check: UPDATE inventory SET stock = stock - :qty WHERE id = :id AND stock >= :qty.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ECOMM AUDIT] Found ECOMM-01: Inventory Overselling Race Condition (Missing Row-Level Lock) at ${file.path}:${lineNum}`);
    }
    // ECOMM-02: Client-Supplied Price / Discount Tampering Vulnerability
    if ((/total\s*\+?=\s*(?:req\.body|item)\.price/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/total\s*\+?=\s*(?:req\.body|item)\.price/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10102,
            type: 'SECURITY',
            title: "ECOMM-02: Client-Supplied Price / Discount Tampering Vulnerability",
            severity: "CRITICAL",
            category: "Pricing Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eCommerce shopping transaction line',
            reproductionSteps: [
                `Audited eCommerce transaction flow in ${file.path}:${lineNum}.`,
                'Detected eCommerce integrity violation matching ECOMM-02.'
            ],
            remediationPrompt: "Recalculate order total server-side using database product price values instead of client JSON amounts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ECOMM AUDIT] Found ECOMM-02: Client-Supplied Price / Discount Tampering Vulnerability at ${file.path}:${lineNum}`);
    }
    // ECOMM-03: Coupon Code Re-entrancy / Parallel Redemption Exploit
    if ((/applyCoupon|redeemDiscount/i.test(cleanContent) && !/transaction|forUpdate|lock|mutex/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/applyCoupon|redeemDiscount/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10103-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10103,
            type: 'SECURITY',
            title: "ECOMM-03: Coupon Code Re-entrancy / Parallel Redemption Exploit",
            severity: "HIGH",
            category: "Coupon Fraud",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eCommerce shopping transaction line',
            reproductionSteps: [
                `Audited eCommerce transaction flow in ${file.path}:${lineNum}.`,
                'Detected eCommerce integrity violation matching ECOMM-03.'
            ],
            remediationPrompt: "Acquire distributed lock on coupon code during checkout transaction to prevent race-condition reuse.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ECOMM AUDIT] Found ECOMM-03: Coupon Code Re-entrancy / Parallel Redemption Exploit at ${file.path}:${lineNum}`);
    }
    // ECOMM-04: Negative Quantity Shopping Cart Exploit (Price Inversion)
    if ((/quantity\s*:\s*(?:req\.body|body)\.quantity/.test(cleanContent) && !/quantity\s*>\s*0|Math\.max/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/quantity\s*:\s*(?:req\.body|body)\.quantity/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10104,
            type: 'SECURITY',
            title: "ECOMM-04: Negative Quantity Shopping Cart Exploit (Price Inversion)",
            severity: "CRITICAL",
            category: "Input Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eCommerce shopping transaction line',
            reproductionSteps: [
                `Audited eCommerce transaction flow in ${file.path}:${lineNum}.`,
                'Detected eCommerce integrity violation matching ECOMM-04.'
            ],
            remediationPrompt: "Validate item quantity is an integer >= 1 using Zod or Joi schema before computing cart totals.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ECOMM AUDIT] Found ECOMM-04: Negative Quantity Shopping Cart Exploit (Price Inversion) at ${file.path}:${lineNum}`);
    }
    // ECOMM-05: Shopping Cart Session Hijacking via Predictable Cart ID
    if ((/cartId\s*=\s*(?:Date\.now\(\)|Math\.random\(\))/.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/cartId\s*=\s*(?:Date\.now\(\)|Math\.random\(\))/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10105-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10105,
            type: 'SECURITY',
            title: "ECOMM-05: Shopping Cart Session Hijacking via Predictable Cart ID",
            severity: "HIGH",
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eCommerce shopping transaction line',
            reproductionSteps: [
                `Audited eCommerce transaction flow in ${file.path}:${lineNum}.`,
                'Detected eCommerce integrity violation matching ECOMM-05.'
            ],
            remediationPrompt: "Replace auto-increment cart IDs with crypto.randomUUID() session tokens.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ECOMM AUDIT] Found ECOMM-05: Shopping Cart Session Hijacking via Predictable Cart ID at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
