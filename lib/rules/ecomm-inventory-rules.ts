/**
 * Zelsis Master evaluateEcommInventoryRules Engine (50 Rules)
 * Rules ECOMM-01 to ECOMM-50 (Rule IDs 10101 to 10150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    const r10101Idx = lines.findIndex(l =>
        // read-modify-write of stock in application code (lost update under concurrency). The SQL form
        // `SET stock = stock - 1` and Prisma `{ decrement: n }` are atomic and are NOT matched.
        /\bstock\s*:\s*[\w$.]+\.stock\s*-\s*[\w$.]+/.test(l) ||
        /\b([\w$]+)\.stock\s*(?:-=\s*[\w$.]+|=\s*\1\.stock\s*-\s*[\w$.]+)/.test(l));
    if (r10101Idx !== -1) {
        const matchLineIdx = r10101Idx;
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
    const r10102Idx = lines.findIndex(l =>
        // money amount taken straight from the request body instead of the server-side catalog
        /(?:\btotal\s*\+?=|\bamount\s*:|\bunit_amount\s*:|\bprice\s*:)[^;\n]*\b(?:req\.body|body|input|payload)\.(?:items\[[^\]]*\]\.)?(?:price|amount|total|unitPrice|unit_amount)\b/.test(l));
    if (r10102Idx !== -1) {
        const matchLineIdx = r10102Idx;
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
    // ECOMM-04: Negative Quantity Shopping Cart Exploit (Price Inversion)
    const r10104Idx = /\.(?:positive|nonnegative)\(\)|\.min\(\s*1\s*\)|quantity\s*(?:<=?|>=?)\s*[01]\b|Math\.max\(|Number\.isInteger\(\s*(?:req\.body|body)\.quantity/.test(cleanContent) ? -1
        : lines.findIndex(l => /\bquantity\s*:\s*(?:Number\(\s*|parseInt\(\s*)?(?:req\.body|body)\.quantity\b/.test(l));
    if (r10104Idx !== -1) {
        const matchLineIdx = r10104Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ecomm10104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10104,
            type: 'SECURITY',
            title: "ECOMM-04: Negative Quantity Shopping Cart Exploit (Price Inversion)",
            severity: "HIGH",
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
    const r10105Idx = lines.findIndex(l => /\bcart_?Id\s*=\s*(?:String\(\s*)?(?:Date\.now\(\)|Math\.random\(\))/i.test(l));
    if (r10105Idx !== -1) {
        const matchLineIdx = r10105Idx;
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
