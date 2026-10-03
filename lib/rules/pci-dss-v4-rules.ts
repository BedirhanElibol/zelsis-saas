/**
 * Zelsis Master evaluatePciDssV4Rules Engine (50 Rules)
 * Rules PCI4-01 to PCI4-50 (Rule IDs 12901 to 12950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface PciDssV4RuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluatePciDssV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): PciDssV4RuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages
    // Only applies if payment/checkout view actually loads an external <script> tag
    const hit_12902 = /payment|checkout/i.test(lowerPath) ? findUnpinnedThirdPartyScript(cleanContent) : -1;
    if (hit_12902 !== -1) {
        const matchLineIdx = hit_12902;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pci412902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12902,
            type: 'LEGAL_COMPLIANCE',
            title: "PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages",
            severity: "CRITICAL",
            category: "Script Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PCI-DSS v4.0 configuration',
            reproductionSteps: [
                `Audited PCI-DSS v4.0 configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching PCI4-02.'
            ],
            remediationPrompt: "Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PCI-DSS AUDIT] Found PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
/** Payment SDKs that must be loaded live from the provider (they forbid SRI pinning). */
const PAYMENT_SDK_HOST = /^https?:\/\/(?:js\.stripe\.com|checkout\.stripe\.com|(?:www\.)?paypal\.com|(?:www\.)?paypalobjects\.com|js\.braintreegateway\.com|checkoutshopper-(?:live|test)\.adyen\.com|(?:sandbox\.)?web\.squarecdn\.com|js\.squareup\.com|cdn\.paddle\.com|assets\.lemonsqueezy\.com|checkout\.razorpay\.com|js\.mollie\.com)\//i;
/** A third-party <script src> on a payment page without an integrity (SRI) pin. */
function findUnpinnedThirdPartyScript(src: string): number {
    const tag = /<script\b[^>]*\bsrc=["'](https?:\/\/[^"']+)["'][^>]*>/g;
    let m: RegExpExecArray | null;
    while ((m = tag.exec(src))) {
        if (/\bintegrity=/.test(m[0]) || PAYMENT_SDK_HOST.test(m[1])) continue;
        return lineAt(src, m.index);
    }
    return -1;
}
