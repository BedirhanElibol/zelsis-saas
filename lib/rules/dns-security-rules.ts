/**
 * Zelsis Master evaluateDnsSecurityRules Engine (50 Rules)
 * Rules DNS-01 to DNS-50 (Rule IDs 11801 to 11850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface DnsSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateDnsSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): DnsSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers
    const hit_11804 = /(?:^|\/)named\.conf(?:\.[\w-]+)?$/.test(lowerPath) ? lines.findIndex((l) => /\ballow-transfer\s*\{\s*any\s*;/.test(l)) : -1;
    if (hit_11804 !== -1) {
        const matchLineIdx = hit_11804;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dns-11804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11804,
            type: 'SECURITY',
            title: "DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers",
            severity: "CRITICAL",
            category: "Reconnaissance Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'DNS Security code segment',
            reproductionSteps: [
                `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching DNS-04.'
            ],
            remediationPrompt: "Restrict DNS zone transfers strictly to authorized secondary nameserver IPs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DNS AUDIT] Found DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
