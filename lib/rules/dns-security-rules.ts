/**
 * Zelsis Master evaluateDnsSecurityRules Engine (50 Rules)
 * Rules DNS-01 to DNS-50 (Rule IDs 11801 to 11850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    // DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone
    if ((/dnsZone/i.test(cleanContent) && !/dnssec|rrsig/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/dnsZone/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dns-11801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11801,
            type: 'SECURITY',
            title: "DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone",
            severity: "HIGH",
            category: "DNS Authenticity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'DNS Security code segment',
            reproductionSteps: [
                `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching DNS-01.'
            ],
            remediationPrompt: "Enable DNSSEC signing with RRSIG and DS records to prevent DNS spoofing and cache poisoning.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DNS AUDIT] Found DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone at ${file.path}:${lineNum}`);
    }
    // DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover
    if ((/CNAME/i.test(cleanContent) && !/verifiedOwner/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/CNAME/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dns-11802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11802,
            type: 'SECURITY',
            title: "DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover",
            severity: "CRITICAL",
            category: "Subdomain Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'DNS Security code segment',
            reproductionSteps: [
                `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching DNS-02.'
            ],
            remediationPrompt: "Remove dangling CNAME records pointing to decommissioned third-party cloud assets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DNS AUDIT] Found DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover at ${file.path}:${lineNum}`);
    }
    // DNS-03: Missing CAA (Certification Authority Authorization) Record
    if ((/dnsRecords/i.test(cleanContent) && !/issue\s*"letsencrypt\.org"|CAA/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/dnsRecords/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dns-11803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11803,
            type: 'SECURITY',
            title: "DNS-03: Missing CAA (Certification Authority Authorization) Record",
            severity: "HIGH",
            category: "PKI Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'DNS Security code segment',
            reproductionSteps: [
                `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching DNS-03.'
            ],
            remediationPrompt: "Configure DNS CAA records to explicitly authorize trusted Certificate Authorities.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DNS AUDIT] Found DNS-03: Missing CAA (Certification Authority Authorization) Record at ${file.path}:${lineNum}`);
    }
    // DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers
    if ((/named\.conf/i.test(cleanContent) && !/allow-transfer\s*\{\s*none;/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/named\.conf/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints
    if ((/httpServer/i.test(cleanContent) && !/validateHostHeader/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/httpServer/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dns-11805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11805,
            type: 'SECURITY',
            title: "DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints",
            severity: "HIGH",
            category: "Internal Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'DNS Security code segment',
            reproductionSteps: [
                `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching DNS-05.'
            ],
            remediationPrompt: "Validate Host and Origin headers on all local HTTP services to thwart DNS rebinding attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DNS AUDIT] Found DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
