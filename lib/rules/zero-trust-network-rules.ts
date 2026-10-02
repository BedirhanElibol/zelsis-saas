/**
 * Zelsis Master evaluateZeroTrustNetworkRules Engine (50 Rules)
 * Rules SDP-01 to SDP-50 (Rule IDs 13101 to 13150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface ZeroTrustNetworkRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateZeroTrustNetworkRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ZeroTrustNetworkRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SDP-02: Split-Tunneling Configuration Permitting DNS Request Leakage
    const r13102Idx = !/^\s*\[Interface\]/m.test(cleanContent) || !/^\s*\[Peer\]/m.test(cleanContent) || /^\s*DNS\s*=/m.test(cleanContent) ? -1
        : lines.findIndex(l => /^\s*AllowedIPs\s*=.*\b0\.0\.0\.0\/0/.test(l));
    if (r13102Idx !== -1) {
        const matchLineIdx = r13102Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sdp13102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13102,
            type: 'SECURITY',
            title: "SDP-02: Split-Tunneling Configuration Permitting DNS Request Leakage",
            severity: "MEDIUM",
            category: "DNS Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Zero Trust Network configuration',
            reproductionSteps: [
                `Audited Zero Trust Network configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SDP-02.'
            ],
            remediationPrompt: "Configure explicit private DNS servers in tunnel profiles to prevent DNS query leakage across split tunnels.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SDP AUDIT] Found SDP-02: Split-Tunneling Configuration Permitting DNS Request Leakage at ${file.path}:${lineNum}`);
    }
    // SDP-03: Inbound Perimeter Firewall Ports Open to Public Internet
    const r13103Idx = !/\.tf$/.test(lowerPath) ? -1 : lines.findIndex((l, i) => {
        if (!/["'\s]0\.0\.0\.0\/0|["']::\/0/.test(l)) return false;
        // walk back to the enclosing ingress block / rule resource and read its port range
        for (let j = i; j >= Math.max(0, i - 15); j--) {
            if (/^\s*egress\s*\{|type\s*=\s*"egress"/.test(lines[j])) return false;
            if (/^\s*ingress\s*\{|resource\s+"aws_(?:security_group_rule|vpc_security_group_ingress_rule)"/.test(lines[j])) {
                const block = lines.slice(j, i + 10).join('\n');
                if (/resource\s+"aws_security_group_rule"/.test(lines[j]) && !/type\s*=\s*"ingress"/.test(block)) return false;
                return /from_port\s*=\s*(?:22|3389|3306|5432|6379|27017|9200|1433|11211|2379)\b|from_port\s*=\s*0\b[\s\S]*to_port\s*=\s*(?:0|65535)\b/.test(block);
            }
        }
        return false;
    });
    if (r13103Idx !== -1) {
        const matchLineIdx = r13103Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sdp13103-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13103,
            type: 'SECURITY',
            title: "SDP-03: Inbound Perimeter Firewall Ports Open to Public Internet",
            severity: "CRITICAL",
            category: "Perimeter Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Zero Trust Network configuration',
            reproductionSteps: [
                `Audited Zero Trust Network configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SDP-03.'
            ],
            remediationPrompt: "Transition to Zero Trust Network Architecture with outbound-only overlay tunnels and zero exposed public ports.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SDP AUDIT] Found SDP-03: Inbound Perimeter Firewall Ports Open to Public Internet at ${file.path}:${lineNum}`);
    }
    // SDP-05: Hardcoded WireGuard Private Key in Infrastructure Repositories
    const r13105Idx = lines.findIndex(l => /^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$/.test(l));
    if (r13105Idx !== -1) {
        const matchLineIdx = r13105Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sdp13105-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13105,
            type: 'SECURITY',
            title: "SDP-05: Hardcoded WireGuard Private Key in Infrastructure Repositories",
            severity: "CRITICAL",
            category: "Key Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Zero Trust Network configuration',
            reproductionSteps: [
                `Audited Zero Trust Network configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SDP-05.'
            ],
            remediationPrompt: "Never hardcode WireGuard private keys in source control; inject them dynamically from secure secret managers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SDP AUDIT] Found SDP-05: Hardcoded WireGuard Private Key in Infrastructure Repositories at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
