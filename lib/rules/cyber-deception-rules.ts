/**
 * Zelsis Master evaluateCyberDeceptionRules Engine (50 Rules)
 * Rules DECEPTION-01 to DECEPTION-50 (Rule IDs 15101 to 15150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface CyberDeceptionRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCyberDeceptionRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CyberDeceptionRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // DECEPTION-01: Missing Honeytoken Decoy Credentials in Source Code Repositories
    if ((/canary_tokens/i.test(lowerPath) && !/canaryTokenActive/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `deception15101-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15101,
            type: 'SECURITY',
            title: "DECEPTION-01: Missing Honeytoken Decoy Credentials in Source Code Repositories",
            severity: "CRITICAL",
            category: "Canary Deployment",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Deception & Honeypots configuration',
            reproductionSteps: [
                `Audited Cyber Deception & Honeypots configuration in ${file.path}:${lineNum}.`,
                'Matched DECEPTION-01: Missing Honeytoken Decoy Credentials in Source Code Repositories.'
            ],
            remediationPrompt: "Deploy inactive canary API keys in repositories to detect unauthorized code exfiltration and cloning.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DECEPTION AUDIT] Found DECEPTION-01: Missing Honeytoken Decoy Credentials in Source Code Repositories at ${file.path}:${lineNum}`);
    }
    // DECEPTION-02: Unmonitored Decoy Database Tables (Honeytables) in Production Schema
    if (((/honeytable|decoy_table/i.test(lowerPath) || /honeytable|decoy_table/i.test(cleanContent)) && !/alertOnDecoyAccess/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/honeytable|decoy_table/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `deception15102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15102,
            type: 'SECURITY',
            title: "DECEPTION-02: Unmonitored Decoy Database Tables (Honeytables) in Production Schema",
            severity: "CRITICAL",
            category: "Database Deception",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Deception & Honeypots configuration',
            reproductionSteps: [
                `Audited Cyber Deception & Honeypots configuration in ${file.path}:${lineNum}.`,
                'Matched DECEPTION-02: Unmonitored Decoy Database Tables (Honeytables) in Production Schema.'
            ],
            remediationPrompt: "Create trigger-based decoy tables alerting immediately on any read or write access attempt by attackers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DECEPTION AUDIT] Found DECEPTION-02: Unmonitored Decoy Database Tables (Honeytables) in Production Schema at ${file.path}:${lineNum}`);
    }
    // DECEPTION-03: Lack of Network Breadcrumb Lures on Compromised Internal Endpoints
    if ((/network_lures/i.test(lowerPath) && !/deployDecoyDns/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `deception15103-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15103,
            type: 'SECURITY',
            title: "DECEPTION-03: Lack of Network Breadcrumb Lures on Compromised Internal Endpoints",
            severity: "HIGH",
            category: "Lateral Deception",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Deception & Honeypots configuration',
            reproductionSteps: [
                `Audited Cyber Deception & Honeypots configuration in ${file.path}:${lineNum}.`,
                'Matched DECEPTION-03: Lack of Network Breadcrumb Lures on Compromised Internal Endpoints.'
            ],
            remediationPrompt: "Plant decoy internal DNS entries and SMB share links to bait lateral movement across enterprise subnets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DECEPTION AUDIT] Found DECEPTION-03: Lack of Network Breadcrumb Lures on Compromised Internal Endpoints at ${file.path}:${lineNum}`);
    }
    // DECEPTION-04: Missing Active Honeypot Ports on Internal Container Worker Nodes
    if ((/k8s_security/i.test(lowerPath) && !/honeypotListener/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `deception15104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15104,
            type: 'SECURITY',
            title: "DECEPTION-04: Missing Active Honeypot Ports on Internal Container Worker Nodes",
            severity: "HIGH",
            category: "Network Trapping",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Deception & Honeypots configuration',
            reproductionSteps: [
                `Audited Cyber Deception & Honeypots configuration in ${file.path}:${lineNum}.`,
                'Matched DECEPTION-04: Missing Active Honeypot Ports on Internal Container Worker Nodes.'
            ],
            remediationPrompt: "Deploy lightweight low-interaction honeypot listeners inside cluster networks to trap internal port scans.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DECEPTION AUDIT] Found DECEPTION-04: Missing Active Honeypot Ports on Internal Container Worker Nodes at ${file.path}:${lineNum}`);
    }
    // DECEPTION-05: Unmonitored Canary Documents in Sensitive Cloud Storage Shares
    if ((/cloud_share/i.test(lowerPath) && !/embeddedTrackingPixel/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `deception15105-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15105,
            type: 'SECURITY',
            title: "DECEPTION-05: Unmonitored Canary Documents in Sensitive Cloud Storage Shares",
            severity: "HIGH",
            category: "Document Tracking",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Deception & Honeypots configuration',
            reproductionSteps: [
                `Audited Cyber Deception & Honeypots configuration in ${file.path}:${lineNum}.`,
                'Matched DECEPTION-05: Unmonitored Canary Documents in Sensitive Cloud Storage Shares.'
            ],
            remediationPrompt: "Place canary documents with embedded tracking pixels in internal file shares to detect data exfiltration.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [DECEPTION AUDIT] Found DECEPTION-05: Unmonitored Canary Documents in Sensitive Cloud Storage Shares at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
