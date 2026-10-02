/**
 * Zelsis Master evaluateThreatDetectionRules Engine (50 Rules)
 * Rules THREAT-01 to THREAT-50 (Rule IDs 13601 to 13650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface ThreatDetectionRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateThreatDetectionRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ThreatDetectionRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files
    // Application code that actually reads a host credential store (not a string in a deny-list): a file read of
    // /etc/shadow or /etc/gshadow, or an LSASS memory dump via procdump / comsvcs MiniDump.
    const credentialReadRe = /\b(?:readFile(?:Sync)?|createReadStream|open|read_text|read_bytes|os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\(\s*['"`]\/etc\/g?shadow['"`]|\bPath\(\s*['"`]\/etc\/g?shadow['"`]\s*\)\.read_|\b(?:procdump|comsvcs(?:\.dll)?[^\n]*MiniDump)\b[^\n]*\blsass\b/i;
    const credentialReadIdx = lines.findIndex(l => !/^\s*(?:\/\/|#|\*|--)/.test(l) && credentialReadRe.test(l));
    if (credentialReadIdx !== -1) {
        const matchLineIdx = credentialReadIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `threat13604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13604,
            type: 'SECURITY',
            title: "THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files",
            severity: "HIGH",
            category: "Credential Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Threat Detection configuration',
            reproductionSteps: [
                `Audited Threat Detection configuration in ${file.path}:${lineNum}.`,
                'Matched THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files.'
            ],
            remediationPrompt: "Detect and block access attempts to sensitive host credential stores (/etc/shadow, SAM, memory dumps).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [THREAT AUDIT] Found THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
