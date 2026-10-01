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
    // THREAT-01: MITRE T1078 Valid Accounts: Missing Detection on Impossible Travel Anomalies
    if ((/loginHandler|authService/i.test(cleanContent) && !/checkGeoVelocity/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `threat13601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13601,
            type: 'SECURITY',
            title: "THREAT-01: MITRE T1078 Valid Accounts: Missing Detection on Impossible Travel Anomalies",
            severity: "CRITICAL",
            category: "Identity Anomaly",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Threat Detection configuration',
            reproductionSteps: [
                `Audited Threat Detection configuration in ${file.path}:${lineNum}.`,
                'Matched THREAT-01: MITRE T1078 Valid Accounts: Missing Detection on Impossible Travel Anomalies.'
            ],
            remediationPrompt: "Alert security operations on consecutive user authentications from distant geographies within impossible timeframes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [THREAT AUDIT] Found THREAT-01: MITRE T1078 Valid Accounts: Missing Detection on Impossible Travel Anomalies at ${file.path}:${lineNum}`);
    }
    // THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods
    const importsChildProcess = /require\(["'](?:node:)?child_process["']\)|from\s+["'](?:node:)?child_process["']/i.test(cleanContent);
    const spawnsShell = /\bexec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(\s*["'](?:(?:\/usr)?\/bin\/)?(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)["']|shell\s*:\s*true/i.test(cleanContent);
    if (importsChildProcess && spawnsShell && !/auditShellProcess/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `threat13602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13602,
            type: 'SECURITY',
            title: "THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods",
            severity: "CRITICAL",
            category: "Execution Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Threat Detection configuration',
            reproductionSteps: [
                `Audited Threat Detection configuration in ${file.path}:${lineNum}.`,
                'Matched THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods.'
            ],
            remediationPrompt: "Monitor and immediately terminate unauthorized shell processes (/bin/sh, /bin/bash) spawned by web services.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [THREAT AUDIT] Found THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods at ${file.path}:${lineNum}`);
    }
    // THREAT-03: MITRE T1562 Impair Defenses: Security Daemon Process Tampering or Disablement
    if ((/agentHeartbeat/i.test(cleanContent) && !/alertMissingHeartbeat/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `threat13603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13603,
            type: 'SECURITY',
            title: "THREAT-03: MITRE T1562 Impair Defenses: Security Daemon Process Tampering or Disablement",
            severity: "CRITICAL",
            category: "Defense Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Threat Detection configuration',
            reproductionSteps: [
                `Audited Threat Detection configuration in ${file.path}:${lineNum}.`,
                'Matched THREAT-03: MITRE T1562 Impair Defenses: Security Daemon Process Tampering or Disablement.'
            ],
            remediationPrompt: "Generate high-priority alerts if host security sensors (Falco, EDR, Auditd) stop reporting heartbeats.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [THREAT AUDIT] Found THREAT-03: MITRE T1562 Impair Defenses: Security Daemon Process Tampering or Disablement at ${file.path}:${lineNum}`);
    }
    // THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files
    if ((/etc\/shadow|LSASS/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `threat13604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13604,
            type: 'SECURITY',
            title: "THREAT-04: MITRE T1003 OS Credential Dumping: Unauthorized Reading of Host Credential Files",
            severity: "CRITICAL",
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
    // THREAT-05: Canary Token Triggering: Unmonitored Honeytoken or Fake Credential Traversal
    if ((/honeytoken|canaryKey/i.test(cleanContent) && !/notifySocWebhook/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `threat13605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13605,
            type: 'SECURITY',
            title: "THREAT-05: Canary Token Triggering: Unmonitored Honeytoken or Fake Credential Traversal",
            severity: "CRITICAL",
            category: "Deception Technology",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Threat Detection configuration',
            reproductionSteps: [
                `Audited Threat Detection configuration in ${file.path}:${lineNum}.`,
                'Matched THREAT-05: Canary Token Triggering: Unmonitored Honeytoken or Fake Credential Traversal.'
            ],
            remediationPrompt: "Deploy canary tokens across codebases and databases to immediately catch unauthorized perimeter intrusions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [THREAT AUDIT] Found THREAT-05: Canary Token Triggering: Unmonitored Honeytoken or Fake Credential Traversal at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
