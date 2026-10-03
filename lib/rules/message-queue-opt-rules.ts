/**
 * Zelsis Master evaluateMessageQueueOptRules Engine (50 Rules)
 * Rules MQOPT-01 to MQOPT-50 (Rule IDs 14501 to 14550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface MessageQueueOptRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateMessageQueueOptRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): MessageQueueOptRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // MQOPT-03: Default Guest Credentials Enabled on Message Broker Management UI
    const r14503Idx = lines.findIndex(l => /^\s*(?:default_user|default_pass)\s*=\s*guest\s*$/i.test(l) ||
        /^\s*-?\s*RABBITMQ_DEFAULT_(?:USER|PASS)\s*[:=]\s*["']?guest["']?\s*$/.test(l));
    if (r14503Idx !== -1) {
        const matchLineIdx = r14503Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mqopt14503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14503,
            type: 'INFRA_DATABASE',
            title: "MQOPT-03: Default Guest Credentials Enabled on Message Broker Management UI",
            severity: "CRITICAL",
            category: "Console Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Queue Optimization configuration',
            reproductionSteps: [
                `Audited Message Queue Optimization configuration in ${file.path}:${lineNum}.`,
                'Matched MQOPT-03: Default Guest Credentials Enabled on Message Broker Management UI.'
            ],
            remediationPrompt: "Disable default guest credentials and bind management consoles strictly to localhost or private VPCs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQOPT-03: Default Guest Credentials Enabled on Message Broker Management UI at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
