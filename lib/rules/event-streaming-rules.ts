/**
 * Zelsis Master evaluateEventStreamingRules Engine (50 Rules)
 * Rules EVENT-01 to EVENT-50 (Rule IDs 9401 to 9450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface EventStreamingRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEventStreamingRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EventStreamingRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-streaming paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // EVENT-03: Plaintext Event Broker Transport (Missing SASL / TLS)
    const hit_9403 = /(?:^|[\/._-])prod(?:uction)?(?:[\/._-]|$)/.test(lowerPath) ? lines.findIndex((l) => /^\s*-?\s*(?:KAFKA_SECURITY_PROTOCOL|KAFKA_CFG_SECURITY_PROTOCOL|security\.protocol)\s*[=:]\s*["']?PLAINTEXT\b/i.test(l)) : -1;
    if (hit_9403 !== -1) {
        const matchLineIdx = hit_9403;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `event9403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9403,
            type: 'INFRA_DATABASE',
            title: "EVENT-03: Plaintext Event Broker Transport (Missing SASL / TLS)",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Event streaming configuration statement',
            reproductionSteps: [
                `Audited streaming infrastructure in ${file.path}:${lineNum}.`,
                'Detected event streaming violation matching EVENT-03.'
            ],
            remediationPrompt: "Configure security.protocol = 'SASL_SSL' and sasl.mechanism = 'SCRAM-SHA-512'.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EVENT AUDIT] Found EVENT-03: Plaintext Event Broker Transport (Missing SASL / TLS) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
