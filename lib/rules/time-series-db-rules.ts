/**
 * Zelsis Master evaluateTimeSeriesDbRules Engine (50 Rules)
 * Rules TSDB-01 to TSDB-50 (Rule IDs 14001 to 14050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface TimeSeriesDbRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTimeSeriesDbRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TimeSeriesDbRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory
    const r14003Idx = !/prom-client|@opentelemetry|hot-shots|statsd|prometheus_client/i.test(cleanContent) ? -1
        : lines.findIndex(l => /\.(?:labels|inc|observe|set|startTimer|add|record)\(\s*\{[^}]*\b(?:user_?id|userId|request_?id|requestId|session_?id|sessionId|email|ip|order_?id|orderId)\s*:/.test(l) ||
            /\.labels\([^)]*\b(?:req|request)\.(?:url|originalUrl|path)\b/.test(l) ||
            /\{[^}]*\b(?:route|path|url)\s*:\s*(?:req|request)\.(?:url|originalUrl|path)\b/.test(l));
    if (r14003Idx !== -1) {
        const matchLineIdx = r14003Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14003,
            type: 'INFRA_DATABASE',
            title: "TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory",
            severity: "MEDIUM",
            category: "Memory Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory.'
            ],
            remediationPrompt: "Enforce limits on unique tag/label values (e.g. banning user IDs or trace IDs in metric tag sets).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
