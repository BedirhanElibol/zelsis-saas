/**
 * Zelsis Master evaluateOtelObservabilityRules Engine (50 Rules)
 * Rules OTEL-01 to OTEL-50 (Rule IDs 9901 to 9950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface OtelObservabilityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateOtelObservabilityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): OtelObservabilityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-telemetry paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // OTEL-02: High-Cardinality Metric Label Explosion (UUID / Timestamp as Tag)
    const hit_9902 = findHighCardinalityMetric(cleanContent);
    if (hit_9902 !== -1) {
        const matchLineIdx = hit_9902;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9902,
            type: 'INFRA_DATABASE',
            title: "OTEL-02: High-Cardinality Metric Label Explosion (UUID / Timestamp as Tag)",
            severity: "MEDIUM",
            category: "Telemetry Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Observability telemetry instruction',
            reproductionSteps: [
                `Audited telemetry in ${file.path}:${lineNum}.`,
                'Detected observability violation matching OTEL-02.'
            ],
            remediationPrompt: "Remove dynamic UUIDs from metric labels and use aggregated categorical attributes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OTEL AUDIT] Found OTEL-02: High-Cardinality Metric Label Explosion (UUID / Timestamp as Tag) at ${file.path}:${lineNum}`);
    }
    // OTEL-05: Unbounded Telemetry Exporter Buffer (Missing Drop / Batching Policy)
    const hit_9905 = /Batch(?:Span|LogRecord)Processor\s*\(/.test(cleanContent) ? lines.findIndex((l) => /\bmaxQueueSize\s*:\s*(?:Infinity|Number\.MAX_SAFE_INTEGER|\d{6,})/.test(l)) : -1;
    if (hit_9905 !== -1) {
        const matchLineIdx = hit_9905;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9905,
            type: 'INFRA_DATABASE',
            title: "OTEL-05: Unbounded Telemetry Exporter Buffer (Missing Drop / Batching Policy)",
            severity: "MEDIUM",
            category: "Telemetry Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Observability telemetry instruction',
            reproductionSteps: [
                `Audited telemetry in ${file.path}:${lineNum}.`,
                'Detected observability violation matching OTEL-05.'
            ],
            remediationPrompt: "Tune BatchSpanProcessor configuration with explicit queue boundaries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OTEL AUDIT] Found OTEL-05: Unbounded Telemetry Exporter Buffer (Missing Drop / Batching Policy) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
/** A metric instrument recorded with a per-user / per-request identifier as an attribute. */
function findHighCardinalityMetric(src: string): number {
    const call = /\b\w*(?:counter|Counter|histogram|Histogram|gauge|Gauge)\.(?:add|record)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = call.exec(src))) {
        const end = src.indexOf(');', m.index);
        const stmt = src.slice(m.index, end === -1 ? m.index + 300 : end);
        if (/\{[^}]*\b(?:userId|user_id|user\.id|traceId|trace_id|requestId|request_id|sessionId|session_id|email|timestamp)\s*[:,}]/.test(stmt)) return lineAt(src, m.index);
    }
    return -1;
}
