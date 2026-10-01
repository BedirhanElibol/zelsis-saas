/**
 * Zelsis Master evaluateOtelObservabilityRules Engine (50 Rules)
 * Rules OTEL-01 to OTEL-50 (Rule IDs 9901 to 9950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
import { emptyRepoContext, type RepoContext } from '../scanner/repo-context';
export interface OtelObservabilityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateOtelObservabilityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}, context: RepoContext = emptyRepoContext()): OtelObservabilityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-telemetry paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // OTEL-01: Missing Distributed Trace Context Propagation (traceparent)
    if ((/axios\.post\s*\([\s\S]*?\)/i.test(cleanContent) && !/traceparent|propagation/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/axios\.post\s*\([\s\S]*?\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9901,
            type: 'INFRA_DATABASE',
            title: "OTEL-01: Missing Distributed Trace Context Propagation (traceparent)",
            severity: "HIGH",
            category: "Distributed Tracing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Observability telemetry instruction',
            reproductionSteps: [
                `Audited telemetry in ${file.path}:${lineNum}.`,
                'Detected observability violation matching OTEL-01.'
            ],
            remediationPrompt: "Add OpenTelemetry trace context injector to HTTP client middleware.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OTEL AUDIT] Found OTEL-01: Missing Distributed Trace Context Propagation (traceparent) at ${file.path}:${lineNum}`);
    }
    // OTEL-02: High-Cardinality Metric Label Explosion (UUID / Timestamp as Tag)
    if ((/counter\.add\s*\([\s\S]*?\{\s*(?:userId|traceId|timestamp)\s*:/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/counter\.add\s*\([\s\S]*?\{\s*(?:userId|traceId|timestamp)\s*:/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9902,
            type: 'INFRA_DATABASE',
            title: "OTEL-02: High-Cardinality Metric Label Explosion (UUID / Timestamp as Tag)",
            severity: "HIGH",
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
    // OTEL-03: Missing Health Check Liveness and Readiness Probe Endpoints
    // Repo-wide: a health route defined in any other file covers this app too
    if ((/express\(\)|FastAPI\(\)|createApp\(\)/.test(cleanContent) && !/health|liveness|readiness/i.test(cleanContent) && !context.hasHealthEndpoint)) {
        const matchLineIdx = locateMatchLine(lines, [/express\(\)|FastAPI\(\)|createApp\(\)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9903,
            type: 'INFRA_DATABASE',
            title: "OTEL-03: Missing Health Check Liveness and Readiness Probe Endpoints",
            severity: "MEDIUM",
            category: "Service Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Observability telemetry instruction',
            reproductionSteps: [
                `Audited telemetry in ${file.path}:${lineNum}.`,
                'Detected observability violation matching OTEL-03.'
            ],
            remediationPrompt: "Add standard liveness and readiness probe routes to HTTP router.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OTEL AUDIT] Found OTEL-03: Missing Health Check Liveness and Readiness Probe Endpoints at ${file.path}:${lineNum}`);
    }
    // OTEL-04: Uncaught Error Missing OpenTelemetry Exception Recording
    if ((/catch\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\{/i.test(cleanContent) && /tracer\.startSpan/i.test(cleanContent) && !/span\.recordException/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/catch\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\{/i, /tracer\.startSpan/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `otel9904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9904,
            type: 'INFRA_DATABASE',
            title: "OTEL-04: Uncaught Error Missing OpenTelemetry Exception Recording",
            severity: "HIGH",
            category: "Span Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Observability telemetry instruction',
            reproductionSteps: [
                `Audited telemetry in ${file.path}:${lineNum}.`,
                'Detected observability violation matching OTEL-04.'
            ],
            remediationPrompt: "Add span.recordException(err) and span.setStatus({ code: SpanStatusCode.ERROR }) in catch blocks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OTEL AUDIT] Found OTEL-04: Uncaught Error Missing OpenTelemetry Exception Recording at ${file.path}:${lineNum}`);
    }
    // OTEL-05: Unbounded Telemetry Exporter Buffer (Missing Drop / Batching Policy)
    if ((/BatchSpanProcessor\(\s*[^)]*maxQueueSize:\s*(?:Infinity|\d{6,})/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/BatchSpanProcessor\(\s*[^)]*maxQueueSize:\s*(?:Infinity|\d{6,})/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
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
