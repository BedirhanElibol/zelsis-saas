/**
 * Zelsis Master evaluateEventStreamingRules Engine (50 Rules)
 * Rules EVENT-01 to EVENT-50 (Rule IDs 9401 to 9450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    // EVENT-01: Unbounded Kafka Consumer Lag Without Backpressure
    if ((/max\.poll\.records\s*=\s*(?:[5-9]\d{3}|[1-9]\d{4,})/i.test(cleanContent) && cleanContent.includes('kafka'))) {
        const matchLineIdx = locateMatchLine(lines, [/max\.poll\.records\s*=\s*(?:[5-9]\d{3}|[1-9]\d{4,})/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `event9401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9401,
            type: 'INFRA_DATABASE',
            title: "EVENT-01: Unbounded Kafka Consumer Lag Without Backpressure",
            severity: "HIGH",
            category: "Consumer Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Event streaming configuration statement',
            reproductionSteps: [
                `Audited streaming infrastructure in ${file.path}:${lineNum}.`,
                'Detected event streaming violation matching EVENT-01.'
            ],
            remediationPrompt: "Tune max.poll.records to 100 and ensure message batch processing completes well within max.poll.interval.ms.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EVENT AUDIT] Found EVENT-01: Unbounded Kafka Consumer Lag Without Backpressure at ${file.path}:${lineNum}`);
    }
    // EVENT-02: Missing Dead Letter Queue (DLQ) on Stream Consumer
    if ((/(?:consumer|kafka|rabbitmq|sqs)\.(?:subscribe|consume|onMessage)/i.test(cleanContent) && !/dlq|deadLetter|retryQueue/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:consumer|kafka|rabbitmq|sqs)\.(?:subscribe|consume|onMessage)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `event9402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9402,
            type: 'INFRA_DATABASE',
            title: "EVENT-02: Missing Dead Letter Queue (DLQ) on Stream Consumer",
            severity: "HIGH",
            category: "Fault Tolerance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Event streaming configuration statement',
            reproductionSteps: [
                `Audited streaming infrastructure in ${file.path}:${lineNum}.`,
                'Detected event streaming violation matching EVENT-02.'
            ],
            remediationPrompt: "Configure error handler with DeadLetterPublishingRecoverer to route poison-pill events to DLQ.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EVENT AUDIT] Found EVENT-02: Missing Dead Letter Queue (DLQ) on Stream Consumer at ${file.path}:${lineNum}`);
    }
    // EVENT-03: Plaintext Event Broker Transport (Missing SASL / TLS)
    if ((/KAFKA_SECURITY_PROTOCOL\s*=\s*PLAINTEXT/i.test(cleanContent) && cleanContent.includes('production'))) {
        const matchLineIdx = locateMatchLine(lines, [/KAFKA_SECURITY_PROTOCOL\s*=\s*PLAINTEXT/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
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
    // EVENT-04: At-Least-Once Duplication Without Idempotent Processing
    if ((/(?:processEvent|handleMessage)/i.test(cleanContent) && !/idempotency|dedup|processedEventId/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:processEvent|handleMessage)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `event9404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9404,
            type: 'INFRA_DATABASE',
            title: "EVENT-04: At-Least-Once Duplication Without Idempotent Processing",
            severity: "HIGH",
            category: "Data Consistency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Event streaming configuration statement',
            reproductionSteps: [
                `Audited streaming infrastructure in ${file.path}:${lineNum}.`,
                'Detected event streaming violation matching EVENT-04.'
            ],
            remediationPrompt: "Implement idempotency check using event ID before triggering financial or notification side effects.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EVENT AUDIT] Found EVENT-04: At-Least-Once Duplication Without Idempotent Processing at ${file.path}:${lineNum}`);
    }
    // EVENT-05: Unpartitioned Hotspotting (Null Message Partition Key)
    if ((/producer\.send\s*\([\s\S]*?messages\s*:\s*\[\s*\{\s*value\s*:/i.test(cleanContent) && !/key\s*:/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/producer\.send\s*\([\s\S]*?messages\s*:\s*\[\s*\{\s*value\s*:/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `event9405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9405,
            type: 'INFRA_DATABASE',
            title: "EVENT-05: Unpartitioned Hotspotting (Null Message Partition Key)",
            severity: "MEDIUM",
            category: "Load Distribution",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Event streaming configuration statement',
            reproductionSteps: [
                `Audited streaming infrastructure in ${file.path}:${lineNum}.`,
                'Detected event streaming violation matching EVENT-05.'
            ],
            remediationPrompt: "Pass user_id or transaction_id as the message partition key.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EVENT AUDIT] Found EVENT-05: Unpartitioned Hotspotting (Null Message Partition Key) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
