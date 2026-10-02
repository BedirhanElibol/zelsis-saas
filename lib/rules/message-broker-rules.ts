/**
 * Zelsis Master evaluateMessageBrokerRules Engine
 * MQ-02 (12502), MQ-03 (12503), MQ-04 (12504).
 * Removed as unsound (ids never reused): 12501 queue declared without a dead-letter exchange (many queues
 * legitimately need none: RPC replies, exclusive / transient queues), 12505 non-durable queue (the check never
 * matched, and whether an event is "critical" is not visible in code).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface MessageBrokerRuleResult {
    findings: Finding[];
    logs: string[];
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
export function evaluateMessageBrokerRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): MessageBrokerRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // MQ-02: explicit unlimited prefetch (amqplib prefetch(0) / pika basic_qos(prefetch_count=0)).
    const unboundedPrefetch = /\.prefetch\(\s*0\s*[,)]|\bbasic_qos\s*\([^)]*\bprefetch_count\s*=\s*0\b/.exec(cleanContent);
    if (unboundedPrefetch) {
        const matchLineIdx = lineAt(cleanContent, unboundedPrefetch.index);
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `mq12502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12502,
            type: 'INFRA_DATABASE',
            title: "MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash",
            severity: "MEDIUM",
            category: "Consumer Stability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Prefetch count 0 means "unlimited": the broker pushes the whole backlog into this consumer\'s memory at once.'
            ],
            remediationPrompt: "Specify explicit consumer prefetch count (e.g. channel.prefetch(20)) to avoid worker starvation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash at ${file.path}:${lineNum}`);
    }
    // MQ-03: a queue consumer that deserializes message bodies with an object-instantiating deserializer
    // (pickle / marshal / node-serialize / yaml full loader): any producer on the queue gets code execution.
    const isConsumer = /\b(?:channel|ch)\.consume\s*\(|\bbasic_consume\s*\(|\bon_message\b|\.subscribe\s*\(|\beachMessage\b|\bKafkaConsumer\b|\bConsumer\s*\(/.test(cleanContent);
    const unsafeDeserialize = /\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(|\bunserialize\s*\(|\byaml\.(?:unsafe_load|load)\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|CSafe)Loader)|\bjsonpickle\.decode\s*\(/;
    const unsafeMatch = isConsumer ? unsafeDeserialize.exec(cleanContent) : null;
    if (unsafeMatch) {
        const matchLineIdx = lineAt(cleanContent, unsafeMatch.index);
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `mq12503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12503,
            type: 'INFRA_DATABASE',
            title: "MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection",
            severity: "CRITICAL",
            category: "Payload Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker consumer in ${file.path}:${lineNum}.`,
                'Message bodies are deserialized with a format that instantiates arbitrary objects; anyone able to publish to the queue can execute code in the consumer.'
            ],
            remediationPrompt: "Encode messages as JSON (or protobuf / Avro) and validate them against a schema (zod / pydantic) before use; never pickle / unserialize broker payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection at ${file.path}:${lineNum}`);
    }
    // MQ-04: a confirm channel whose confirms are never consumed (no waitForConfirms, no publish callback).
    const confirmChannel = /\bcreateConfirmChannel\s*\(/.exec(cleanContent);
    const publishCalls = cleanContent.match(/\.(?:publish|sendToQueue)\s*\([^;]*/g) || [];
    const confirmsConsumed = /\bwaitForConfirms\s*\(/.test(cleanContent) || publishCalls.some(c => /=>|\bfunction\b/.test(c));
    if (confirmChannel && publishCalls.length > 0 && !confirmsConsumed) {
        const matchLineIdx = lineAt(cleanContent, confirmChannel.index);
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `mq12504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12504,
            type: 'INFRA_DATABASE',
            title: "MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss",
            severity: "MEDIUM",
            category: "Message Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker publisher in ${file.path}:${lineNum}.`,
                'A confirm channel is opened but no publish waits for or handles the broker confirm, so nacked / dropped messages are silently lost.'
            ],
            remediationPrompt: "Await channel.waitForConfirms() after publishing (or pass a callback to publish / sendToQueue) and retry or fail on a nack.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
