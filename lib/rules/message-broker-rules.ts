/**
 * Zelsis Master evaluateMessageBrokerRules Engine
 * MQ-02 (12502), MQ-03 (12503), MQ-04 (12504), MQ-06 (12506).
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
    // MQ-06: a failed message is put straight back on the queue from an error handler. requeue defaults to true
    // for amqplib nack()/reject() and pika basic_nack()/basic_reject(), and a dead-letter exchange only applies when
    // requeue is false, so a message that always fails is redelivered forever. Code that looks at redelivery or a
    // retry counter decides when to stop, so it stays quiet.
    const countsRetries = /\bredelivered\b|x-death|x-retry|retry[_-]?count|retryCount|delivery_count|deliveryCount/i.test(cleanContent);
    if (isConsumer && !countsRetries) {
        const requeueForever = /\b(?!Promise\b)\w+\s*\.\s*(?:nack\s*\(\s*\w+(?:\.\w+)*\s*(?:,\s*(?:true|false)\s*,\s*true\s*)?\)|reject\s*\(\s*\w+(?:\.\w+)*\s*(?:,\s*true\s*)?\))|\bbasic_(?:nack|reject)\s*\((?![^)]*\brequeue\s*=\s*False)[^)]*\)/g;
        for (const m of cleanContent.matchAll(requeueForever)) {
            // Only inside an error handler: catch (...) { ... } in JS, except ...: in Python
            const before = cleanContent.slice(Math.max(0, m.index! - 400), m.index!);
            if (!/\bcatch\s*(?:\([^)]*\))?\s*\{[^}]*$|\bexcept\b[^\n]*:\s*\n(?:[^\n]*\n)*?[^\n]*$/.test(before)) continue;
            const matchLineIdx = lineAt(cleanContent, m.index!);
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `mq12506-${Date.now()}-${findingCounter.count++}`,
                ruleId: 12506,
                type: 'INFRA_DATABASE',
                title: "MQ-06: Failed Message Is Requeued Forever From the Error Handler",
                severity: "HIGH",
                category: "Consumer Stability",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: lines[matchLineIdx] || m[0],
                reproductionSteps: [
                    `Followed the consumer error path in ${file.path}:${lineNum}.`,
                    'nack / reject requeue the message by default. A message that always fails (bad payload, missing record) comes straight back, fails again and blocks the consumer in a loop; a dead-letter exchange is skipped because the message is requeued, not rejected.'
                ],
                remediationPrompt: "Pass requeue=false (channel.nack(msg, false, false) / basic_nack(delivery_tag, requeue=False)) and bind the queue to a dead-letter exchange, or requeue only when !msg.fields.redelivered.",
                status: 'OPEN',
                falsePositive: false
            });
            logs.push(`[${ts}] [MQ AUDIT] Found MQ-06: Failed Message Is Requeued Forever From the Error Handler at ${file.path}:${lineNum}`);
            break;
        }
    }
    return { findings, logs };
}
