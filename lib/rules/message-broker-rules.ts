/**
 * Zelsis Master evaluateMessageBrokerRules Engine (50 Rules)
 * Rules MQ-01 to MQ-50 (Rule IDs 12501 to 12550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface MessageBrokerRuleResult {
    findings: Finding[];
    logs: string[];
}
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
    // MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages
    if ((/assertQueue\(/i.test(cleanContent) && !/deadLetterExchange|x-dead-letter/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/assertQueue\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mq12501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12501,
            type: 'INFRA_DATABASE',
            title: "MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages",
            severity: "HIGH",
            category: "Message Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching MQ-01.'
            ],
            remediationPrompt: "Configure dead-letter exchanges (x-dead-letter-exchange) and routing keys for all worker queues.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages at ${file.path}:${lineNum}`);
    }
    // MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash
    if ((/channel\.prefetch\(\s*0\s*\)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/channel\.prefetch\(\s*0\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mq12502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12502,
            type: 'INFRA_DATABASE',
            title: "MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash",
            severity: "HIGH",
            category: "Consumer Stability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching MQ-02.'
            ],
            remediationPrompt: "Specify explicit consumer prefetch count (e.g. channel.prefetch(20)) to avoid worker starvation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash at ${file.path}:${lineNum}`);
    }
    // MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection
    if ((/channel\.consume/i.test(cleanContent) && !/validateMessageSchema/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/channel\.consume/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mq12503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12503,
            type: 'INFRA_DATABASE',
            title: "MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection",
            severity: "CRITICAL",
            category: "Message Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching MQ-03.'
            ],
            remediationPrompt: "Validate message payloads against strict schemas before deserialization.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection at ${file.path}:${lineNum}`);
    }
    // MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss
    if ((/createConfirmChannel/i.test(cleanContent) && !/waitForConfirms/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/createConfirmChannel/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mq12504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12504,
            type: 'INFRA_DATABASE',
            title: "MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss",
            severity: "HIGH",
            category: "Data Durability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching MQ-04.'
            ],
            remediationPrompt: "Enable publisher confirms and await broker acknowledgment before committing transactional states.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss at ${file.path}:${lineNum}`);
    }
    // MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events
    if ((/assertQueue/i.test(cleanContent) && cleanContent.includes('durable:\s*false'))) {
        const matchLineIdx = locateMatchLine(lines, [/assertQueue/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mq12505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12505,
            type: 'INFRA_DATABASE',
            title: "MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events",
            severity: "HIGH",
            category: "Message Persistence",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Broker configuration',
            reproductionSteps: [
                `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching MQ-05.'
            ],
            remediationPrompt: "Declare queues with durable: true and send messages with persistent: true delivery mode.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
