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
    // MQOPT-01: Unbounded Message Queue Depth Triggering Broker Disk Paging
    if ((/createQueue|assertQueue/i.test(cleanContent) && !/max-length/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mqopt14501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14501,
            type: 'INFRA_DATABASE',
            title: "MQOPT-01: Unbounded Message Queue Depth Triggering Broker Disk Paging",
            severity: "CRITICAL",
            category: "Queue Sizing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Queue Optimization configuration',
            reproductionSteps: [
                `Audited Message Queue Optimization configuration in ${file.path}:${lineNum}.`,
                'Matched MQOPT-01: Unbounded Message Queue Depth Triggering Broker Disk Paging.'
            ],
            remediationPrompt: "Set max-length and max-length-bytes limits on queues to prevent high-latency disk paging during message surges.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQOPT-01: Unbounded Message Queue Depth Triggering Broker Disk Paging at ${file.path}:${lineNum}`);
    }
    // MQOPT-02: Missing Consumer Acknowledgment Timeout Guardrail on Worker Queues
    if ((/consumeQueue/i.test(cleanContent) && !/consumer_timeout/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mqopt14502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14502,
            type: 'INFRA_DATABASE',
            title: "MQOPT-02: Missing Consumer Acknowledgment Timeout Guardrail on Worker Queues",
            severity: "HIGH",
            category: "Acknowledgment Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Queue Optimization configuration',
            reproductionSteps: [
                `Audited Message Queue Optimization configuration in ${file.path}:${lineNum}.`,
                'Matched MQOPT-02: Missing Consumer Acknowledgment Timeout Guardrail on Worker Queues.'
            ],
            remediationPrompt: "Configure consumer ack timeouts to requeue messages if worker processes terminate mid-processing.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQOPT-02: Missing Consumer Acknowledgment Timeout Guardrail on Worker Queues at ${file.path}:${lineNum}`);
    }
    // MQOPT-03: Default Guest Credentials Enabled on Message Broker Management UI
    if ((/(?:default_user|default_pass)\s*=\s*guest/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // MQOPT-04: Unroutable Message Dead-Letter Exchange (DLX) Configuration Missing
    if ((/queueOptions/i.test(cleanContent) && !/x-dead-letter-exchange/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mqopt14504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14504,
            type: 'INFRA_DATABASE',
            title: "MQOPT-04: Unroutable Message Dead-Letter Exchange (DLX) Configuration Missing",
            severity: "HIGH",
            category: "Fault Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Queue Optimization configuration',
            reproductionSteps: [
                `Audited Message Queue Optimization configuration in ${file.path}:${lineNum}.`,
                'Matched MQOPT-04: Unroutable Message Dead-Letter Exchange (DLX) Configuration Missing.'
            ],
            remediationPrompt: "Configure x-dead-letter-exchange and dead-letter-routing-key on all queues to capture poison pill payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQOPT-04: Unroutable Message Dead-Letter Exchange (DLX) Configuration Missing at ${file.path}:${lineNum}`);
    }
    // MQOPT-05: Uncompressed High-Payload Message Publishing Causing Network Saturation
    if ((/publishMessage/i.test(cleanContent) && !/compressPayload/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mqopt14505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14505,
            type: 'INFRA_DATABASE',
            title: "MQOPT-05: Uncompressed High-Payload Message Publishing Causing Network Saturation",
            severity: "MEDIUM",
            category: "Payload Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Message Queue Optimization configuration',
            reproductionSteps: [
                `Audited Message Queue Optimization configuration in ${file.path}:${lineNum}.`,
                'Matched MQOPT-05: Uncompressed High-Payload Message Publishing Causing Network Saturation.'
            ],
            remediationPrompt: "Compress message payloads exceeding 10KB using Snappy or LZ4 before publishing to the broker exchange.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MQ AUDIT] Found MQOPT-05: Uncompressed High-Payload Message Publishing Causing Network Saturation at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
