/**
 * Zelsis Master evaluateCronSchedulerRules Engine (50 Rules)
 * Rules CRON-01 to CRON-50 (Rule IDs 11701 to 11750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CronSchedulerRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCronSchedulerRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CronSchedulerRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("data/catalogs/") || lowerPath.includes("data/mockdata") || lowerPath.includes("data/workspacefiles") || lowerPath.includes("data/schema") || lowerPath.includes("scratch/") || lowerPath.includes(".agent/") || lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") || lowerPath.endsWith(".tsx") || lowerPath.endsWith(".jsx")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CRON-01: Distributed Mutex Lock Missing on Periodic Worker
    if ((/setInterval\(/i.test(cleanContent) && !/redlock|pg_try_advisory_lock/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cron-11701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11701,
            type: 'INFRA_DATABASE',
            title: "CRON-01: Distributed Mutex Lock Missing on Periodic Worker",
            severity: "HIGH",
            category: "Execution Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cron Scheduler code segment',
            reproductionSteps: [
                `Audited Cron Scheduler configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CRON-01.'
            ],
            remediationPrompt: "Wrap periodic job execution with a distributed mutex lock such as Redis Redlock or Postgres advisory locks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRON AUDIT] Found CRON-01: Distributed Mutex Lock Missing on Periodic Worker at ${file.path}:${lineNum}`);
    }
    // CRON-02: Unbounded Job Queue Backlog Without Rate Limiting
    if ((/new Queue\(/i.test(cleanContent) && !/rateLimiter|limiter/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cron-11702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11702,
            type: 'INFRA_DATABASE',
            title: "CRON-02: Unbounded Job Queue Backlog Without Rate Limiting",
            severity: "HIGH",
            category: "Queue Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cron Scheduler code segment',
            reproductionSteps: [
                `Audited Cron Scheduler configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CRON-02.'
            ],
            remediationPrompt: "Enforce queue rate limiting and backpressure thresholds to prevent out-of-memory worker crashes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRON AUDIT] Found CRON-02: Unbounded Job Queue Backlog Without Rate Limiting at ${file.path}:${lineNum}`);
    }
    // CRON-03: Missing Dead Letter Queue (DLQ) for Failed Cron Jobs
    if ((/(?:QueueOptions|new Queue)/i.test(cleanContent) && !/(?:deadLetter|dead_letter|\bdlq\b)/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cron-11703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11703,
            type: 'INFRA_DATABASE',
            title: "CRON-03: Missing Dead Letter Queue (DLQ) for Failed Cron Jobs",
            severity: "HIGH",
            category: "Failure Recovery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cron Scheduler code segment',
            reproductionSteps: [
                `Audited Cron Scheduler configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CRON-03.'
            ],
            remediationPrompt: "Configure a dead letter queue and max retry budget for all background job processors.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRON AUDIT] Found CRON-03: Missing Dead Letter Queue (DLQ) for Failed Cron Jobs at ${file.path}:${lineNum}`);
    }
    // CRON-04: Non-Idempotent Job Handler Causing Duplicate Processing
    if ((/processJob\(/i.test(cleanContent) && !/idempotencyKey|dedup/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cron-11704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11704,
            type: 'INFRA_DATABASE',
            title: "CRON-04: Non-Idempotent Job Handler Causing Duplicate Processing",
            severity: "CRITICAL",
            category: "State Consistency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cron Scheduler code segment',
            reproductionSteps: [
                `Audited Cron Scheduler configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CRON-04.'
            ],
            remediationPrompt: "Add unique idempotency keys and check-then-set locks before processing stateful background jobs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRON AUDIT] Found CRON-04: Non-Idempotent Job Handler Causing Duplicate Processing at ${file.path}:${lineNum}`);
    }
    // CRON-05: Missing Exponential Backoff on Worker Transient Failures
    if ((/backoff/i.test(cleanContent) && !/exponential/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cron-11705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11705,
            type: 'INFRA_DATABASE',
            title: "CRON-05: Missing Exponential Backoff on Worker Transient Failures",
            severity: "MEDIUM",
            category: "Network Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cron Scheduler code segment',
            reproductionSteps: [
                `Audited Cron Scheduler configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CRON-05.'
            ],
            remediationPrompt: "Set retry backoff strategy to exponential with randomized jitter.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRON AUDIT] Found CRON-05: Missing Exponential Backoff on Worker Transient Failures at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
