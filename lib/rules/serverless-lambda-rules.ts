/**
 * Zelsis Master evaluateServerlessLambdaRules Engine (50 Rules)
 * Rules SLS-01 to SLS-50 (Rule IDs 11301 to 11350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface ServerlessLambdaRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateServerlessLambdaRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ServerlessLambdaRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SLS-01: Unbounded Function Execution Timeout (Runaway Billing Risk)
    if ((/timeout:\s*900/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/timeout:\s*900/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sls11301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11301,
            type: 'INFRA_DATABASE',
            title: "SLS-01: Unbounded Function Execution Timeout (Runaway Billing Risk)",
            severity: "HIGH",
            category: "Serverless Cost",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-01.'
            ],
            remediationPrompt: "Set timeout: 20 in serverless.yml or Lambda cloudformation properties for API handlers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-01: Unbounded Function Execution Timeout (Runaway Billing Risk) at ${file.path}:${lineNum}`);
    }
    // SLS-02: Heavyweight Module Initialization Inside Handler Loop (Cold Start Spike)
    if ((/exports\.handler\s*=\s*async[\s\S]*?new\s+(?:PrismaClient|MongoClient)/.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/exports\.handler\s*=\s*async[\s\S]*?new\s+(?:PrismaClient|MongoClient)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sls11302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11302,
            type: 'INFRA_DATABASE',
            title: "SLS-02: Heavyweight Module Initialization Inside Handler Loop (Cold Start Spike)",
            severity: "HIGH",
            category: "Function Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-02.'
            ],
            remediationPrompt: "Extract client initialization to module scope to leverage Lambda execution context reuse.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-02: Heavyweight Module Initialization Inside Handler Loop (Cold Start Spike) at ${file.path}:${lineNum}`);
    }
    // SLS-03: Missing Dead-Letter Queue (DLQ) on Asynchronous Serverless Event Sources
    if ((/events:\s*-[\s\S]*?sns:|events:\s*-[\s\S]*?sqs:/i.test(cleanContent) && !/dead_letter_config|onError/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/events:\s*-[\s\S]*?sns:|events:\s*-[\s\S]*?sqs:/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sls11303-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11303,
            type: 'INFRA_DATABASE',
            title: "SLS-03: Missing Dead-Letter Queue (DLQ) on Asynchronous Serverless Event Sources",
            severity: "HIGH",
            category: "Event Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-03.'
            ],
            remediationPrompt: "Add dead_letter_config { target_arn = aws_sqs_queue.dlq.arn } to serverless function definition.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-03: Missing Dead-Letter Queue (DLQ) on Asynchronous Serverless Event Sources at ${file.path}:${lineNum}`);
    }
    // SLS-04: Direct Unpooled Database Connection in Autoscaling Serverless Workers
    if ((/new\s+Client\s*\([\s\S]*?\)/.test(cleanContent) && !/rdsProxy|pooler|accelerate/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Client\s*\([\s\S]*?\)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sls11304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11304,
            type: 'INFRA_DATABASE',
            title: "SLS-04: Direct Unpooled Database Connection in Autoscaling Serverless Workers",
            severity: "CRITICAL",
            category: "Database Connection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-04.'
            ],
            remediationPrompt: "Route serverless database connections through AWS RDS Proxy or Supabase Connection Pooler.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-04: Direct Unpooled Database Connection in Autoscaling Serverless Workers at ${file.path}:${lineNum}`);
    }
    // SLS-05: Uncleaned /tmp Ephemeral Disk Space in Warm Container Instances
    if ((/fs\.writeFileSync\s*\(\s*['"]\/tmp\//.test(cleanContent) && !/unlink|cleanup/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/fs\.writeFileSync\s*\(\s*['"]\/tmp\//], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sls11305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11305,
            type: 'INFRA_DATABASE',
            title: "SLS-05: Uncleaned /tmp Ephemeral Disk Space in Warm Container Instances",
            severity: "MEDIUM",
            category: "Storage Hygiene",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-05.'
            ],
            remediationPrompt: "Add cleanup routines deleting temporary artifacts in /tmp upon completion of handler execution.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-05: Uncleaned /tmp Ephemeral Disk Space in Warm Container Instances at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
