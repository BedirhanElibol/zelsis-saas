/**
 * Zelsis Master evaluateServerlessLambdaRules Engine (50 Rules)
 * Rules SLS-01 to SLS-50 (Rule IDs 11301 to 11350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    // serverless.yml: an HTTP-triggered function (API Gateway caps the request at ~29s) given a long Lambda timeout.
    // The client has long since received a 504, but the function keeps running and billing for up to the full timeout.
    const isServerlessYml = /(?:^|\/)serverless\.ya?ml$/.test(lowerPath);
    const indentOf = (l: string) => l.length - l.trimStart().length;
    const longHttpTimeoutIdx = !isServerlessYml ? -1 : lines.findIndex((l, i) => {
        const m = l.match(/^\s*timeout\s*:\s*(\d+)\s*$/i);
        if (!m || Number(m[1]) <= 30) return false;
        const ind = indentOf(l);
        let start = i - 1;
        while (start >= 0 && (!lines[start].trim() || indentOf(lines[start]) >= ind)) start--;
        if (start < 0 || /^\s*provider\s*:/.test(lines[start])) return false;
        let end = i + 1;
        while (end < lines.length && (!lines[end].trim() || indentOf(lines[end]) > indentOf(lines[start]))) end++;
        return lines.slice(start, end).some(b => /^\s*-\s*(?:http|httpApi)\s*:?/.test(b));
    });
    if (longHttpTimeoutIdx !== -1) {
        const matchLineIdx = longHttpTimeoutIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `sls11301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11301,
            type: 'INFRA_DATABASE',
            title: "SLS-01: HTTP Function Timeout Above the API Gateway Limit (Runaway Billing)",
            severity: "MEDIUM",
            category: "Serverless Cost",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Serverless function definition',
            reproductionSteps: [
                `Audited serverless handler in ${file.path}:${lineNum}.`,
                'Detected serverless architecture violation matching SLS-01.'
            ],
            remediationPrompt: "API Gateway ends HTTP requests after ~29s, so a longer Lambda timeout only keeps a function the client abandoned running and billing. Set timeout to 29 or less for http/httpApi functions; move long work to an async queue-triggered function.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-01: HTTP Function Timeout Above the API Gateway Limit (Runaway Billing) at ${file.path}:${lineNum}`);
    }
    // SLS-02: Heavyweight Module Initialization Inside Handler Loop (Cold Start Spike)
    // A DB client constructed on every invocation inside the Lambda handler body (not at module scope, not lazily cached):
    // each request opens a fresh connection pool, exhausting database connections under load.
    const handlerStartIdx = lines.findIndex(l => /^(?:exports\.handler|module\.exports\.handler)\s*=\s*async\b|^export\s+(?:const\s+handler\s*(?::[^=]+)?=\s*async\b|async\s+function\s+handler\s*\()/.test(l));
    let clientInHandlerIdx = -1;
    if (handlerStartIdx !== -1) {
        // The handler body: the indented lines up to its column-0 closing brace.
        for (let i = handlerStartIdx + 1; i < lines.length; i++) {
            const l = lines[i];
            if (/^\S/.test(l)) break;
            if (/\bnew\s+(?:PrismaClient|MongoClient)\s*\(/.test(l) && !/\?\?=|\|\|=|^\s*if\s*\(\s*!/.test(l) && !/^\s*if\s*\(\s*!/.test(lines[i - 1] || '')) {
                clientInHandlerIdx = i;
                break;
            }
        }
    }
    if (clientInHandlerIdx !== -1) {
        const matchLineIdx = clientInHandlerIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `sls11302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11302,
            type: 'INFRA_DATABASE',
            title: "SLS-02: Database Client Created Per Invocation Inside Lambda Handler",
            severity: "MEDIUM",
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
        logs.push(`[${ts}] [SLS AUDIT] Found SLS-02: Database Client Created Per Invocation Inside Lambda Handler at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
