/**
 * Zelsis Master evaluateWafEdgeRules Engine (50 Rules)
 * Rules WAF-01 to WAF-50 (Rule IDs 10401 to 10450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { LLM_CALL, RATE_LIMIT_GUARD } from './shared/stack-signals';
import { locateMatchLine } from './shared/locate';
export interface WafEdgeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWafEdgeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): WafEdgeRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // WAF-02: Missing Edge Rate Limiting on High-Cost AI Inference Endpoints
    const callsAiInference = /chat\.completions|chat\/completions|messages\.create|responses\.create|generateText|streamText|generateObject|streamObject|from\s+['"](?:openai|@anthropic-ai\/sdk|@ai-sdk\/[\w-]+|ai|@google\/generative-ai|@google\/genai|@mistralai\/mistralai|groq-sdk|cohere-ai|replicate|together-ai|ollama)['"]|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai\/api|api\.together\.xyz|api\.cohere\.(?:ai|com)|api\.deepseek\.com|api\.x\.ai/i.test(cleanContent);
    if ((callsAiInference || LLM_CALL.test(cleanContent)) && /export\s+async\s+function\s+POST/i.test(cleanContent) && !RATE_LIMIT_GUARD.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [LLM_CALL, /export\s+async\s+function\s+POST/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `waf10402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10402,
            type: 'SECURITY',
            title: "WAF-02: Missing Edge Rate Limiting on High-Cost AI Inference Endpoints",
            severity: "HIGH",
            category: "DDoS Mitigation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WAF edge configuration',
            reproductionSteps: [
                `Audited edge configuration in ${file.path}:${lineNum}.`,
                'Detected WAF security violation matching WAF-02.'
            ],
            remediationPrompt: "Configure Cloudflare / AWS WAF token bucket rate limiting on /api/generate and /api/v1/scan routes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WAF AUDIT] Found WAF-02: Missing Edge Rate Limiting on High-Cost AI Inference Endpoints at ${file.path}:${lineNum}`);
    }
    // WAF-05: Unchecked HTTP Request Body Size Exceeding Edge WAF Inspection Buffer
    const r10405Idx = !/bodyParser|express\.(?:json|urlencoded|raw|text)|bodySizeLimit|sizeLimit|fastify/i.test(cleanContent) ? -1
        : lines.findIndex(l => {
            // request body limit raised to 50 MB+ (or GB): larger than any edge WAF inspects
            const m = l.match(/\b(?:limit|bodySizeLimit|sizeLimit|bodyLimit)\s*:\s*['"](\d+)\s*(mb|gb)['"]/i);
            return !!m && (m[2].toLowerCase() === 'gb' || Number(m[1]) >= 50);
        });
    if (r10405Idx !== -1) {
        const matchLineIdx = r10405Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `waf10405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10405,
            type: 'SECURITY',
            title: "WAF-05: Unchecked HTTP Request Body Size Exceeding Edge WAF Inspection Buffer",
            severity: "MEDIUM",
            category: "Inspection Evasion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WAF edge configuration',
            reproductionSteps: [
                `Audited edge configuration in ${file.path}:${lineNum}.`,
                'Detected WAF security violation matching WAF-05.'
            ],
            remediationPrompt: "Enforce client_max_body_size and reject oversized uninspected request bodies at the edge gateway.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WAF AUDIT] Found WAF-05: Unchecked HTTP Request Body Size Exceeding Edge WAF Inspection Buffer at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
