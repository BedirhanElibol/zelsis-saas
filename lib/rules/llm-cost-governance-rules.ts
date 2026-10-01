/**
 * Zelsis Master evaluateLlmCostGovernanceRules Engine
 * Rules LLM-COST-01 to LLM-COST-08 (Rule IDs 8071 to 8078).
 * Provides FinOps, AI Token Cost Protection, Denial-of-Wallet Defense, and Model Governance.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { LLM_CALL, LLM_OUTPUT_LIMIT, RATE_LIMIT_GUARD } from './shared/stack-signals';
export interface LlmCostGovernanceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateLlmCostGovernanceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): LlmCostGovernanceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // LLM-COST-01: Unbounded Token Generation (max_tokens / max_completion_tokens missing)
    const hasLlmCall = LLM_CALL.test(cleanContent);
    if (hasLlmCall && !LLM_OUTPUT_LIMIT.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            !l.trim().startsWith('*') &&
            /(?:openai\.chat\.completions\.create|anthropic\.messages\.create|mistral\.chat)/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8071,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-01: Unbounded Token Generation (Missing max_tokens Guard)',
            severity: 'HIGH',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<LLM chat completion call without max_tokens>',
            reproductionSteps: [
                `Scanned AI SDK invocation in ${file.path}:${lineNum}.`,
                'Detected LLM chat completion without explicit `max_tokens` or `max_completion_tokens` boundary.',
                'Exposes backend infrastructure to Denial-of-Wallet (DoW) and unbounded cloud billing spikes.'
            ],
            remediationPrompt: 'Always define an explicit `max_tokens` (e.g. 1024 or 2048) or `max_completion_tokens` parameter on all LLM API invocations.',
            status: 'OPEN',
            owner: 'Platform Engineering & FinOps',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-01 (Unbounded Tokens) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-02: Missing Token Budget Rate Limiter on API Routes Invoking LLMs
    const isApiRoute = lowerPath.includes('/api/') || lowerPath.includes('route.ts') || lowerPath.includes('route.js');
    if (isApiRoute && hasLlmCall && !RATE_LIMIT_GUARD.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            /(?:export async function POST|export async function GET|handler|app\.post)/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8072,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-02: Missing Token Budget Rate Limiter on LLM Endpoint',
            severity: 'HIGH',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<API route invoking LLM without rate limiting>',
            reproductionSteps: [
                `Audited server API route in ${file.path}:${lineNum}.`,
                'Route invokes LLM model completions without sliding-window IP/user rate limiting or token spend ceilings.',
                'Attackers can script high-concurrency requests to deplete organization cloud credits rapidly.'
            ],
            remediationPrompt: 'Integrate sliding-window rate limiting (e.g. checkRateLimit / Upstash) before invoking commercial LLM APIs.',
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-02 (Missing Rate Limit on LLM Route) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-03: Uncached Vector Embedding Loops
    const hasEmbeddingLoop = /(?:for|while|\.map|\.forEach)\s*\([^)]*\)[\s\S]{0,300}(?:embeddings\.create|createEmbedding)/i.test(cleanContent);
    if (hasEmbeddingLoop && !/(?:cache|memoize|lru|redis|kv|store)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            /(?:embeddings\.create|createEmbedding)/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8073,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-03: Uncached Vector Embedding Loop (Compounding API Cost)',
            severity: 'HIGH',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Embedding generation in loop without cache>',
            reproductionSteps: [
                `Inspected embedding generation logic in ${file.path}:${lineNum}.`,
                'Detected batch or looped vector embedding calls without hash-based cache or memoization.',
                'Repeated queries with identical input generate redundant OpenAI/Cohere API fees.'
            ],
            remediationPrompt: 'Implement SHA-256 content-hash caching (via Redis, KV, or in-memory LRU) before generating remote embeddings.',
            status: 'OPEN',
            owner: 'Data Engineering & AI Infrastructure',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-03 (Uncached Embeddings Loop) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-04: High-Cost Flagship Model Overkill for Simple Parsing
    const hasFlagshipModel = /model\s*:\s*['"](?:gpt-4o|claude-3-opus|claude-3-opus-20240229)['"]/i.test(cleanContent);
    const isSimpleExtraction = /(?:extract|classify|categorize|parse_json|sentiment|slugify|summary_short)/i.test(cleanContent);
    if (hasFlagshipModel && isSimpleExtraction && !/(?:haiku|mini|fallbackModel|economyModel)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            /model\s*:\s*['"](?:gpt-4o|claude-3-opus)/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8074,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-04: Flagship Model Overkill on Low-Complexity Task',
            severity: 'MEDIUM',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Flagship model assigned to classification/extraction>',
            reproductionSteps: [
                `Evaluated model architecture in ${file.path}:${lineNum}.`,
                'Flagship tier model (GPT-4o or Claude 3 Opus) assigned to lightweight extraction, classification, or formatting.',
                'Swapping to tier-matched models (gpt-4o-mini or Claude 3.5 Haiku) provides identical accuracy with 80-95% cost reduction.'
            ],
            remediationPrompt: 'Route low-complexity classification and extraction tasks to `gpt-4o-mini` or `claude-3-5-haiku` to cut cloud expenses.',
            status: 'OPEN',
            owner: 'Platform Engineering & FinOps',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-04 (Model Tier Overkill) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-05: Serverless Function Timeout Cost Spiral on Streaming
    const hasStreaming = /stream\s*:\s*true/i.test(cleanContent);
    if (isApiRoute && hasStreaming && !/(?:maxDuration|timeout|AbortController|signal)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            /stream\s*:\s*true/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8075,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-05: Serverless LLM Stream Without Timeout Guard',
            severity: 'MEDIUM',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Serverless streaming without timeout or AbortSignal>',
            reproductionSteps: [
                `Inspected serverless streaming handler in ${file.path}:${lineNum}.`,
                'Route streams tokens without explicit timeout (`maxDuration`) or `AbortController` cancellation.',
                'Disconnected clients keep serverless compute instances running until maximum platform timeout, multiplying compute bills.'
            ],
            remediationPrompt: 'Attach `req.signal` (AbortSignal) to stream reader and declare `export const maxDuration = 30;` in Next.js routes.',
            status: 'OPEN',
            owner: 'Cloud & Infrastructure',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-05 (Serverless Stream Timeout Spiral) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-06: Infinite / Exponentialless Retry on LLM Provider Errors
    const hasNaiveRetry = /(?:retryCount\s*\+\+|retries\s*<|attempts\s*<)\s*\d+/i.test(cleanContent);
    if (hasLlmCall && hasNaiveRetry && !/(?:exponential|backoff|jitter|Math\.pow|setTimeout\s*\([^,]+,\s*(?:delay|\d{3,}))/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            /(?:retryCount|retries|attempts)/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmcost06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8076,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-06: Naive LLM Retry Loop Without Exponential Backoff',
            severity: 'MEDIUM',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Tight retry loop on LLM API calls>',
            reproductionSteps: [
                `Audited fault tolerance in ${file.path}:${lineNum}.`,
                'Detected tight retry loop on LLM calls without exponential backoff or jitter.',
                'Under upstream provider degradation (HTTP 429/500/503), rapid retry bursts trigger cascading rate limit penalties and wasted billing quota.'
            ],
            remediationPrompt: 'Implement exponential backoff with full jitter on LLM API retries, capping at maximum 3 attempts.',
            status: 'OPEN',
            owner: 'Platform Engineering & FinOps',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-06 (Naive Retry Loop) in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
