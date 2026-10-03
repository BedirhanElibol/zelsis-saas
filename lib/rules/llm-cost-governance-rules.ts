/**
 * Zelsis Master evaluateLlmCostGovernanceRules Engine
 * LLM-COST-03 (8073) and LLM-COST-06 (8076).
 * Removed as unsound (ids never reused): 8071 missing max_tokens (idiomatic SDK code omits it; output is
 * bounded by the model), 8072 rate limit absent from the route file (usually lives in middleware / gateway),
 * 8074 "flagship model on a simple task" (a product choice), 8075 stream without timeout (platform caps it).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { LLM_CALL } from './shared/stack-signals';
export interface LlmCostGovernanceRuleResult {
    findings: Finding[];
    logs: string[];
}
/** Text of the `{ ... }` block opening at or after `from` (brace-matched), or '' when none. */
function blockAfter(src: string, from: number): string {
    const open = src.indexOf('{', from);
    if (open === -1) return '';
    let depth = 0;
    for (let i = open; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
    }
    return src.slice(open);
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
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
    // LLM-COST-03: one embeddings request per item inside a loop, embedding just that loop item.
    // The OpenAI / Voyage / Cohere embeddings APIs (and AI SDK embedMany) take an array: N calls -> 1.
    let perItemEmbedIdx = -1;
    const loopHeader = /\bfor\s*\(\s*(?:const|let|var)\s+(\w+)\s+of\b|\.(?:map|forEach)\s*\(\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>/g;
    for (let m = loopHeader.exec(cleanContent); m && perItemEmbedIdx === -1; m = loopHeader.exec(cleanContent)) {
        const item = m[1] || m[2];
        const body = blockAfter(cleanContent, m.index + m[0].length);
        const call = new RegExp(String.raw`(?:embeddings\.create|\bembed)\s*\(\s*\{[^}]*?\b(?:input|value)\s*:\s*${item}\b(?!\s*\.map)`).exec(body);
        if (call) perItemEmbedIdx = lineAt(cleanContent, cleanContent.indexOf(body) + call.index);
    }
    if (perItemEmbedIdx !== -1) {
        const matchLineIdx = perItemEmbedIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `llmcost03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8073,
            type: 'INFRA_DATABASE',
            title: 'LLM-COST-03: Uncached Vector Embedding Loop (Compounding API Cost)',
            severity: 'LOW',
            category: 'FinOps & Cost Governance',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Embedding request per loop item>',
            reproductionSteps: [
                `Inspected embedding generation logic in ${file.path}:${lineNum}.`,
                'Detected one embeddings API request per loop item, embedding only that item.',
                'N sequential round trips multiply latency, rate-limit pressure and per-request overhead; the API accepts the whole batch in one call.'
            ],
            remediationPrompt: 'Send the inputs as one batch (embeddings.create({ input: chunks }) or embedMany({ values })), chunked to the provider limit, instead of one request per item.',
            status: 'OPEN',
            owner: 'Data Engineering & AI Infrastructure',
            falsePositive: false
        });
        logs.push(`[${ts}] [FINOPS COST] Flagged LLM-COST-03 (Per-item embeddings loop) in ${file.path}:${lineNum}`);
    }
    // LLM-COST-06: a retry loop around an LLM call that retries immediately (no wait of any kind in the loop).
    let tightRetryIdx = -1;
    const retryLoop = /\b(?:while\s*\(\s*\w*(?:attempt|retr|tries)\w*\s*<|for\s*\(\s*let\s+(\w*(?:attempt|retr|tries)\w*)\s*=\s*\d+\s*;\s*\1\s*<)/gi;
    for (let m = retryLoop.exec(cleanContent); m && tightRetryIdx === -1; m = retryLoop.exec(cleanContent)) {
        const body = blockAfter(cleanContent, m.index + m[0].length);
        if (LLM_CALL.test(body) && !/setTimeout|\bsleep\s*\(|\bdelay\b|backoff|\bwait\w*\s*\(|pRetry|retry\s*\(/i.test(body)) {
            tightRetryIdx = lineAt(cleanContent, m.index);
        }
    }
    if (tightRetryIdx !== -1) {
        const matchLineIdx = tightRetryIdx;
        const lineNum = matchLineIdx + 1;
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
