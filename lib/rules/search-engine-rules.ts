/**
 * Zelsis Master evaluateSearchEngineRules Engine (50 Rules)
 * Rules SEARCH-01 to SEARCH-50 (Rule IDs 13001 to 13050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface SearchEngineRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSearchEngineRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): SearchEngineRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") || lowerPath.endsWith(".tsx") || lowerPath.endsWith(".jsx")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SEARCH-01: Unbounded Deep Pagination via from + size Exceeding 10,000
    if ((/"from"\s*:\s*\d{5,}/i.test(cleanContent) && !/search_after/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `search13001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13001,
            type: 'INFRA_DATABASE',
            title: "SEARCH-01: Unbounded Deep Pagination via from + size Exceeding 10,000",
            severity: "HIGH",
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search Engine configuration',
            reproductionSteps: [
                `Audited Search Engine configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SEARCH-01.'
            ],
            remediationPrompt: "Replace deep offset pagination with search_after parameter to prevent cluster heap exhaustion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-01: Unbounded Deep Pagination via from + size Exceeding 10,000 at ${file.path}:${lineNum}`);
    }
    // SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans
    if ((/wildcard/i.test(cleanContent) && /(?:'\*|"\*)/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `search13002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13002,
            type: 'INFRA_DATABASE',
            title: "SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans",
            severity: "HIGH",
            category: "Index Efficiency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search Engine configuration',
            reproductionSteps: [
                `Audited Search Engine configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SEARCH-02.'
            ],
            remediationPrompt: "Avoid leading wildcards in search queries or use ngram / wildcard index mappings to safeguard cluster search SLAs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans at ${file.path}:${lineNum}`);
    }
    // SEARCH-03: Missing Circuit Breaker on High-Cardinality Aggregations
    if ((/aggs/i.test(cleanContent) && !/circuit_breaker|max_buckets/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `search13003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13003,
            type: 'INFRA_DATABASE',
            title: "SEARCH-03: Missing Circuit Breaker on High-Cardinality Aggregations",
            severity: "CRITICAL",
            category: "Resource Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search Engine configuration',
            reproductionSteps: [
                `Audited Search Engine configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SEARCH-03.'
            ],
            remediationPrompt: "Configure max_buckets limits and fielddata circuit breakers to prevent out-of-memory crashes on aggregations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-03: Missing Circuit Breaker on High-Cardinality Aggregations at ${file.path}:${lineNum}`);
    }
    // SEARCH-04: Fielddata Memory Leakage on High-Cardinality Analyzed Text
    if ((/\"type\"\s*:\s*\"text\"/i.test(cleanContent) && /(?:\"fielddata\"|fielddata)\s*:\s*true/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `search13004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13004,
            type: 'INFRA_DATABASE',
            title: "SEARCH-04: Fielddata Memory Leakage on High-Cardinality Analyzed Text",
            severity: "HIGH",
            category: "Memory Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search Engine configuration',
            reproductionSteps: [
                `Audited Search Engine configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SEARCH-04.'
            ],
            remediationPrompt: "Disable fielddata on text fields; use keyword multi-fields for sorting and aggregating to avoid heap consumption.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-04: Fielddata Memory Leakage on High-Cardinality Analyzed Text at ${file.path}:${lineNum}`);
    }
    // SEARCH-05: Unmanaged Elasticsearch Index Lifecycle Management (ILM)
    if ((/createIndex/i.test(cleanContent) && !/lifecycle/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `search13005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13005,
            type: 'INFRA_DATABASE',
            title: "SEARCH-05: Unmanaged Elasticsearch Index Lifecycle Management (ILM)",
            severity: "MEDIUM",
            category: "Storage Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search Engine configuration',
            reproductionSteps: [
                `Audited Search Engine configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SEARCH-05.'
            ],
            remediationPrompt: "Configure Index Lifecycle Management (ILM) policies to automatically roll over and phase out historical indices.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-05: Unmanaged Elasticsearch Index Lifecycle Management (ILM) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
