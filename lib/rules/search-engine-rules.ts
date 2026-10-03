/**
 * Zelsis Master evaluateSearchEngineRules Engine
 * SEARCH-02 (13002), SEARCH-04 (13004).
 * Removed as unsound (ids never reused): 13001 literal `"from": 10000+` (real deep paging is computed, a
 * literal is a toy pattern), 13003 any `aggs` without circuit-breaker settings (cluster config, not code),
 * 13005 index creation without an ILM policy in the same file.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface SearchEngineRuleResult {
    findings: Finding[];
    logs: string[];
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
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
    // SEARCH-02: a wildcard / query_string query whose pattern STARTS with `*` followed by user input
    // (`*${q}` or '*' + q): every term in the index is scanned per request. Trailing wildcards are fine.
    const leadingWildcard = /\b(?:wildcard|query_string)\b[\s\S]{0,200}?:\s*(?:`\*\$\{|['"]\*['"]\s*\+)/.exec(cleanContent);
    if (leadingWildcard) {
        const matchLineIdx = lineAt(cleanContent, leadingWildcard.index + leadingWildcard[0].search(/:\s*(?:`\*\$\{|['"]\*['"]\s*\+)$/));
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `search13002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13002,
            type: 'INFRA_DATABASE',
            title: "SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans",
            severity: "MEDIUM",
            category: "Index Efficiency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Search query',
            reproductionSteps: [
                `Audited search query construction in ${file.path}:${lineNum}.`,
                'A user-supplied term is wrapped in a leading `*` wildcard, forcing a scan of every term in the field for each request.'
            ],
            remediationPrompt: "Avoid leading wildcards in search queries or use ngram / wildcard index mappings to safeguard cluster search SLAs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans at ${file.path}:${lineNum}`);
    }
    // SEARCH-04: one mapping property declaring `type: text` together with `fielddata: true`.
    let fielddataIdx = -1;
    const mappingProp = /\{[^{}]*\}/g;
    for (let m = mappingProp.exec(cleanContent); m && fielddataIdx === -1; m = mappingProp.exec(cleanContent)) {
        const prop = m[0];
        if (/["']?type["']?\s*:\s*["']text["']/.test(prop)) {
            const fd = /["']?fielddata["']?\s*:\s*true\b/.exec(prop);
            if (fd) fielddataIdx = lineAt(cleanContent, m.index + fd.index);
        }
    }
    if (fielddataIdx !== -1) {
        const matchLineIdx = fielddataIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `search13004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13004,
            type: 'INFRA_DATABASE',
            title: "SEARCH-04: Fielddata Memory Leakage on High-Cardinality Analyzed Text",
            severity: "MEDIUM",
            category: "Memory Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Index mapping',
            reproductionSteps: [
                `Audited index mapping in ${file.path}:${lineNum}.`,
                'fielddata: true on an analyzed text field loads every token of the field into JVM heap on the first sort / aggregation.'
            ],
            remediationPrompt: "Disable fielddata on text fields; use keyword multi-fields for sorting and aggregating to avoid heap consumption.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SEARCH AUDIT] Found SEARCH-04: Fielddata Memory Leakage on High-Cardinality Analyzed Text at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
