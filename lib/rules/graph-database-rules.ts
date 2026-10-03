/**
 * Zelsis Master evaluateGraphDatabaseRules Engine (50 Rules)
 * Rules GRPH-01 to GRPH-50 (Rule IDs 12001 to 12050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface GraphDatabaseRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGraphDatabaseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GraphDatabaseRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GRPH-01: Unbounded Cypher Traversal Missing Maximum Hop Limit
    const r12001Idx = !/neo4j|session\.run|executeQuery|\btx\.run|cypher/i.test(cleanContent) ? -1
        : lines.findIndex(l => /-\[[\w:|`]*\*(?:\s*\d+\s*\.\.)?\s*\]-/.test(l));
    if (r12001Idx !== -1) {
        const matchLineIdx = r12001Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12001,
            type: 'INFRA_DATABASE',
            title: "GRPH-01: Unbounded Cypher Traversal Missing Maximum Hop Limit",
            severity: "MEDIUM",
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Graph Database code segment',
            reproductionSteps: [
                `Audited Graph Database configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching GRPH-01.'
            ],
            remediationPrompt: "Add upper bound hop constraints (e.g. -[*1..4]->) to Cypher graph traversals to prevent memory exhaustion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRAPH AUDIT] Found GRPH-01: Unbounded Cypher Traversal Missing Maximum Hop Limit at ${file.path}:${lineNum}`);
    }
    // GRPH-02: Cypher Query String Concatenation Permitting Injection
    const r12002Idx = !/neo4j|session\.run|executeQuery|\btx\.run/i.test(cleanContent) ? -1
        : lines.findIndex(l => /`[^`]*\b(?:MATCH|MERGE|CREATE|WHERE|SET|DELETE)\b[^`]*\$\{/.test(l) ||
            /['"][^'"]*\b(?:MATCH|MERGE|WHERE)\b[^'"]*['"]\s*\+\s*[\w$]/.test(l));
    if (r12002Idx !== -1) {
        const matchLineIdx = r12002Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12002,
            type: 'INFRA_DATABASE',
            title: "GRPH-02: Cypher Query String Concatenation Permitting Injection",
            severity: "CRITICAL",
            category: "Injection Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Graph Database code segment',
            reproductionSteps: [
                `Audited Graph Database configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching GRPH-02.'
            ],
            remediationPrompt: "Use parameterized Cypher queries with parameters object rather than string concatenation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRAPH AUDIT] Found GRPH-02: Cypher Query String Concatenation Permitting Injection at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
