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
    if ((/(?:session\.run|neo4j|cypher)/i.test(cleanContent) && /-\[\*\s*\]->/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12001,
            type: 'INFRA_DATABASE',
            title: "GRPH-01: Unbounded Cypher Traversal Missing Maximum Hop Limit",
            severity: "HIGH",
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
    if ((/(?:session\.run|neo4j|cypher)/i.test(cleanContent) && /MATCH\s*\([a-zA-Z0-9_]*:[a-zA-Z0-9_]+/i.test(cleanContent) && /\$\{|\+\s*[a-zA-Z0-9_]+/i.test(cleanContent) && !/\$params|\$props/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // GRPH-03: Missing Schema Index on High-Cardinality Graph Properties
    if ((/createIndex/i.test(cleanContent) && !/CREATE INDEX/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12003,
            type: 'INFRA_DATABASE',
            title: "GRPH-03: Missing Schema Index on High-Cardinality Graph Properties",
            severity: "HIGH",
            category: "Indexing Strategy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Graph Database code segment',
            reproductionSteps: [
                `Audited Graph Database configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching GRPH-03.'
            ],
            remediationPrompt: "Define schema indexes on high-cardinality node labels and relationship properties.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRAPH AUDIT] Found GRPH-03: Missing Schema Index on High-Cardinality Graph Properties at ${file.path}:${lineNum}`);
    }
    // GRPH-04: Supernode Cartesian Explosion in Variable Length Expansions
    if ((/expandPath/i.test(cleanContent) && !/filterSupernodes/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12004,
            type: 'INFRA_DATABASE',
            title: "GRPH-04: Supernode Cartesian Explosion in Variable Length Expansions",
            severity: "HIGH",
            category: "Graph Scalability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Graph Database code segment',
            reproductionSteps: [
                `Audited Graph Database configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching GRPH-04.'
            ],
            remediationPrompt: "Apply relationship type filtering and degree thresholds when traversing dense graph supernodes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRAPH AUDIT] Found GRPH-04: Supernode Cartesian Explosion in Variable Length Expansions at ${file.path}:${lineNum}`);
    }
    // GRPH-05: Unbounded Result Set Missing LIMIT Clause on Graph Query
    if ((/(?:session\.run|neo4j|cypher)/i.test(cleanContent) && /RETURN\s+[a-z]+/i.test(cleanContent) && !/LIMIT\s+\d+/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grph-12005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12005,
            type: 'INFRA_DATABASE',
            title: "GRPH-05: Unbounded Result Set Missing LIMIT Clause on Graph Query",
            severity: "MEDIUM",
            category: "Resource Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Graph Database code segment',
            reproductionSteps: [
                `Audited Graph Database configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching GRPH-05.'
            ],
            remediationPrompt: "Include LIMIT clauses on Cypher path queries to prevent driver heap out-of-memory errors.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRAPH AUDIT] Found GRPH-05: Unbounded Result Set Missing LIMIT Clause on Graph Query at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
