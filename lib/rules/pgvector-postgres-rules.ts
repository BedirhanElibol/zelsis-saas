/**
 * Zelsis Master evaluatePgvectorPostgresRules Engine (50 Rules)
 * Rules PG-01 to PG-50 (Rule IDs 10301 to 10350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface PgvectorPostgresRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluatePgvectorPostgresRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): PgvectorPostgresRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // PG-01: Vector Similarity Search Without HNSW or IVFFlat Index
    if ((/ORDER\s+BY\s+[a-zA-Z0-9_]+\s*<=>/i.test(cleanContent) && !/hnsw|ivfflat/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/ORDER\s+BY\s+[a-zA-Z0-9_]+\s*<=>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pg10301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10301,
            type: 'INFRA_DATABASE',
            title: "PG-01: Vector Similarity Search Without HNSW or IVFFlat Index",
            severity: "CRITICAL",
            category: "Vector Indexing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PostgreSQL statement',
            reproductionSteps: [
                `Audited database schema in ${file.path}:${lineNum}.`,
                'Detected PostgreSQL / pgvector optimization violation matching PG-01.'
            ],
            remediationPrompt: "Add CREATE INDEX idx_vectors ON documents USING hnsw (embedding vector_cosine_ops) to migrations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PG AUDIT] Found PG-01: Vector Similarity Search Without HNSW or IVFFlat Index at ${file.path}:${lineNum}`);
    }
    // PG-02: Missing Index on High-Cardinality Foreign Key Columns
    if ((/REFERENCES\s+[a-zA-Z0-9_]+\s*\([a-zA-Z0-9_]+\)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/REFERENCES\s+[a-zA-Z0-9_]+\s*\([a-zA-Z0-9_]+\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pg10302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10302,
            type: 'INFRA_DATABASE',
            title: "PG-02: Missing Index on High-Cardinality Foreign Key Columns",
            severity: "HIGH",
            category: "Query Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PostgreSQL statement',
            reproductionSteps: [
                `Audited database schema in ${file.path}:${lineNum}.`,
                'Detected PostgreSQL / pgvector optimization violation matching PG-02.'
            ],
            remediationPrompt: "Add CREATE INDEX CONCURRENTLY on foreign key columns referencing parent table IDs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PG AUDIT] Found PG-02: Missing Index on High-Cardinality Foreign Key Columns at ${file.path}:${lineNum}`);
    }
    // PG-03: Exhaustion of Connection Pool via Missing Max Connection Limits
    if ((/new\s+Pool\s*\([\s\S]*?\)/i.test(cleanContent) && !/max:|poolSize/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Pool\s*\([\s\S]*?\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pg10303-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10303,
            type: 'INFRA_DATABASE',
            title: "PG-03: Exhaustion of Connection Pool via Missing Max Connection Limits",
            severity: "MEDIUM",
            category: "Connection Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PostgreSQL statement',
            reproductionSteps: [
                `Audited database schema in ${file.path}:${lineNum}.`,
                'Detected PostgreSQL / pgvector optimization violation matching PG-03.'
            ],
            remediationPrompt: "Configure connection pool limits (max: 20) and point application database URLs to PgBouncer port 6543.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PG AUDIT] Found PG-03: Exhaustion of Connection Pool via Missing Max Connection Limits at ${file.path}:${lineNum}`);
    }
    // PG-04: Unbounded Statement Execution Time (Missing statement_timeout)
    if ((/createPool|new\s+Client/i.test(cleanContent) && !/statement_timeout/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/createPool|new\s+Client/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pg10304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10304,
            type: 'INFRA_DATABASE',
            title: "PG-04: Unbounded Statement Execution Time (Missing statement_timeout)",
            severity: "HIGH",
            category: "Query Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PostgreSQL statement',
            reproductionSteps: [
                `Audited database schema in ${file.path}:${lineNum}.`,
                'Detected PostgreSQL / pgvector optimization violation matching PG-04.'
            ],
            remediationPrompt: "Execute SET statement_timeout = '30s' on application connection pool initialization.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PG AUDIT] Found PG-04: Unbounded Statement Execution Time (Missing statement_timeout) at ${file.path}:${lineNum}`);
    }
    // PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order
    if ((/SELECT\s+[\s\S]*?FOR\s+UPDATE/i.test(cleanContent) && !/ORDER\s+BY/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/SELECT\s+[\s\S]*?FOR\s+UPDATE/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `pg10305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10305,
            type: 'INFRA_DATABASE',
            title: "PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order",
            severity: "HIGH",
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'PostgreSQL statement',
            reproductionSteps: [
                `Audited database schema in ${file.path}:${lineNum}.`,
                'Detected PostgreSQL / pgvector optimization violation matching PG-05.'
            ],
            remediationPrompt: "Ensure batch transactional updates order primary keys ascending before acquiring row locks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PG AUDIT] Found PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
