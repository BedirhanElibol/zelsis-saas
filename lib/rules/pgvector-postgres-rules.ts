/**
 * Zelsis Master evaluatePgvectorPostgresRules Engine
 * PG-05 (10305). Removed as unsound (ids never reused): 10301 vector ORDER BY without an index in the same
 * file (indexes live in migrations), 10302 every REFERENCES column, 10303 pg Pool without max (node-postgres
 * already defaults to 10), 10304 statement_timeout absent from the file.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    // PG-05: one statement locks a SET of rows (WHERE ... IN (...) / = ANY(...)) FOR UPDATE with no ORDER BY.
    // Rows are locked in scan order, so two such transactions over overlapping sets can deadlock.
    // Single-row locks, ordered locks and SKIP LOCKED / NOWAIT queue claims are not flagged.
    let unorderedLockIdx = -1;
    const lockStmt = /\bSELECT\b(?:(?!\bSELECT\b|;)[\s\S]){0,800}?\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b(?!\s+(?:SKIP\s+LOCKED|NOWAIT))/gi;
    for (let m = lockStmt.exec(cleanContent); m && unorderedLockIdx === -1; m = lockStmt.exec(cleanContent)) {
        if (/\bIN\s*\(|=\s*ANY\s*\(/i.test(m[0]) && !/\bORDER\s+BY\b/i.test(m[0])) {
            unorderedLockIdx = cleanContent.slice(0, m.index + m[0].search(/\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b/i)).split('\n').length - 1;
        }
    }
    if (unorderedLockIdx !== -1) {
        const matchLineIdx = unorderedLockIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `pg10305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10305,
            type: 'INFRA_DATABASE',
            title: "PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order",
            severity: "MEDIUM",
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
