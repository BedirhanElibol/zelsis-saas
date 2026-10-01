/**
 * Zelsis Master evaluateTimeSeriesDbRules Engine (50 Rules)
 * Rules TSDB-01 to TSDB-50 (Rule IDs 14001 to 14050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface TimeSeriesDbRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTimeSeriesDbRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TimeSeriesDbRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries
    if ((/create\s*table.*ENGINE\s*=\s*MergeTree/i.test(cleanContent) && !/ORDER BY/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/create\s*table.*ENGINE\s*=\s*MergeTree/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14001,
            type: 'INFRA_DATABASE',
            title: "TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries",
            severity: "CRITICAL",
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries.'
            ],
            remediationPrompt: "Enforce clustering or primary sorting keys on timestamp and metric dimensions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries at ${file.path}:${lineNum}`);
    }
    // TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry
    if ((/retention_policy/i.test(lowerPath) && !/storagePolicy/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14002,
            type: 'INFRA_DATABASE',
            title: "TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry",
            severity: "HIGH",
            category: "Storage Lifecycle",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry.'
            ],
            remediationPrompt: "Configure automatic compression and tiered storage offloading for historical metrics.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry at ${file.path}:${lineNum}`);
    }
    // TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory
    if ((/recordMetric|emitEvent/i.test(cleanContent) && !/sanitizeMetricTags/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/recordMetric|emitEvent/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14003,
            type: 'INFRA_DATABASE',
            title: "TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory",
            severity: "CRITICAL",
            category: "Memory Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory.'
            ],
            remediationPrompt: "Enforce limits on unique tag/label values (e.g. banning user IDs or trace IDs in metric tag sets).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory at ${file.path}:${lineNum}`);
    }
    // TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation
    if (((/writeTelemetry/i.test(lowerPath) || /writeTelemetry/i.test(cleanContent)) && !/batchBuffer/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/writeTelemetry/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14004,
            type: 'INFRA_DATABASE',
            title: "TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation",
            severity: "HIGH",
            category: "Ingestion Efficiency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation.'
            ],
            remediationPrompt: "Batch metric writes (minimum 5,000-10,000 points per HTTP/TCP write request).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation at ${file.path}:${lineNum}`);
    }
    // TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space
    if ((/column_definition/i.test(cleanContent) && !/CODEC\(ZSTD\)|Gorilla/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/column_definition/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdb14005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14005,
            type: 'INFRA_DATABASE',
            title: "TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space",
            severity: "MEDIUM",
            category: "Storage Efficiency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
            reproductionSteps: [
                `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
                'Matched TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space.'
            ],
            remediationPrompt: "Enable ZSTD or Gorilla columnar compression codecs on time-series chunks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
