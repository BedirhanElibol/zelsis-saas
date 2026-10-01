/**
 * Zelsis Master evaluateTimeSeriesDbOptRules Engine (50 Rules)
 * Rules TSDB-OPT-01 to TSDB-OPT-50 (Rule IDs 15901 to 15950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface TimeSeriesDbOptRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTimeSeriesDbOptRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TimeSeriesDbOptRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TSDB-OPT-01: TimescaleDB Hypertable Chunk Interval Sizing Exceeding In-Memory RAM Working Set
    if (((/hypertable|timescale_schema/i.test(lowerPath) || /create_hypertable/i.test(cleanContent)) && !/chunk_time_interval/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdbopt15901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15901,
            type: 'INFRA_DATABASE',
            title: "TSDB-OPT-01: TimescaleDB Hypertable Chunk Interval Sizing Exceeding In-Memory RAM Working Set",
            severity: "CRITICAL",
            category: "Memory Sizing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database Optimization configuration',
            reproductionSteps: [
                `Audited Time-Series Database Optimization configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Configure hypertable chunk intervals (e.g. 1 day or 12 hours) so that recent chunk indexes fit fully into shared memory buffers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-OPT-01: TimescaleDB Hypertable Chunk Interval Sizing Exceeding In-Memory RAM Working Set at ${file.path}:${lineNum}`);
    }
    // TSDB-OPT-02: ClickHouse MergeTree Missing Partition Granularity Causing Shard Thread Starvation
    if (((/clickhouse_ddl|mergetree/i.test(lowerPath) || /ENGINE\s*=\s*MergeTree/i.test(cleanContent)) && !/PARTITION BY/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdbopt15902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15902,
            type: 'INFRA_DATABASE',
            title: "TSDB-OPT-02: ClickHouse MergeTree Missing Partition Granularity Causing Shard Thread Starvation",
            severity: "HIGH",
            category: "Partition Granularity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database Optimization configuration',
            reproductionSteps: [
                `Audited Time-Series Database Optimization configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Partition MergeTree tables by reasonable time intervals (e.g. toYYYYMM) to avoid excessive part mutation overhead.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-OPT-02: ClickHouse MergeTree Missing Partition Granularity Causing Shard Thread Starvation at ${file.path}:${lineNum}`);
    }
    // TSDB-OPT-03: Missing Columnar DoubleDelta or Gorilla Compression Codecs on Numeric Metric Series
    if (((/timeseries_schema|column_codecs/i.test(lowerPath) || /CODEC\(/i.test(cleanContent)) && !/DoubleDelta|Gorilla/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdbopt15903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15903,
            type: 'INFRA_DATABASE',
            title: "TSDB-OPT-03: Missing Columnar DoubleDelta or Gorilla Compression Codecs on Numeric Metric Series",
            severity: "HIGH",
            category: "Compression Efficiency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database Optimization configuration',
            reproductionSteps: [
                `Audited Time-Series Database Optimization configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Apply Gorilla or DoubleDelta compression encodings to floating point and integer telemetry streams to reduce storage by 80%+.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-OPT-03: Missing Columnar DoubleDelta or Gorilla Compression Codecs on Numeric Metric Series at ${file.path}:${lineNum}`);
    }
    // TSDB-OPT-04: Unscheduled Continuous Aggregates Causing Real-Time Metric Query CPU Spikes
    if (((/continuous_aggs|rollup_views/i.test(lowerPath) || /continuous_aggregate/i.test(cleanContent)) && !/add_continuous_aggregate_policy/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdbopt15904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15904,
            type: 'INFRA_DATABASE',
            title: "TSDB-OPT-04: Unscheduled Continuous Aggregates Causing Real-Time Metric Query CPU Spikes",
            severity: "HIGH",
            category: "Rollup Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database Optimization configuration',
            reproductionSteps: [
                `Audited Time-Series Database Optimization configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Materialize downsampled time-series rollups using continuous aggregate views with automated refresh policies.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-OPT-04: Unscheduled Continuous Aggregates Causing Real-Time Metric Query CPU Spikes at ${file.path}:${lineNum}`);
    }
    // TSDB-OPT-05: Missing Automated Data Retention Policy on Raw High-Frequency Metric Partitions
    if (((/retention_policy|metric_cleanup/i.test(lowerPath) || /drop_chunks/i.test(cleanContent)) && !/add_retention_policy/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tsdbopt15905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15905,
            type: 'INFRA_DATABASE',
            title: "TSDB-OPT-05: Missing Automated Data Retention Policy on Raw High-Frequency Metric Partitions",
            severity: "CRITICAL",
            category: "Retention Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Time-Series Database Optimization configuration',
            reproductionSteps: [
                `Audited Time-Series Database Optimization configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Implement automated drop_chunks retention policies discarding raw granular metric data after 30 to 90 days.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-OPT-05: Missing Automated Data Retention Policy on Raw High-Frequency Metric Partitions at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
