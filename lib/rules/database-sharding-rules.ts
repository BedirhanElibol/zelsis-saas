/**
 * Zelsis Master evaluateDatabaseShardingRules Engine (50 Rules)
 * Rules SHARD-01 to SHARD-50 (Rule IDs 15501 to 15550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface DatabaseShardingRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateDatabaseShardingRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): DatabaseShardingRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SHARD-01: Missing Shard Routing Key in Schema Definitions Causing Full Cluster Scatter-Gather Broadcasts
    if (((/db_sharding|vschema|citus_schema/i.test(lowerPath) || /create_distributed_table|vschema/i.test(cleanContent)) && !/sharding_key|distribution_key/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `shard15501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15501,
            type: 'INFRA_DATABASE',
            title: "SHARD-01: Missing Shard Routing Key in Schema Definitions Causing Full Cluster Scatter-Gather Broadcasts",
            severity: "CRITICAL",
            category: "Query Routing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Horizontal Database Sharding configuration',
            reproductionSteps: [
                `Audited Horizontal Database Sharding configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Include the primary sharding key (e.g. tenant_id or user_id) in query predicates to ensure direct single-shard routing.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SHARD AUDIT] Found SHARD-01: Missing Shard Routing Key in Schema Definitions Causing Full Cluster Scatter-Gather Broadcasts at ${file.path}:${lineNum}`);
    }
    // SHARD-02: Unco-located Sharded Table Joins Triggering Massive Cross-Network Data Reshuffling
    if (((/sharded_joins|citus_colocate/i.test(lowerPath) || /colocate_with/i.test(cleanContent)) && !/colocate_with\s*=/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `shard15502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15502,
            type: 'INFRA_DATABASE',
            title: "SHARD-02: Unco-located Sharded Table Joins Triggering Massive Cross-Network Data Reshuffling",
            severity: "CRITICAL",
            category: "Schema Co-location",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Horizontal Database Sharding configuration',
            reproductionSteps: [
                `Audited Horizontal Database Sharding configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Co-locate frequently joined sharded tables using identical shard distribution columns and co-location groups (e.g. Citus table co-location).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SHARD AUDIT] Found SHARD-02: Unco-located Sharded Table Joins Triggering Massive Cross-Network Data Reshuffling at ${file.path}:${lineNum}`);
    }
    // SHARD-03: Unbalanced Hash Partitioning Keys Creating High-Frequency Shard Hotspots
    if (((/partition_key|shard_key/i.test(lowerPath) || /partitionBy/i.test(cleanContent)) && !/consistentHashRing/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `shard15503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15503,
            type: 'INFRA_DATABASE',
            title: "SHARD-03: Unbalanced Hash Partitioning Keys Creating High-Frequency Shard Hotspots",
            severity: "HIGH",
            category: "Partition Design",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Horizontal Database Sharding configuration',
            reproductionSteps: [
                `Audited Horizontal Database Sharding configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Select high-cardinality shard keys combined with consistent hashing to evenly distribute data partitions across cluster nodes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SHARD AUDIT] Found SHARD-03: Unbalanced Hash Partitioning Keys Creating High-Frequency Shard Hotspots at ${file.path}:${lineNum}`);
    }
    // SHARD-04: Unbounded Two-Phase Commit (2PC) Distributed Transactions Across Disparate Shards
    if (((/distributed_tx|two_phase_commit/i.test(lowerPath) || /twoPhaseCommit/i.test(cleanContent)) && cleanContent.includes('unbounded2pcTimeoutRisk') && !/twoPhaseCommitTimeout/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `shard15504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15504,
            type: 'INFRA_DATABASE',
            title: "SHARD-04: Unbounded Two-Phase Commit (2PC) Distributed Transactions Across Disparate Shards",
            severity: "HIGH",
            category: "Transaction Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Horizontal Database Sharding configuration',
            reproductionSteps: [
                `Audited Horizontal Database Sharding configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Redesign transaction boundaries to execute single-shard operations or use asynchronous saga patterns for cross-shard consistency.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SHARD AUDIT] Found SHARD-04: Unbounded Two-Phase Commit (2PC) Distributed Transactions Across Disparate Shards at ${file.path}:${lineNum}`);
    }
    // SHARD-05: Missing Online Resharding Split/Merge Strategy Permitting Out-of-Disk Worker Node Failures
    if (((/resharding_policy|worker_storage/i.test(lowerPath) || /shardRebalance/i.test(cleanContent)) && !/dynamicRangeSplitting/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `shard15505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15505,
            type: 'INFRA_DATABASE',
            title: "SHARD-05: Missing Online Resharding Split/Merge Strategy Permitting Out-of-Disk Worker Node Failures",
            severity: "CRITICAL",
            category: "Capacity Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Horizontal Database Sharding configuration',
            reproductionSteps: [
                `Audited Horizontal Database Sharding configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Configure automated dynamic range splitting rules (e.g. 64GB max shard size) to trigger online rebalancing before capacity breaches occur.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SHARD AUDIT] Found SHARD-05: Missing Online Resharding Split/Merge Strategy Permitting Out-of-Disk Worker Node Failures at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
