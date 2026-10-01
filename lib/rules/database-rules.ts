/**
 * Zelsis Master Database & ORM Performance Evaluator (50 Rules)
 * Rules DB-PERF-01 to DB-PERF-50 (Rule IDs 6001 to 6050).
 *
 * Detects N+1 query loops, unindexed foreign keys, deep offset pagination traps,
 * connection pool exhaustion in serverless runtimes, and transaction lock contention.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface DatabaseRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateDatabaseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): DatabaseRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('data/catalogs/') || lowerPath.includes('data/mockdata') || lowerPath.includes('data/workspacefiles') || lowerPath.includes('data/schema') || lowerPath.includes('scratch/') || lowerPath.includes('.agent/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // DB-PERF-01: Prisma / ORM N+1 Query in Loop
    if (/(?:for\s*\([^)]+of|\.map\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>)[\s\S]*?prisma\.[a-zA-Z0-9_]+\.(?:findMany|findUnique|findFirst)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-01|prisma/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6001,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-01: Prisma / ORM N+1 Query in Loop',
            severity: 'HIGH',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Prisma / ORM N+1 Query in Loop: Executing individual database queries inside for/map iteration loops instead of batching."
            ],
            remediationPrompt: "Refactor loop into a single batch query using include or where: { id: { in: ids } }.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-01: Prisma / ORM N+1 Query in Loop detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-02: Missing Index on Foreign Key Columns
    if (/REFERENCES\s+[a-zA-Z0-9_.]+\s*\([a-zA-Z0-9_]+\)/i.test(cleanContent) && !/CREATE\s+INDEX/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-02|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6002,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-02: Missing Index on Foreign Key Columns',
            severity: 'HIGH',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Index on Foreign Key Columns: Foreign key columns referencing other tables without dedicated B-Tree indexes."
            ],
            remediationPrompt: "Add CREATE INDEX IF NOT EXISTS idx_table_fk ON table(fk_id); to migrations.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-02: Missing Index on Foreign Key Columns detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-03: Deep Offset Pagination Performance Trap
    if (/\.skip\(\s*(?:1000|[2-9]\d{3,}|\d{5,})\s*\)|OFFSET\s+(?:1000|[2-9]\d{3,}|\d{5,})\b/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-03|deep/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6003,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-03: Deep Offset Pagination Performance Trap',
            severity: 'MEDIUM',
            category: "Pagination & Keyset",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Deep Offset Pagination Performance Trap: Using OFFSET > 1000 or skip(1000) forcing database to scan and discard thousands of rows."
            ],
            remediationPrompt: "Replace OFFSET/skip with keyset cursor pagination on indexed timestamp or ID column.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-03: Deep Offset Pagination Performance Trap detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-04: Unbounded SELECT * Full Table Scan
    if (/SELECT\s+\*\s+FROM\s+[a-zA-Z0-9_]+(?!\s+WHERE|\s+LIMIT)/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-04|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6004,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-04: Unbounded SELECT * Full Table Scan',
            severity: 'HIGH',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unbounded SELECT * Full Table Scan: Executing SELECT * without LIMIT clause on high-volume production tables."
            ],
            remediationPrompt: "Add explicit column selection and LIMIT/take bounds to all database queries.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-04: Unbounded SELECT * Full Table Scan detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-05: Direct Unpooled Database Connection in Edge / Serverless
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /new\s+(?:Pool|Client)\s*\(/i.test(cleanContent) && !/globalThis|singleton/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-05|direct/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6005,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-05: Direct Unpooled Database Connection in Edge / Serverless',
            severity: 'CRITICAL',
            category: "Connection Pooling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Direct Unpooled Database Connection in Edge / Serverless: Instantiating new Pool() or raw pg Client on each serverless API request without pooler."
            ],
            remediationPrompt: "Connect serverless functions through pooled port 6543 / Supavisor with connection limits.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-05: Direct Unpooled Database Connection in Edge / Serverless detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-06: Missing Composite Index on Multi-Column Filters
    if (/WHERE\s+[a-zA-Z0-9_]+\s*=\s*\$1\s+AND\s+[a-zA-Z0-9_]+\s*=\s*\$2/i.test(cleanContent) && !/INDEX/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-06|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6006,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-06: Missing Composite Index on Multi-Column Filters',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Composite Index on Multi-Column Filters: Frequent compound WHERE a = ? AND b = ? queries executing without composite index."
            ],
            remediationPrompt: "Add CREATE INDEX idx_table_a_b ON table(a, b); to database migration.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-06: Missing Composite Index on Multi-Column Filters detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-07: Unindexed Leading Wildcard LIKE Query
    if (/ILIKE\s+[\'"]%[^\'"]+%[\'"]|LIKE\s+[\'"]%[^\'"]+%[\'"]/i.test(cleanContent) && !/gin_trgm_ops|tsvector/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-07|unindexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6007,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-07: Unindexed Leading Wildcard LIKE Query',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unindexed Leading Wildcard LIKE Query: Using LIKE '%search%' or ILIKE '%...%' which completely disables standard B-Tree indexes."
            ],
            remediationPrompt: "Create pg_trgm GIN index: CREATE INDEX idx_trgm ON table USING gin(col gin_trgm_ops);",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-07: Unindexed Leading Wildcard LIKE Query detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-08: Missing ON DELETE Strategy on Foreign Key Constraints
    if (/FOREIGN\s+KEY[^\n]+(?<!ON\s+DELETE\s+(?:CASCADE|RESTRICT|SET\s+NULL|SET\s+DEFAULT|NO\s+ACTION));/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-08|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6008,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-08: Missing ON DELETE Strategy on Foreign Key Constraints',
            severity: 'HIGH',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing ON DELETE Strategy on Foreign Key Constraints: Foreign keys lacking explicit ON DELETE CASCADE / RESTRICT / SET NULL rules."
            ],
            remediationPrompt: "Specify ON DELETE CASCADE or ON DELETE RESTRICT on all foreign key constraints.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-08: Missing ON DELETE Strategy on Foreign Key Constraints detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-09: Long-Running External API Call Inside DB Transaction
    if (/\$transaction\s*\(\s*async\s*\([^)]*\)\s*=>[\s\S]*?(?:fetch\(|axios\.|openai\.|anthropic\.)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-09|long-running/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6009,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-09: Long-Running External API Call Inside DB Transaction',
            severity: 'CRITICAL',
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Long-Running External API Call Inside DB Transaction: Awaiting external HTTP or AI completion calls while holding active database transaction."
            ],
            remediationPrompt: "Move external API/LLM calls outside transaction; use optimistic concurrency or sagas.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-09: Long-Running External API Call Inside DB Transaction detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-10: PostgreSQL Public Table Missing Row Level Security (RLS)
    if (/CREATE\s+TABLE\s+(?:public\.)?[a-zA-Z0-9_]+/i.test(cleanContent) && !/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-10|create\s+table/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6010,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-10: PostgreSQL Public Table Missing Row Level Security (RLS)',
            severity: 'CRITICAL',
            category: "Database Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database DDL schema in ${file.path}:${lineNum}.`,
                "Detected PostgreSQL Public Table Missing Row Level Security: Public database tables created without ALTER TABLE ... ENABLE ROW LEVEL SECURITY."
            ],
            remediationPrompt: "Execute ALTER TABLE public.table_name ENABLE ROW LEVEL SECURITY;",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-10: PostgreSQL Public Table Missing Row Level Security (RLS) detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-11: Non-Deterministic findFirst without OrderBy
    if (/\.findFirst\(\s*\{(?![^}]*orderBy)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-11|non-deterministic/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6011,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-11: Non-Deterministic findFirst without OrderBy',
            severity: 'MEDIUM',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Non-Deterministic findFirst without OrderBy: Using findFirst() or LIMIT 1 without explicit orderBy clause, returning arbitrary rows."
            ],
            remediationPrompt: "Add orderBy: { createdAt: 'desc' } to guarantee deterministic query results.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-11: Non-Deterministic findFirst without OrderBy detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-12: Unbounded Bulk Insert Batch Exhaustion
    if (/createMany\(\s*\{\s*data:\s*\[[^\]]{500,}\]/i.test(cleanContent) && !/chunk/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-12|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6012,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-12: Unbounded Bulk Insert Batch Exhaustion',
            severity: 'HIGH',
            category: "Write Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unbounded Bulk Insert Batch Exhaustion: Inserting thousands of records in a single batch without chunking, risking packet size limit."
            ],
            remediationPrompt: "Chunk bulk insert arrays into batches of 500 rows using array chunking utility.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-12: Unbounded Bulk Insert Batch Exhaustion detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-13: Missing Connection Pool Acquisition Timeout
    if (/new\s+Pool\(\s*\{(?![^}]*connectionTimeoutMillis)/i.test(cleanContent) && !/mock|test/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-13|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6013,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-13: Missing Connection Pool Acquisition Timeout',
            severity: 'HIGH',
            category: "Connection Pooling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Connection Pool Acquisition Timeout: Database pool configured with indefinite connection acquisition timeout, freezing server."
            ],
            remediationPrompt: "Configure pool with connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-13: Missing Connection Pool Acquisition Timeout detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-14: Unindexed UUID Primary Key Fragmenting B-Tree
    if (/CREATE\s+TABLE\s+(?:public\.)?(?:high_throughput_logs|clickstream_events|metric_samples|raw_telemetry)[\s\S]*?id\s+UUID\s+PRIMARY\s+KEY\s+DEFAULT\s+gen_random_uuid\(\)/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-14|unindexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6014,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-14: Unindexed UUID Primary Key Fragmenting B-Tree',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unindexed UUID Primary Key Fragmenting B-Tree: High-write volume tables using random UUIDv4 as clustered primary key causing index bloat."
            ],
            remediationPrompt: "Migrate random UUIDv4 to sequential UUIDv7 or BIGSERIAL for write-heavy tables.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-14: Unindexed UUID Primary Key Fragmenting B-Tree detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-15: Uncommitted Database Transaction Connection Leak
    if (/const\s+client\s*=\s*await\s+pool\.connect\(\)/i.test(cleanContent) && !/client\.release\(\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-15|uncommitted/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6015,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-15: Uncommitted Database Transaction Connection Leak',
            severity: 'CRITICAL',
            category: "Connection Pooling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Uncommitted Database Transaction Connection Leak: Acquiring client from pool without ensuring client.release() in finally block."
            ],
            remediationPrompt: "Always wrap client acquisition in try { ... } finally { client.release(); }.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-15: Uncommitted Database Transaction Connection Leak detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-16: Missing Dead-Letter Queue on CDC / Event Stream
    if (/supabase\.channel\([^)]+\)\.on\(\s*["\']postgres_changes["\']/i.test(cleanContent) && !/catch|error|deadletter|dlq/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-16|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6016,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-16: Missing Dead-Letter Queue on CDC / Event Stream',
            severity: 'HIGH',
            category: "Event-Driven DB",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Dead-Letter Queue on CDC / Event Stream: Database change stream triggers lacking dead-letter queues for unparseable payloads."
            ],
            remediationPrompt: "Add try-catch and DLQ fallback table for unhandled CDC webhook payloads.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-16: Missing Dead-Letter Queue on CDC / Event Stream detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-17: Redundant Duplicate Indexes on Same Column Prefix
    if (/CREATE\s+INDEX\s+[^\n]+\s+ON\s+[a-zA-Z0-9_]+\s*\(\s*([a-zA-Z0-9_]+)\s*\)[\s\S]*?CREATE\s+INDEX\s+[^\n]+\s+ON\s+[a-zA-Z0-9_]+\s*\(\s*\1\s*,\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-17|redundant/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6017,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-17: Redundant Duplicate Indexes on Same Column Prefix',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Redundant Duplicate Indexes on Same Column Prefix: Having both INDEX(a) and INDEX(a, b) on table, wasting memory and write I/O."
            ],
            remediationPrompt: "Drop single-column index when composite index with identical leading column exists.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-17: Redundant Duplicate Indexes on Same Column Prefix detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-18: Unbounded JSONB Column Bloat Without Size Cap
    if (/data\s+JSONB\s+NOT\s+NULL/i.test(cleanContent) && !/CHECK\s*\(\s*octet_length/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-18|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6018,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-18: Unbounded JSONB Column Bloat Without Size Cap',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unbounded JSONB Column Bloat Without Size Cap: Storing multi-megabyte JSONB documents in frequently queried operational tables."
            ],
            remediationPrompt: "Store large JSON payloads in object storage and save reference URI in database.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-18: Unbounded JSONB Column Bloat Without Size Cap detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-19: Missing Statement Timeout on Production Database
    if (/createPool|new\s+Pool/i.test(cleanContent) && !/statement_timeout/i.test(cleanContent) && !/test|mock/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-19|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6019,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-19: Missing Statement Timeout on Production Database',
            severity: 'HIGH',
            category: "Resource Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Statement Timeout on Production Database: Database operating without statement_timeout, allowing rogue queries to run for hours."
            ],
            remediationPrompt: "Set statement_timeout = '15000' in PostgreSQL database configuration.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-19: Missing Statement Timeout on Production Database detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-20: Case-Insensitive Query Missing Functional Index
    if (/WHERE\s+LOWER\s*\(\s*[a-zA-Z0-9_]+\s*\)\s*=/i.test(cleanContent) && !/LOWER\(/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-20|case-insensitive/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6020,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-20: Case-Insensitive Query Missing Functional Index',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Case-Insensitive Query Missing Functional Index: Querying WHERE LOWER(email) = ? without functional index ON LOWER(email)."
            ],
            remediationPrompt: "Add CREATE INDEX idx_table_lower_email ON table(LOWER(email));",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-20: Case-Insensitive Query Missing Functional Index detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-21: Uncached Read-Heavy System Settings Queries
    if (/findUnique\(\s*\{\s*where:\s*\{\s*key:\s*["\']system_/i.test(cleanContent) && !/cache|redis/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-21|uncached/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6021,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-21: Uncached Read-Heavy System Settings Queries',
            severity: 'MEDIUM',
            category: "Caching Strategy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Uncached Read-Heavy System Settings Queries: Querying static system configuration or tenant settings on every single HTTP request."
            ],
            remediationPrompt: "Wrap settings queries in Redis cache layer with 10-minute TTL and invalidation hook.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-21: Uncached Read-Heavy System Settings Queries detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-22: Missing Table Partitioning on High-Volume Event Tables
    if (/CREATE\s+TABLE\s+(?:audit_logs|analytics_events|user_activities)/i.test(cleanContent) && !/PARTITION\s+BY/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-22|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6022,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-22: Missing Table Partitioning on High-Volume Event Tables',
            severity: 'HIGH',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Table Partitioning on High-Volume Event Tables: Audit log or analytics tables exceeding 10M rows without monthly/weekly partitioning."
            ],
            remediationPrompt: "Implement declarative table partitioning on high-volume event tables.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-22: Missing Table Partitioning on High-Volume Event Tables detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-23: Un-indexed Array Containment Query (@>)
    if (/@>\s*ARRAY\[/i.test(cleanContent) && !/USING\s+gin/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-23|un-indexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6023,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-23: Un-indexed Array Containment Query (@>)',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Un-indexed Array Containment Query (@>): Querying array columns with ANY() or @> without GIN index support."
            ],
            remediationPrompt: "Create GIN index on array column: CREATE INDEX idx_tags ON table USING gin(tags);",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-23: Un-indexed Array Containment Query (@>) detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-24: Lock Contention from Table Alters in Production
    if (/ALTER\s+TABLE\s+[a-zA-Z0-9_]+\s+ADD\s+COLUMN\s+[^\n]+NOT\s+NULL\s+DEFAULT/i.test(cleanContent) && !/lock_timeout/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-24|lock/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6024,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-24: Lock Contention from Table Alters in Production',
            severity: 'HIGH',
            category: "Zero Downtime",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Lock Contention from Table Alters in Production: Adding columns with non-null defaults without PostgreSQL 11+ metadata optimization."
            ],
            remediationPrompt: "Set lock_timeout = '5s' before executing DDL migrations in production.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-24: Lock Contention from Table Alters in Production detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-25: Missing Optimistic Concurrency Version Column
    if (/update\(\s*\{\s*where:\s*\{\s*id\s*\}[\s\S]*?data:\s*\{(?![^}]*version)/i.test(cleanContent) && /inventory|balance|seat/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-25|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6025,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-25: Missing Optimistic Concurrency Version Column',
            severity: 'MEDIUM',
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Optimistic Concurrency Version Column: Read-modify-write workflows lacking version or updated_at checks, causing lost updates."
            ],
            remediationPrompt: "Add version INT DEFAULT 1 and verify version match on concurrent updates.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-25: Missing Optimistic Concurrency Version Column detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-26: Missing Index on Polymorphic Relationship Columns
    if (/entity_type\s+TEXT[\s\S]*?entity_id\s+(?:UUID|INT)/i.test(cleanContent) && !/CREATE\s+INDEX.*entity_type.*entity_id/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-26|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6026,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-26: Missing Index on Polymorphic Relationship Columns',
            severity: 'HIGH',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Index on Polymorphic Relationship Columns: Polymorphic references (type, entity_id) lacking composite index."
            ],
            remediationPrompt: "Add CREATE INDEX idx_poly ON table(entity_type, entity_id);",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-26: Missing Index on Polymorphic Relationship Columns detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-27: Direct COUNT(*) Query on Giant Table
    if (/SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+(?:logs|events|transactions|users)/i.test(cleanContent) && !/WHERE/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-27|direct/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6027,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-27: Direct COUNT(*) Query on Giant Table',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Direct COUNT(*) Query on Giant Table: Running SELECT COUNT(*) on multi-million row table for UI pagination total count."
            ],
            remediationPrompt: "Replace exact COUNT(*) with pg_class reltuples estimate or Redis counter.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-27: Direct COUNT(*) Query on Giant Table detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-28: Missing pg_stat_statements Query Monitoring
    if (/shared_preload_libraries/i.test(cleanContent) && !/pg_stat_statements/i.test(cleanContent) && /postgres.*conf/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-28|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6028,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-28: Missing pg_stat_statements Query Monitoring',
            severity: 'MEDIUM',
            category: "Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing pg_stat_statements Query Monitoring: Production database lacking pg_stat_statements extension for slow query tracking."
            ],
            remediationPrompt: "Add pg_stat_statements to PostgreSQL configuration to log slow queries.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-28: Missing pg_stat_statements Query Monitoring detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-29: Realtime WebSocket Channel Flooding Without Filter
    if (/(?:supabase\.channel|realtime\.channel|socket\.on)\([^)]+\)\.on\(\s*["\'](?:postgres_changes|change|events)["\'],\s*\{\s*event:\s*["\']\*["\'],\s*schema:\s*["\']public["\'],\s*table:\s*["\'][^"\']+["\']\s*\}\s*,\s*\(payload\)/i.test(cleanContent) && !/filter:/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-29|channel/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6029,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-29: Realtime WebSocket Channel Flooding Without Filter',
            severity: 'HIGH',
            category: "Resource Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned realtime event stream architecture in ${file.path}:${lineNum}.`,
                "Detected Realtime WebSocket Channel Flooding Without Filter: Subscribing to change events on an entire table without filter predicates."
            ],
            remediationPrompt: "Add row filter parameter to realtime channel subscription.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-29: Realtime WebSocket Channel Flooding Without Filter detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-30: Prisma Schema Missing @@index on Search Columns
    if (/model\s+[a-zA-Z0-9_]+\s*\{[\s\S]*?tenantId\s+String[\s\S]*?\}(?![^}]*@@index)/i.test(cleanContent) && file.path.endsWith(".prisma")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-30|prisma/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6030,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-30: Prisma Schema Missing @@index on Search Columns',
            severity: 'HIGH',
            category: "ORM Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Prisma Schema Missing @@index on Search Columns: Prisma model queried by status or tenantId without @@index in schema.prisma."
            ],
            remediationPrompt: "Add @@index([tenantId, status]) to model in schema.prisma and migrate.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-30: Prisma Schema Missing @@index on Search Columns detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-31: Implicit Type Coercion Preventing Index Scan
    if (/WHERE\s+[a-zA-Z0-9_]+_str\s*=\s*\d+\b/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-31|implicit/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6031,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-31: Implicit Type Coercion Preventing Index Scan',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Implicit Type Coercion Preventing Index Scan: Comparing VARCHAR column with integer literal, forcing full table scan."
            ],
            remediationPrompt: "Ensure query parameters are cast to exact column type (e.g. String(id)).",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-31: Implicit Type Coercion Preventing Index Scan detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-32: Unindexed Soft-Delete (deleted_at) Queries
    if (/deleted_at\s+IS\s+NULL/i.test(cleanContent) && !/WHERE\s+deleted_at\s+IS\s+NULL/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-32|unindexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6032,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-32: Unindexed Soft-Delete (deleted_at) Queries',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unindexed Soft-Delete (deleted_at) Queries: Filtering WHERE deleted_at IS NULL on every query without partial index."
            ],
            remediationPrompt: "Add partial index for active non-deleted rows to eliminate table scans.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-32: Unindexed Soft-Delete (deleted_at) Queries detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-33: Missing Foreign Key Cascade Delete Lock Warning
    if (/ON\s+DELETE\s+CASCADE/i.test(cleanContent) && /organizations|tenants|accounts/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-33|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6033,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-33: Missing Foreign Key Cascade Delete Lock Warning',
            severity: 'HIGH',
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Foreign Key Cascade Delete Lock Warning: Deleting parent row in high-traffic table cascading to 100k child rows, locking tables."
            ],
            remediationPrompt: "Delete child rows in small batched transactions prior to deleting parent entity.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-33: Missing Foreign Key Cascade Delete Lock Warning detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-34: Unbounded In-Memory Array Sorting in ORM
    if (/(?:await\s+prisma\.[a-zA-Z0-9_]+\.findMany\(\)|await\s+db\.select\(\))[\s\S]*?\.sort\(\s*\([^)]*\)\s*=>/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-34|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6034,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-34: Unbounded In-Memory Array Sorting in ORM',
            severity: 'HIGH',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unbounded In-Memory Array Sorting in ORM: Fetching all rows into Node.js memory and sorting with .sort(), crashing process."
            ],
            remediationPrompt: "Move array sorting into database query via orderBy: { createdAt: 'desc' }.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-34: Unbounded In-Memory Array Sorting in ORM detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-35: Missing Database Backup Automated Verification
    if (/backup_cron|pg_dump/i.test(cleanContent) && !/restore_test|verify_backup/i.test(cleanContent) && /script|ci/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-35|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6035,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-35: Missing Database Backup Automated Verification',
            severity: 'CRITICAL',
            category: "Disaster Recovery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Database Backup Automated Verification: Database automated backups running without periodic restoration drills."
            ],
            remediationPrompt: "Implement automated script testing database dump restoration in staging weekly.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-35: Missing Database Backup Automated Verification detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-36: Prisma include Over-Fetching Nested Graphs
    if (/include:\s*\{[\s\S]*?include:\s*\{[\s\S]*?include:\s*\{/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-36|prisma/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6036,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-36: Prisma include Over-Fetching Nested Graphs',
            severity: 'HIGH',
            category: "ORM Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Prisma include Over-Fetching Nested Graphs: Using include: { deepRel: { include: { ... } } } fetching 500KB JSON payload per row."
            ],
            remediationPrompt: "Replace broad include with specific select projection for related entities.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-36: Prisma include Over-Fetching Nested Graphs detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-37: Missing Unique Constraint on Natural Key Columns
    if (/email\s+TEXT\s+NOT\s+NULL/i.test(cleanContent) && !/UNIQUE/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-37|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6037,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-37: Missing Unique Constraint on Natural Key Columns',
            severity: 'HIGH',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Unique Constraint on Natural Key Columns: Enforcing uniqueness only in application code without database UNIQUE constraint."
            ],
            remediationPrompt: "Add ALTER TABLE table ADD CONSTRAINT uq_col UNIQUE (col); to migrations.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-37: Missing Unique Constraint on Natural Key Columns detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-38: Database Connection String with Plaintext Password in Repo
    if (/DATABASE_URL\s*=\s*["\']postgres(?:ql)?:\/\/[^:]+:[^@]+@/i.test(cleanContent) && !/\.env/i.test(lowerPath) && !/localhost/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-38|database/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6038,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-38: Database Connection String with Plaintext Password in Repo',
            severity: 'CRITICAL',
            category: "Secret Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Database Connection String with Plaintext Password in Repo: Direct database credentials committed in codebase or client configuration."
            ],
            remediationPrompt: "Move DATABASE_URL into .env and load securely via process.env.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-38: Database Connection String with Plaintext Password in Repo detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-39: Missing Deadlock Detection & Automatic Retry
    if (/\$transaction/i.test(cleanContent) && !/40P01|deadlock|retry/i.test(cleanContent) && /payment|ledger|transfer/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-39|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6039,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-39: Missing Deadlock Detection & Automatic Retry',
            severity: 'HIGH',
            category: "Fault Tolerance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Deadlock Detection & Automatic Retry: Database transactions failing permanently on serialization/deadlock errors (40P01)."
            ],
            remediationPrompt: "Wrap database transactions in retry runner handling error code 40P01.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-39: Missing Deadlock Detection & Automatic Retry detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-40: Unindexed Date Range Query Bottleneck
    if (/WHERE\s+created_at\s+BETWEEN/i.test(cleanContent) && !/CREATE\s+INDEX.*created_at/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-40|unindexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6040,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-40: Unindexed Date Range Query Bottleneck',
            severity: 'MEDIUM',
            category: "Query Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unindexed Date Range Query Bottleneck: Filtering WHERE created_at BETWEEN ? AND ? on unindexed timestamp column."
            ],
            remediationPrompt: "Add CREATE INDEX idx_created_at ON table USING brin(created_at);",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-40: Unindexed Date Range Query Bottleneck detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-41: Synchronous Heavy Aggregation in User Request Path
    if (/app\/api\/dashboard/i.test(lowerPath) && /GROUP\s+BY\s+[a-zA-Z0-9_,\s]+/i.test(cleanContent) && !/materialized|rollup/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-41|synchronous/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6041,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-41: Synchronous Heavy Aggregation in User Request Path',
            severity: 'HIGH',
            category: "Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Synchronous Heavy Aggregation in User Request Path: Executing complex GROUP BY across 5M rows on user dashboard page load."
            ],
            remediationPrompt: "Pre-calculate dashboard metrics in a scheduled background rollup table.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-41: Synchronous Heavy Aggregation in User Request Path detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-42: Missing Autovacuum Tuning on High-Churn Tables
    if (/autovacuum_vacuum_scale_factor/i.test(cleanContent) && />\s*0\.2/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-42|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6042,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-42: Missing Autovacuum Tuning on High-Churn Tables',
            severity: 'HIGH',
            category: "Database Maintenance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Autovacuum Tuning on High-Churn Tables: High-update queue/job tables suffering from table bloat due to default autovacuum."
            ],
            remediationPrompt: "Set (autovacuum_vacuum_scale_factor = 0.05) on high-write table storage params.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-42: Missing Autovacuum Tuning on High-Churn Tables detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-43: Unprepared Dynamic SQL Query Injections
    if (/(?:db\.query|client\.query|prisma\.\$queryRawUnsafe)\s*\(\s*`[^`]*\$\{/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-43|unprepared/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6043,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-43: Unprepared Dynamic SQL Query Injections',
            severity: 'CRITICAL',
            category: "Database Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unprepared Dynamic SQL Query Injections: Concatenating raw user variables into SQL strings without parameterized bindings."
            ],
            remediationPrompt: "Replace string template queries with parameterized query placeholders.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-43: Unprepared Dynamic SQL Query Injections detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-44: Missing Read Replica Routing for Analytical Queries
    if (/app\/api\/(?:reports|export|analytics)/i.test(lowerPath) && /prisma\./i.test(cleanContent) && !/readReplica|RO_DATABASE_URL/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-44|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6044,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-44: Missing Read Replica Routing for Analytical Queries',
            severity: 'HIGH',
            category: "Read Scaling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Read Replica Routing for Analytical Queries: Running long analytical export queries directly on primary write database replica."
            ],
            remediationPrompt: "Configure secondary Prisma/pg client pointed to read replica for reports.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-44: Missing Read Replica Routing for Analytical Queries detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-45: Unindexed Enum Column Filtering
    if (/WHERE\s+status\s*=\s*[\'"](?:PENDING|PROCESSING)[\'"]/i.test(cleanContent) && !/CREATE\s+INDEX.*WHERE\s+status/i.test(cleanContent) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-45|unindexed/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6045,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-45: Unindexed Enum Column Filtering',
            severity: 'MEDIUM',
            category: "Schema Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unindexed Enum Column Filtering: Frequently filtering by enum column (status = 'PENDING') on table with 1M rows."
            ],
            remediationPrompt: "Add partial index: CREATE INDEX idx_pending ON table(id) WHERE status = 'PENDING';",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-45: Unindexed Enum Column Filtering detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-46: Missing Redis Lock on Database Mutation Race Condition
    if (/stripe-webhook|polar-webhook/i.test(lowerPath) && /updateUserTier|creditBalance/i.test(cleanContent) && !/redlock|advisory_lock|mutex/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-46|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6046,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-46: Missing Redis Lock on Database Mutation Race Condition',
            severity: 'HIGH',
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Redis Lock on Database Mutation Race Condition: Simultaneous webhook callbacks updating same user balance without distributed lock."
            ],
            remediationPrompt: "Acquire distributed lock before executing balance adjustments.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-46: Missing Redis Lock on Database Mutation Race Condition detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-47: Un-batched ORM DeleteMany Cascade Contention
    if (/prisma\.[a-zA-Z0-9_]+\.deleteMany\(\s*\{(?![^}]*limit)/i.test(cleanContent) && !/chunk/i.test(cleanContent) && /cleanup|prune|cron/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-47|un-batched/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6047,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-47: Un-batched ORM DeleteMany Cascade Contention',
            severity: 'HIGH',
            category: "Write Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Un-batched ORM DeleteMany Cascade Contention: Executing deleteMany() across 100k rows holding exclusive table lock."
            ],
            remediationPrompt: "Delete in batches of 1000 rows in a loop until zero rows remain.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-47: Un-batched ORM DeleteMany Cascade Contention detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-48: Missing SSL/TLS Enforcement on Production DB Connections
    if (/DATABASE_URL.*postgres/i.test(cleanContent) && !/sslmode=require|ssl=true/i.test(cleanContent) && !/localhost|127\.0\.0\.1/i.test(cleanContent) && /production/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-48|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6048,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-48: Missing SSL/TLS Enforcement on Production DB Connections',
            severity: 'CRITICAL',
            category: "Database Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing SSL/TLS Enforcement on Production DB Connections: Database connection string missing sslmode=require or ssl=true parameter."
            ],
            remediationPrompt: "Append ?sslmode=require to all production database connection strings.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-48: Missing SSL/TLS Enforcement on Production DB Connections detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-49: Unbounded Connection Spike on HTTP Traffic Burst
    if (/new\s+Pool\(\s*\{[\s\S]*?max:\s*(?:50|100|200)\b/i.test(cleanContent) && /serverless|vercel/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-49|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6049,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-49: Unbounded Connection Spike on HTTP Traffic Burst',
            severity: 'HIGH',
            category: "Connection Pooling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Unbounded Connection Spike on HTTP Traffic Burst: Traffic surge opening 500 simultaneous serverless connections, exceeding DB max_connections."
            ],
            remediationPrompt: "Enforce max connection bounds (e.g. max: 5) per serverless lambda instance.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-49: Unbounded Connection Spike on HTTP Traffic Burst detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-50: Missing Transaction Isolation Level Specification
    if (/BEGIN\s+TRANSACTION;(?!\s+ISOLATION\s+LEVEL)/i.test(cleanContent) && /balance|ledger|transfer/i.test(lowerPath) && file.path.endsWith(".sql")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/db-perf-50|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6050,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-50: Missing Transaction Isolation Level Specification',
            severity: 'HIGH',
            category: "Concurrency & Locks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected database or orm pattern>',
            reproductionSteps: [
                `Scanned database and ORM architecture in ${file.path}:${lineNum}.`,
                "Detected Missing Transaction Isolation Level Specification: Financial balance transfers operating under default READ COMMITTED, risking race condition."
            ],
            remediationPrompt: "Declare SET TRANSACTION ISOLATION LEVEL SERIALIZABLE for financial ledgers.",
            status: 'OPEN',
            owner: 'Database Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🗄️ DB-PERF-50: Missing Transaction Isolation Level Specification detected (${file.path}:${lineNum})`);
    }
    // DB-PERF-51: Migration Takes a Blocking Table Lock (NOT NULL without DEFAULT / non-concurrent index)
    if (/\.sql$/i.test(lowerPath) && /migrations?\//i.test(lowerPath)) {
        const createdTables = new Set(
            Array.from(cleanContent.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)/gi), (m) => m[1].replace(/"/g, '').split('.').pop()!.toLowerCase())
        );
        const lockingStatements = cleanContent.split(';').map((stmt) => stmt.replace(/--[^\n]*/g, '')).filter((stmt) => {
            if (/ADD\s+COLUMN[^,]*\bNOT\s+NULL\b/i.test(stmt) && !/\bDEFAULT\b/i.test(stmt)) return true;
            const index = stmt.match(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)(?:IF\s+NOT\s+EXISTS\s+)?[\w."]+\s+ON\s+(?:ONLY\s+)?([\w."]+)/i);
            return !!index && !createdTables.has(index[1].replace(/"/g, '').split('.').pop()!.toLowerCase());
        });
        if (lockingStatements.length > 0) {
            const statementLines = lockingStatements[0].split('\n').map((l) => l.trim()).filter(Boolean);
            const firstStatement = statementLines.find((l) => /ADD\s+COLUMN|CREATE\s+(?:UNIQUE\s+)?INDEX/i.test(l)) || statementLines[0] || '';
            const matchLineIdx = lines.findIndex(l => l.includes(firstStatement));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            findings.push({
                id: `dbperf-${Date.now()}-${findingCounter.count++}`,
                ruleId: 6051,
                type: 'INFRA_DATABASE',
                title: 'DB-PERF-51: Migration Takes a Blocking Table Lock on an Existing Table',
                severity: 'HIGH',
                category: "Concurrency & Locks",
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: lines[matchLineIdx] || firstStatement,
                reproductionSteps: [
                    `Scanned migration ${file.path}:${lineNum}.`,
                    'Adding a NOT NULL column without DEFAULT fails on non-empty tables, and CREATE INDEX without CONCURRENTLY blocks writes for the whole build.'
                ],
                remediationPrompt: "Add the column as nullable (or with a DEFAULT), backfill, then SET NOT NULL; build indexes on existing tables with CREATE INDEX CONCURRENTLY in a migration that does not run inside a transaction.",
                status: 'OPEN',
                owner: 'Database Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🗄️ DB-PERF-51: Blocking migration lock detected (${file.path}:${lineNum})`);
        }
    }
    return { findings, logs };
}
