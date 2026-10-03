/**
 * Zelsis Master Database & ORM Performance Evaluator (50 Rules)
 * Rules DB-PERF-01 to DB-PERF-50 (Rule IDs 6001 to 6050).
 *
 * Detects N+1 query loops, unindexed foreign keys, deep offset pagination traps,
 * connection pool exhaustion in serverless runtimes, and transaction lock contention.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { emptyRepoContext, normalizeSqlName, RepoContext } from '../scanner/repo-context';
import { locateMatchLine } from './shared/locate';
export interface DatabaseRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateDatabaseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}, context: RepoContext = emptyRepoContext()): DatabaseRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // DB-PERF-01: Prisma / ORM N+1 Query in Loop
    // An awaited Prisma read inside the body of a for...of loop or an async .map() callback (one query per element)
    const n1Line = (() => {
        for (const m of cleanContent.matchAll(/\bfor\s*\(\s*(?:const|let|var)\s+[^)]*\s+of\s+[^)]*\)\s*\{|\.map\s*\(\s*async\s*(?:\([^)]*\)|\w+)\s*=>\s*\{/g)) {
            let depth = 1;
            let i = m.index! + m[0].length;
            while (i < cleanContent.length && depth > 0) {
                if (cleanContent[i] === '{') depth++;
                else if (cleanContent[i] === '}') depth--;
                i++;
            }
            const body = cleanContent.slice(m.index! + m[0].length, i);
            const call = body.search(/\bawait\s+(?:this\.)?(?:prisma|db|tx)\.\w+\.(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|count)\s*\(/);
            if (call !== -1) return cleanContent.slice(0, m.index! + m[0].length + call).split('\n').length - 1;
        }
        return -1;
    })();
    if (n1Line !== -1) {
        const matchLineIdx = n1Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6001,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-01: Prisma / ORM N+1 Query in Loop',
            severity: 'MEDIUM',
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
    // DB-PERF-03: Deep Offset Pagination Performance Trap
    if (/\.skip\(\s*(?:1000|[2-9]\d{3,}|\d{5,})\s*\)|OFFSET\s+(?:1000|[2-9]\d{3,}|\d{5,})\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/\.skip\(\s*(?:1000|[2-9]\d{3,}|\d{5,})\s*\)|OFFSET\s+(?:1000|[2-9]\d{3,}|\d{5,})\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6003,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-03: Deep Offset Pagination Performance Trap',
            severity: 'LOW',
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
    // DB-PERF-05: Direct Unpooled Database Connection in Edge / Serverless
    // A pg Pool/Client created inside the request handler opens new connections on every request; module scope is reused across warm invocations
    const handlerBody = cleanContent.slice(Math.max(0, cleanContent.search(/export\s+(?:default\s+)?(?:async\s+)?function\s*(?:GET|POST|PUT|PATCH|DELETE|handler)?\s*\(/)));
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /from\s+['"]pg['"]|require\(\s*['"]pg['"]\s*\)/.test(cleanContent) && /export\s+(?:default\s+)?(?:async\s+)?function/.test(cleanContent) && /new\s+(?:Pool|Client)\s*\(/.test(handlerBody) && !/\.end\(\)/.test(handlerBody) && !/globalThis|singleton/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+(?:Pool|Client)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6005,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-05: Direct Unpooled Database Connection in Edge / Serverless',
            severity: 'HIGH',
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
    // DB-PERF-09: Long-Running External API Call Inside DB Transaction
    // Only calls inside the transaction callback body count, so brace-match the body instead of scanning to EOF
    const txExternalCallLine = (() => {
        for (const m of cleanContent.matchAll(/\$transaction\s*\(\s*async\s*\([^)]*\)\s*=>\s*\{/g)) {
            let depth = 1;
            let i = m.index! + m[0].length;
            while (i < cleanContent.length && depth > 0) {
                if (cleanContent[i] === '{') depth++;
                else if (cleanContent[i] === '}') depth--;
                i++;
            }
            const body = cleanContent.slice(m.index! + m[0].length, i);
            const call = body.search(/\bfetch\(|axios\.|openai\.|anthropic\./);
            if (call !== -1) return cleanContent.slice(0, m.index! + m[0].length + call).split('\n').length - 1;
        }
        return -1;
    })();
    if (txExternalCallLine !== -1) {
        const matchLineIdx = txExternalCallLine;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6009,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-09: Long-Running External API Call Inside DB Transaction',
            severity: 'HIGH',
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
    // Only tables in the API-exposed public schema (unqualified or public.*); the finding points at that table's CREATE TABLE line
    const tablesWithoutRls = [...cleanContent.matchAll(/CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)/gi)]
        .filter((m) => !/\./.test(m[1].replace(/"/g, '')) || /^"?public"?\./i.test(m[1]))
        .filter((m) => {
            const t = normalizeSqlName(m[1]);
            return !context.rlsEnabledTables.has(t) && !new RegExp(String.raw`ALTER\s+TABLE\s+[^;]*\b` + t + String.raw`\b[^;]*ENABLE\s+ROW\s+LEVEL\s+SECURITY`, 'i').test(cleanContent);
        });
    if (context.exposesDatabaseToClients && tablesWithoutRls.length > 0 && file.path.endsWith(".sql")) {
        const matchLineIdx = cleanContent.slice(0, tablesWithoutRls[0].index).split('\n').length - 1;
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
    // DB-PERF-15: Uncommitted Database Transaction Connection Leak
    if (/(?:const|let)\s+\w+\s*=\s*await\s+pool\.connect\(\)/i.test(cleanContent) && !/\.release\(\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:const|let)\s+\w+\s*=\s*await\s+pool\.connect\(\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6015,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-15: Uncommitted Database Transaction Connection Leak',
            severity: 'HIGH',
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
    // DB-PERF-17: Redundant Duplicate Indexes on Same Column Prefix
    // A plain (non-unique, non-partial, btree) single-column index whose column leads another plain index on the SAME table
    const redundantIndexLine = (() => {
        if (!file.path.endsWith('.sql')) return -1;
        const idx = [...cleanContent.matchAll(/CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?[\w."]+\s+ON\s+(?:ONLY\s+)?([\w."]+)\s*(?:USING\s+btree\s*)?\(([^()]*)\)\s*(WHERE)?/gi)]
            .filter((m) => !m[3])
            .map((m) => ({ at: m.index!, table: normalizeSqlName(m[1]), cols: m[2].split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase()) }));
        for (const single of idx.filter((i) => i.cols.length === 1)) {
            if (idx.some((o) => o !== single && o.table === single.table && o.cols.length > 1 && o.cols[0] === single.cols[0])) {
                return cleanContent.slice(0, single.at).split('\n').length - 1;
            }
        }
        return -1;
    })();
    if (redundantIndexLine !== -1) {
        const matchLineIdx = redundantIndexLine;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6017,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-17: Redundant Duplicate Indexes on Same Column Prefix',
            severity: 'LOW',
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
    // DB-PERF-29: Realtime WebSocket Channel Flooding Without Filter
    if (/(?:supabase\s*\.channel|realtime\.channel|socket\.on)\([^)]+\)\.on\(\s*["\'](?:postgres_changes|change|events)["\'],\s*\{\s*event:\s*["\']\*["\'],\s*schema:\s*["\']public["\'],\s*table:\s*["\'][^"\']+["\']\s*\}\s*,\s*\(payload\)/i.test(cleanContent) && !/filter:/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:supabase\s*\.channel|realtime\.channel|socket\.on)\([^)]+\)\.on\(\s*["\'](?:postgres_changes|change|events)["\'],\s*\{\s*event:\s*["\']\*["\'],\s*schema:\s*["\']public["\'],\s*table:\s*["\'][^"\']+["\']\s*\}\s*,\s*\(payload\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6029,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-29: Realtime WebSocket Channel Flooding Without Filter',
            severity: 'LOW',
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
    // DB-PERF-34: Unbounded In-Memory Array Sorting in ORM
    if (/(?:await\s+prisma\.[a-zA-Z0-9_]+\.findMany\(\)|await\s+db\.select\(\))[\s\S]*?\.sort\(\s*\([^)]*\)\s*=>/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:await\s+prisma\.[a-zA-Z0-9_]+\.findMany\(\)|await\s+db\.select\(\))[\s\S]*?\.sort\(\s*\([^)]*\)\s*=>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `dbperf-${Date.now()}-${findingCounter.count++}`,
            ruleId: 6034,
            type: 'INFRA_DATABASE',
            title: 'DB-PERF-34: Unbounded In-Memory Array Sorting in ORM',
            severity: 'MEDIUM',
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
    // DB-PERF-38: Database Connection String with Plaintext Password in Repo
    if (/DATABASE_URL\s*=\s*["\']postgres(?:ql)?:\/\/[^:]+:[^@]+@/i.test(cleanContent) && !/\.env/i.test(lowerPath) && !/localhost/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/DATABASE_URL\s*=\s*["\']postgres(?:ql)?:\/\/[^:]+:[^@]+@/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // DB-PERF-43: Unprepared Dynamic SQL Query Injections
    if (/(?:db\.query|client\.query|prisma\.\$queryRawUnsafe)\s*\(\s*`[^`]*\$\{/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:db\.query|client\.query|prisma\.\$queryRawUnsafe)\s*\(\s*`[^`]*\$\{/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
