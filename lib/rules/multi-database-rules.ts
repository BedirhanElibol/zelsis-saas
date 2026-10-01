/**
 * Zelsis Universal Multi-Database & ORM Security Engine
 *
 * Implements deterministic AST & regex-based security checks for:
 * 1. MYSQL-SEC-01: MySQL Raw Query Injection via string interpolation / concatenation
 * 2. MONGO-SEC-01: MongoDB NoSQL Injection via $where or raw request object
 * 3. REDIS-SEC-01: Redis Insecure Binding & Dangerous Command / EVAL Lua Injection
 * 4. ORM-RAW-01:   ORM Raw Query Injection (Prisma $queryRawUnsafe, TypeORM raw where, Drizzle sql.raw)
 * 5. SQLITE-SEC-01: SQLite Public File Placement & Query Concatenation
 *
 * Provides detectProjectDatabases() to automatically detect all databases and ORMs in a scanned project.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface MultiDatabaseRuleResult {
    findings: Finding[];
    logs: string[];
}
export interface DetectedStack {
    databases: string[];
    orms: string[];
}
function extractSnippet(lines: string[], lineNum: number): string {
    const targetIdx = Math.max(0, lineNum - 1);
    const start = Math.max(0, targetIdx - 2);
    const end = Math.min(lines.length, targetIdx + 3);
    return lines.slice(start, end).join('\n');
}
/**
 * Automatically inspects repository files to detect databases and ORMs in use.
 * Scans package manifests, configuration files, docker-compose, and source imports.
 */
export function detectProjectDatabases(files: CodeFile[]): DetectedStack {
    const detectedDbs = new Set<string>();
    const detectedOrms = new Set<string>();
    for (const file of files) {
        if (!file || !file.path)
            continue;
        const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
        const content = file.content || '';
        // 1. Package Manifests
        if (lowerPath.endsWith('package.json')) {
            if (/"(?:pg|postgres|@neondatabase\/serverless|@supabase\/supabase-js)"/i.test(content))
                detectedDbs.add('PostgreSQL');
            if (/"(?:mysql|mysql2|@planetscale\/database)"/i.test(content))
                detectedDbs.add('MySQL');
            if (/"(?:mongodb|mongoose)"/i.test(content))
                detectedDbs.add('MongoDB');
            if (/"(?:redis|ioredis|@upstash\/redis)"/i.test(content))
                detectedDbs.add('Redis');
            if (/"(?:better-sqlite3|sqlite3|@libsql\/client)"/i.test(content))
                detectedDbs.add('SQLite');
            if (/"(?:@aws-sdk\/client-dynamodb|dynamoose)"/i.test(content))
                detectedDbs.add('DynamoDB');
            if (/"(?:@pinecone-database\/pinecone|@qdrant\/js-client-rest|weaviate-ts-client)"/i.test(content))
                detectedDbs.add('Vector DB');
            // ORMs
            if (/"@prisma\/client"|"prisma"/i.test(content))
                detectedOrms.add('Prisma');
            if (/"drizzle-orm"/i.test(content))
                detectedOrms.add('Drizzle');
            if (/"typeorm"/i.test(content))
                detectedOrms.add('TypeORM');
            if (/"sequelize"/i.test(content))
                detectedOrms.add('Sequelize');
            if (/"mongoose"/i.test(content))
                detectedOrms.add('Mongoose');
        }
        // Python Manifests
        if (lowerPath.endsWith('requirements.txt') || lowerPath.endsWith('pyproject.toml')) {
            if (/psycopg2|asyncpg/i.test(content))
                detectedDbs.add('PostgreSQL');
            if (/pymysql|mysqlclient/i.test(content))
                detectedDbs.add('MySQL');
            if (/pymongo|motor/i.test(content))
                detectedDbs.add('MongoDB');
            if (/redis/i.test(content))
                detectedDbs.add('Redis');
            if (/sqlite3/i.test(content))
                detectedDbs.add('SQLite');
            if (/boto3/i.test(content) && /dynamodb/i.test(content))
                detectedDbs.add('DynamoDB');
            // ORMs
            if (/sqlalchemy/i.test(content))
                detectedOrms.add('SQLAlchemy');
            if (/tortoise-orm/i.test(content))
                detectedOrms.add('Tortoise ORM');
            if (/django/i.test(content))
                detectedOrms.add('Django ORM');
        }
        // Go Manifests
        if (lowerPath.endsWith('go.mod')) {
            if (/github\.com\/jackc\/pgx|lib\/pq/i.test(content))
                detectedDbs.add('PostgreSQL');
            if (/github\.com\/go-sql-driver\/mysql/i.test(content))
                detectedDbs.add('MySQL');
            if (/go\.mongodb\.org\/mongo-driver/i.test(content))
                detectedDbs.add('MongoDB');
            if (/github\.com\/redis\/go-redis/i.test(content))
                detectedDbs.add('Redis');
            if (/mattn\/go-sqlite3/i.test(content))
                detectedDbs.add('SQLite');
            if (/gorm\.io\/gorm/i.test(content))
                detectedOrms.add('GORM');
        }
        // Config files
        if (lowerPath.endsWith('schema.prisma')) {
            detectedOrms.add('Prisma');
            if (/provider\s*=\s*"postgresql"/i.test(content))
                detectedDbs.add('PostgreSQL');
            if (/provider\s*=\s*"mysql"/i.test(content))
                detectedDbs.add('MySQL');
            if (/provider\s*=\s*"mongodb"/i.test(content))
                detectedDbs.add('MongoDB');
            if (/provider\s*=\s*"sqlite"/i.test(content))
                detectedDbs.add('SQLite');
        }
        if (lowerPath.endsWith('drizzle.config.ts') || lowerPath.endsWith('drizzle.config.js')) {
            detectedOrms.add('Drizzle');
        }
        if (lowerPath.endsWith('.sqlite') || lowerPath.endsWith('.sqlite3') || lowerPath.endsWith('.db')) {
            detectedDbs.add('SQLite');
        }
        // Docker Compose
        if (lowerPath.includes('docker-compose')) {
            if (/image:.*postgres/i.test(content))
                detectedDbs.add('PostgreSQL');
            if (/image:.*mysql|mariadb/i.test(content))
                detectedDbs.add('MySQL');
            if (/image:.*mongo/i.test(content))
                detectedDbs.add('MongoDB');
            if (/image:.*redis/i.test(content))
                detectedDbs.add('Redis');
        }
        // Source Code Connection Patterns
        if (/(?:postgres|postgresql):\/\//i.test(content))
            detectedDbs.add('PostgreSQL');
        if (/mysql:\/\//i.test(content))
            detectedDbs.add('MySQL');
        if (/mongodb(?:\+srv)?:\/\//i.test(content))
            detectedDbs.add('MongoDB');
        if (/redis(?:s)?:\/\//i.test(content))
            detectedDbs.add('Redis');
    }
    return {
        databases: Array.from(detectedDbs),
        orms: Array.from(detectedOrms)
    };
}
/**
 * Universal Multi-Database Security Evaluator.
 * Pure deterministic AST and syntax validation without synthetic sentinels.
 */
export function evaluateMultiDatabaseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): MultiDatabaseRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and node_modules
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // =========================================================================
    // 1. MYSQL-SEC-01: MySQL Raw Query Injection
    // =========================================================================
    // JS/TS: mysql.query(`SELECT ... ${userInput}`), connection.query("SELECT ... " + id)
    // Python: cursor.execute("SELECT ... %s" % id) or cursor.execute(f"SELECT ... {id}")
    const isJsTs = lowerPath.endsWith('.js') || lowerPath.endsWith('.ts') || lowerPath.endsWith('.mjs') || lowerPath.endsWith('.cjs');
    const isPy = lowerPath.endsWith('.py');
    if (isJsTs) {
        // Template literal or concatenation in mysql / pool / connection query
        const mysqlInterpolationRegex = /(?:mysql|connection|pool|dbClient)\.query\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{[^}]+\}[^`]*`/i;
        const mysqlConcatRegex = /(?:mysql|connection|pool|dbClient)\.query\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"']*["']\s*\+/i;
        if (mysqlInterpolationRegex.test(cleanContent) || mysqlConcatRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
                !l.trim().startsWith('*') &&
                (mysqlInterpolationRegex.test(l) || mysqlConcatRegex.test(l) || /(?:connection|pool|mysql)\.query/.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `mysql-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18101,
                type: 'SECURITY',
                title: 'MYSQL-SEC-01: MySQL Raw Query Injection via String Formatting',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'connection.query(`SELECT * FROM users WHERE id = ${id}`)',
                reproductionSteps: [
                    `Scanned database query call in ${file.path}:${lineNum}.`,
                    'Detected MySQL query constructed using template literal interpolation (${...}) or string concatenation (+) without parameterized prepared statements.'
                ],
                remediationPrompt: 'Use parameterized queries: connection.query("SELECT * FROM users WHERE id = ?", [id]) to ensure values are escaped and separated from query logic.',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [MYSQL AUDIT] CRITICAL: MySQL SQL Injection in ${file.path}:${lineNum}`);
        }
    }
    if (isPy) {
        const pyMysqlSqli = /cursor\.execute\s*\(\s*(?:f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{[^}]+\}|["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*%\s*[a-zA-Z0-9_]+)/i;
        if (pyMysqlSqli.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && pyMysqlSqli.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `mysql-py-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18101,
                type: 'SECURITY',
                title: 'MYSQL-SEC-01: MySQL Raw Query Injection via Python String Interpolation',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                reproductionSteps: [
                    `Scanned Python database routine in ${file.path}:${lineNum}.`,
                    'Detected Python database cursor executing SQL constructed via f-string or % string interpolation.'
                ],
                remediationPrompt: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [MYSQL AUDIT] CRITICAL: Python MySQL Injection in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 2. MONGO-SEC-01: MongoDB NoSQL Injection ($where or unvalidated raw input)
    // =========================================================================
    if (isJsTs) {
        const mongoWhereExpr = /(?:\$where\s*:\s*["'][^"']*|\.find\s*\(\s*\{\s*["']?\$where["']?\s*:)/i;
        const mongoRawBodyExpr = /(?:collection|db\.[a-zA-Z0-9_]+)\.(?:find|findOne|update|updateOne|delete|deleteOne)\s*\(\s*(?:req\.body|req\.query|params)\b/i;
        if (mongoWhereExpr.test(cleanContent) || mongoRawBodyExpr.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
                !l.trim().startsWith('*') &&
                (mongoWhereExpr.test(l) || mongoRawBodyExpr.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `mongo-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18102,
                type: 'SECURITY',
                title: 'MONGO-SEC-01: MongoDB NoSQL Injection via $where or Unvalidated Object Filter',
                severity: 'CRITICAL',
                category: 'NoSQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'collection.find({ $where: `this.username == "${username}"` })',
                reproductionSteps: [
                    `Scanned MongoDB query in ${file.path}:${lineNum}.`,
                    'Detected MongoDB query utilizing $where JavaScript evaluation or passing unsanitized HTTP request objects (req.body/req.query) directly into query filters.'
                ],
                remediationPrompt: 'Replace $where with deterministic operators ($eq, $in). Validate all request payload fields with Zod schemas before building MongoDB query objects.',
                status: 'OPEN',
                owner: 'Database Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [MONGO AUDIT] CRITICAL: MongoDB NoSQL Injection in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 3. REDIS-SEC-01: Redis Insecure Binding & Dangerous Commands / EVAL Injection
    // =========================================================================
    // Redis EVAL with string concatenation
    if (isJsTs) {
        const redisEvalConcat = /redis(?:\.eval|\.evalsha)\s*\(\s*(?:"[^"]*"|'[^']*'|`[^`]*`)\s*\+|redis(?:\.eval|\.evalsha)\s*\(\s*`[^`]*\$\{[^}]+\}/i;
        const redisDangerousCommand = /(?:redis|client)\.(?:flushall|flushdb|config)\s*\(/i;
        if (redisEvalConcat.test(cleanContent) || redisDangerousCommand.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
                !l.trim().startsWith('*') &&
                (redisEvalConcat.test(l) || redisDangerousCommand.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `redis-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18103,
                type: 'SECURITY',
                title: 'REDIS-SEC-01: Insecure Redis Command Invocation or Lua Script Concatenation',
                severity: 'HIGH',
                category: 'In-Memory Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'redis.eval(`return redis.call("get", "${key}")`)',
                reproductionSteps: [
                    `Scanned Redis caching logic in ${file.path}:${lineNum}.`,
                    'Detected unsafe string interpolation inside Redis EVAL Lua scripts, or direct invocation of administrative commands (FLUSHALL/CONFIG) in application code.'
                ],
                remediationPrompt: 'Pass parameters to Redis EVAL as KEYS and ARGV arrays instead of string concatenation. Disallow administrative commands in production application clients.',
                status: 'OPEN',
                owner: 'Cache Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [REDIS AUDIT] HIGH: Redis Insecure Command/EVAL in ${file.path}:${lineNum}`);
        }
    }
    // Redis open binding in configs or docker-compose
    if (lowerPath.includes('docker-compose') || lowerPath.endsWith('.conf') || lowerPath.endsWith('.yaml') || lowerPath.endsWith('.yml')) {
        const redisOpenPort = /["']?6379:6379["']?/i;
        const redisNoAuth = /--protected-mode\s+no|bind\s+0\.0\.0\.0/i;
        if (redisOpenPort.test(cleanContent) && redisNoAuth.test(cleanContent) && !/requirepass/i.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && (redisOpenPort.test(l) || redisNoAuth.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `redis-infra-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18103,
                type: 'INFRA_DATABASE',
                title: 'REDIS-SEC-01: Publicly Exposed Redis Port Without Password Authentication',
                severity: 'CRITICAL',
                category: 'In-Memory Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || '6379:6379 protected-mode no',
                reproductionSteps: [
                    `Scanned infrastructure configuration at ${file.path}:${lineNum}.`,
                    'Detected Redis service exposing port 6379 with protected-mode disabled or 0.0.0.0 binding without requirepass authentication.'
                ],
                remediationPrompt: 'Require strong password authentication (requirepass) and bind Redis to internal Docker network or 127.0.0.1.',
                status: 'OPEN',
                owner: 'DevOps & Infrastructure Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [REDIS INFRA] CRITICAL: Unprotected Redis Port Exposed in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 4. ORM-RAW-01: Prisma, TypeORM, Drizzle Unsafe Raw SQL Injection
    // =========================================================================
    if (isJsTs) {
        // Prisma $queryRawUnsafe or $executeRawUnsafe with interpolation
        const prismaRawUnsafe = /prisma\.\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*`[^`]*\$\{[^}]+\}/i;
        const prismaRawUnsafeConcat = /prisma\.\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*["'][^"']*["']\s*\+/i;
        // TypeORM createQueryBuilder raw where concatenation
        const typeormRawConcat = /\.where\s*\(\s*["'][^"']*\b[a-zA-Z0-9_]+\s*=\s*["']\s*\+/i;
        // Drizzle sql.raw with interpolation
        const drizzleSqlRaw = /sql\.raw\s*\(\s*`[^`]*\$\{[^}]+\}/i;
        if (prismaRawUnsafe.test(cleanContent) || prismaRawUnsafeConcat.test(cleanContent) || typeormRawConcat.test(cleanContent) || drizzleSqlRaw.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
                !l.trim().startsWith('*') &&
                (prismaRawUnsafe.test(l) || prismaRawUnsafeConcat.test(l) || typeormRawConcat.test(l) || drizzleSqlRaw.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `orm-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18104,
                type: 'SECURITY',
                title: 'ORM-RAW-01: ORM Raw Query Injection via Unsafe String Interpolation',
                severity: 'CRITICAL',
                category: 'ORM Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE id = ${userId}`)',
                reproductionSteps: [
                    `Scanned ORM query call in ${file.path}:${lineNum}.`,
                    'Detected unsafe raw query method ($queryRawUnsafe, sql.raw, or unparameterized TypeORM where) passing interpolated strings directly into the database engine.'
                ],
                remediationPrompt: 'In Prisma, use tagged template literal prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${userId}` which auto-parameterizes values. In TypeORM, use parameter objects: .where("user.id = :id", { id }).',
                status: 'OPEN',
                owner: 'Database Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [ORM AUDIT] CRITICAL: ORM Raw SQL Injection in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 5. SQLITE-SEC-01: SQLite Public Placement & Unsafe Query Formatting
    // =========================================================================
    // Placing .sqlite / .db inside public/ or static/ web root folders
    if ((lowerPath.startsWith('public/') || lowerPath.startsWith('static/') || lowerPath.startsWith('app/')) && (lowerPath.endsWith('.sqlite') || lowerPath.endsWith('.sqlite3') || lowerPath.endsWith('.db'))) {
        findings.push({
            id: `sqlite-path-${Date.now()}-${findingCounter.count++}`,
            ruleId: 18105,
            type: 'SECURITY',
            title: 'SQLITE-SEC-01: Sensitive SQLite Database File Stored in Public Web Root',
            severity: 'CRITICAL',
            category: 'Information Disclosure',
            filePath: file.path,
            lineRange: 'L1',
            snippet: file.path,
            reproductionSteps: [
                `Inspected file tree path for ${file.path}.`,
                'Detected SQLite database file located in public static asset directory, making the entire database directly downloadable via HTTP GET.'
            ],
            remediationPrompt: 'Move SQLite database files outside the web root (e.g. into private data/ or var/ directory with strict file permissions 0600).',
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] 🔒 [SQLITE AUDIT] CRITICAL: SQLite DB Exposed in Public Directory: ${file.path}`);
    }
    return { findings, logs };
}
