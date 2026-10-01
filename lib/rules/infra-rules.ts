/**
 * Infrastructure, Cloud & Database Security Gate Rules (Rules 3001-3006)
 *
 * Rules:
 * 1. INFRA-01 (Rule ID 3001): Supabase & PostgreSQL Missing Row Level Security (RLS) Policy
 * 2. INFRA-02 (Rule ID 3002): Dockerfile Root User Execution (Privilege Escalation Risk)
 * 3. INFRA-03 (Rule ID 3003): Hardcoded Database Connection URI with Plaintext Credentials
 * 4. INFRA-04 (Rule ID 3004): Permissive Wildcard CORS Configuration in Middleware or API
 * 5. INFRA-05 (Rule ID 3005): Unprotected Production Debug / Profiler / Swagger Endpoints
 * 6. INFRA-06 (Rule ID 3006): Next.js Server Action Mutation Lacks Schema Validation Guard
 *
 * Classification: 100% Native English Only
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { DB_MUTATION } from './shared/stack-signals';
export interface InfraRuleResult {
    findings: Finding[];
    logs: string[];
}
function extractSnippet(lines: string[], lineNum: number): string {
    const targetIdx = Math.max(0, lineNum - 1);
    const start = Math.max(0, targetIdx - 2);
    const end = Math.min(lines.length, targetIdx + 3);
    return lines.slice(start, end).join('\n');
}
export function evaluateInfraRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): InfraRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const ts = new Date().toLocaleTimeString();
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // False-positive guard: Skip internal scanner engines, mock data, and rule definitions
    const isExcluded = lowerPath.includes('dist/') ||
        lowerPath.includes('build/') ||
        lowerPath.includes('node_modules/') ||
        lowerPath.includes('.next/');
    if (isExcluded)
        return { findings, logs };
    // =========================================================================
    // RULE 3001 (INFRA-01): PostgreSQL Missing Row Level Security (RLS)
    // =========================================================================
    const isSqlFile = lowerPath.endsWith('.sql') || lowerPath.includes('migration') || lowerPath.includes('schema');
    if (isSqlFile) {
        const tableRegex = /create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_."]+)/gi;
        let match: RegExpExecArray | null;
        while ((match = tableRegex.exec(cleanContent)) !== null) {
            const rawTableName = (match[1] || '').replace(/["']/g, '');
            const simpleName = rawTableName.includes('.') ? rawTableName.split('.').pop()! : rawTableName;
            // Check if RLS is enabled for this table anywhere in the file
            const rlsPattern = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:[a-zA-Z0-9_."]+\\.)?${simpleName}\\s+enable\\s+row\\s+level\\s+security`, 'i');
            if (!rlsPattern.test(cleanContent)) {
                const lineNum = cleanContent.slice(0, match.index).split('\n').length;
                const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
                const snippet = extractSnippet(lines, lineNum);
                const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},5 +${lineNum},8 @@\n CREATE TABLE ${rawTableName} (\n   ...\n );\n+\n+-- Enable Row Level Security (RLS) to restrict unauthorized anon reads/writes\n+ALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;\n+CREATE POLICY "Allow authenticated read" ON ${rawTableName} FOR SELECT TO authenticated USING (true);`;
                findings.push({
                    id: findingId,
                    ruleId: 3001,
                    type: 'INFRA_DATABASE',
                    title: `PostgreSQL Table "${simpleName}" Missing Row Level Security (RLS)`,
                    severity: 'CRITICAL',
                    category: 'Database Security',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet,
                    reproductionSteps: [
                        `Navigate to database schema file "${file.path}" at line ${lineNum}.`,
                        `Observe table definition "CREATE TABLE ${rawTableName}" created without RLS enforcement.`,
                        `Anonymous unauthenticated database clients can query or manipulate table data if public/anon permissions exist.`,
                        `Apply "ALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;" with appropriate access policies.`
                    ],
                    remediationPrompt: `Enable Row Level Security (RLS) on "${rawTableName}" immediately:\nALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Allow authenticated read" ON ${rawTableName} FOR SELECT TO authenticated USING (true);`,
                    diffPatch,
                    status: 'OPEN',
                    owner: 'Database & Cloud',
                    falsePositive: false
                });
                logs.push(`[${ts}] 🚨 [INFRA-01] CRITICAL: Table "${simpleName}" missing RLS in ${file.path}:${lineNum}`);
            }
        }
    }
    // =========================================================================
    // RULE 3002 (INFRA-02): Dockerfile Root User Execution
    // =========================================================================
    const isDockerfile = lowerPath.includes('dockerfile') || lowerPath.endsWith('dockerfile');
    if (isDockerfile) {
        const hasFrom = /^\s*FROM\s+/im.test(cleanContent);
        if (hasFrom) {
            const hasNonRootUser = /^\s*USER\s+(?!root\b)[a-zA-Z0-9_-]+/im.test(cleanContent);
            const hasExplicitRoot = /^\s*USER\s+root\b/im.test(cleanContent);
            if (!hasNonRootUser || hasExplicitRoot) {
                let lineNum = 1;
                lines.forEach((l, idx) => {
                    if (/^\s*FROM\s+/i.test(l))
                        lineNum = idx + 1;
                });
                const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
                const snippet = extractSnippet(lines, lineNum);
                const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},4 +${lineNum},7 @@\n FROM node:20-alpine AS runner\n WORKDIR /app\n+\n+# Security: Run production container with unprivileged user\n+USER node\n EXPOSE 3000\n CMD ["node", "server.js"]`;
                findings.push({
                    id: findingId,
                    ruleId: 3002,
                    type: 'INFRA_DATABASE',
                    title: 'Dockerfile Executes as Root User (Container Privilege Escalation Risk)',
                    severity: 'HIGH',
                    category: 'Container Security',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet,
                    reproductionSteps: [
                        `Inspect container definition file "${file.path}".`,
                        `Note that the container runs with default root privileges or specifies "USER root".`,
                        `Container breakout vulnerabilities can grant attackers root privileges on the underlying host.`,
                        `Declare an unprivileged user (e.g., "USER node" or "USER 1001") before the container entrypoint.`
                    ],
                    remediationPrompt: `Add an unprivileged user directive to Dockerfile before the final command:\nRUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser`,
                    diffPatch,
                    status: 'OPEN',
                    owner: 'DevOps & Cloud',
                    falsePositive: false
                });
                logs.push(`[${ts}] ⚠️ [INFRA-02] HIGH: Root container execution in ${file.path}:${lineNum}`);
            }
        }
    }
    // =========================================================================
    // RULE 3003 (INFRA-03): Hardcoded Database Connection URI with Credentials
    // =========================================================================
    const isCodeOrEnv = /\.(ts|js|tsx|jsx|json|yaml|yml|py|go|php)$/i.test(lowerPath) || lowerPath.includes('.env');
    const isEnvExample = lowerPath.includes('.env.example') || lowerPath.includes('.env.sample') || lowerPath.includes('.env.template');
    if (isCodeOrEnv && !isEnvExample) {
        const dbUriRegex = /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/([a-zA-Z0-9_%-]+):([a-zA-Z0-9_!@#$%^&*()-]+)@([a-zA-Z0-9_.-]+)(?::\d+)?\/([a-zA-Z0-9_.-]+)?/gi;
        let dbMatch: RegExpExecArray | null;
        while ((dbMatch = dbUriRegex.exec(cleanContent)) !== null) {
            const user = dbMatch[1];
            const password = dbMatch[2];
            // Skip generic placeholder credentials
            if (['username', 'user', 'your_user', 'password', 'your_password', 'xxx'].includes(user.toLowerCase()) && ['password', 'pass', 'your_password', 'xxx', 'secret'].includes(password.toLowerCase())) {
                continue;
            }
            // Skip common default local dev credentials
            if (['postgres', 'root', 'admin', 'test', 'demo'].includes(user.toLowerCase()) && ['postgres', 'root', 'admin', 'test', 'demo', ''].includes(password.toLowerCase())) {
                continue;
            }
            const lineNum = cleanContent.slice(0, dbMatch.index).split('\n').length;
            const matchingLine = lines[lineNum - 1]?.trim() || '';
            // Skip commented-out sample URIs in YAML, Python, SQL, or code comments
            if (matchingLine.startsWith('#') || matchingLine.startsWith('//') || matchingLine.startsWith('*') || matchingLine.startsWith('--')) {
                continue;
            }
            const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
            const snippet = extractSnippet(lines, lineNum);
            const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},3 +${lineNum},3 @@\n- const dbUri = "${dbMatch[0]}";\n+ const dbUri = process.env.DATABASE_URL;\n+ if (!dbUri) throw new Error("Missing DATABASE_URL environment variable.");`;
            findings.push({
                id: findingId,
                ruleId: 3003,
                type: 'INFRA_DATABASE',
                title: 'Plaintext Database Credentials Embedded in Connection URI',
                severity: 'CRITICAL',
                category: 'Secrets & Cloud',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Open file "${file.path}" at line ${lineNum}.`,
                    `Observe raw database connection string with embedded username and password credentials.`,
                    `Committing credentials to version control exposes production databases to automated credential stuffing.`,
                    `Extract connection URI into environment variable (e.g. process.env.DATABASE_URL).`
                ],
                remediationPrompt: `Remove hardcoded database credentials. Use environment variables:\nconst connectionString = process.env.DATABASE_URL;`,
                diffPatch,
                status: 'OPEN',
                owner: 'Database & Security',
                falsePositive: false
            });
            logs.push(`[${ts}] 🚨 [INFRA-03] CRITICAL: Hardcoded database credentials detected in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3004 (INFRA-04): Permissive Wildcard CORS Configuration
    // =========================================================================
    const isNetworkFile = lowerPath.includes('middleware') || lowerPath.includes('api/') || lowerPath.includes('cors') || lowerPath.includes('server') || lowerPath.includes('next.config');
    if (isNetworkFile) {
        const wildcardCorsRegex = /['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/i;
        const corsWildcardCall = /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/i;
        if (wildcardCorsRegex.test(cleanContent) || corsWildcardCall.test(cleanContent)) {
            let lineNum = 1;
            lines.forEach((l, idx) => {
                if (wildcardCorsRegex.test(l) || corsWildcardCall.test(l))
                    lineNum = idx + 1;
            });
            const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
            const snippet = extractSnippet(lines, lineNum);
            const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},3 +${lineNum},5 @@\n- headers.set('Access-Control-Allow-Origin', '*');\n+ const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL || 'https://yourdomain.com'];\n+ const origin = request.headers.get('origin');\n+ if (origin && allowedOrigins.includes(origin)) headers.set('Access-Control-Allow-Origin', origin);`;
            findings.push({
                id: findingId,
                ruleId: 3004,
                type: 'INFRA_DATABASE',
                title: 'Permissive Wildcard CORS ("*") Allows Arbitrary Cross-Origin Requests',
                severity: 'HIGH',
                category: 'API & Network',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Inspect CORS headers in "${file.path}" at line ${lineNum}.`,
                    `Notice header "Access-Control-Allow-Origin: *" configured without origin whitelist.`,
                    `Allows malicious third-party websites to forge API requests and read authenticated API responses.`,
                    `Validate request origin against a dynamic whitelist of approved frontend origins.`
                ],
                remediationPrompt: `Replace wildcard CORS with explicit allowed origin validation:\nconst allowedOrigins = ['https://app.yourdomain.com'];\nconst origin = req.headers.get('origin');\nif (origin && allowedOrigins.includes(origin)) headers.set('Access-Control-Allow-Origin', origin);`,
                diffPatch,
                status: 'OPEN',
                owner: 'API & Network',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ [INFRA-04] HIGH: Wildcard CORS configuration in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3005 (INFRA-05): Unprotected Debug / Profiler Endpoints Exposed
    // =========================================================================
    const isRouteFile = lowerPath.includes('app/api/') || lowerPath.includes('pages/api/');
    if (isRouteFile) {
        const isDebugPath = lowerPath.includes('/debug') ||
            lowerPath.includes('/profiler') ||
            lowerPath.includes('/health/verbose') ||
            lowerPath.includes('/swagger') ||
            lowerPath.includes('/test-env');
        if (isDebugPath) {
            const hasProdGuard = cleanContent.includes('process.env.NODE_ENV !== \'production\'') ||
                cleanContent.includes('process.env.NODE_ENV === \'development\'') ||
                cleanContent.includes('isAdmin') ||
                cleanContent.includes('authorizeAdmin');
            if (!hasProdGuard) {
                const lineNum = 1;
                const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
                const snippet = extractSnippet(lines, 1);
                const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -1,4 +1,7 @@\n export async function GET(request: Request) {\n+  if (process.env.NODE_ENV === 'production') {\n+    return new Response(JSON.stringify({ error: 'Endpoint not available in production' }), { status: 404 });\n+  }\n   return Response.json({ status: 'ok', debug: true });\n }`;
                findings.push({
                    id: findingId,
                    ruleId: 3005,
                    type: 'INFRA_DATABASE',
                    title: 'Unprotected Debug / Profiler Endpoint Exposed in Production Build',
                    severity: 'MEDIUM',
                    category: 'Infra Hardening',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet,
                    reproductionSteps: [
                        `Examine route handler "${file.path}".`,
                        `Route provides internal telemetry, environment dumps, or profiling data.`,
                        `Missing development-only guard (process.env.NODE_ENV !== 'production').`,
                        `Exposes internal infrastructure topologies and software versions to reconnaissance scans.`
                    ],
                    remediationPrompt: `Guard debug routes so they are inaccessible in production:\nif (process.env.NODE_ENV === 'production') return new Response(null, { status: 404 });`,
                    diffPatch,
                    status: 'OPEN',
                    owner: 'Infra & SecOps',
                    falsePositive: false
                });
                logs.push(`[${ts}] ℹ️ [INFRA-05] MEDIUM: Unprotected debug endpoint exposed in ${file.path}`);
            }
        }
    }
    // =========================================================================
    // RULE 3006 (INFRA-06): Next.js Server Action Mutation Lacks Schema Validation
    // =========================================================================
    const isActionFile = lowerPath.endsWith('.ts') || lowerPath.endsWith('.tsx') || lowerPath.endsWith('.js');
    if (isActionFile) {
        const hasUseServer = /['"]use server['"]/i.test(cleanContent);
        const hasDbMutation = DB_MUTATION.test(cleanContent);
        const hasValidation = /\.parse\(|\.safeParse\(|zod|yup|valibot/i.test(cleanContent);
        if (hasUseServer && hasDbMutation && !hasValidation) {
            let lineNum = 1;
            lines.forEach((l, idx) => {
                if (/['"]use server['"]/i.test(l))
                    lineNum = idx + 1;
            });
            const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
            const snippet = extractSnippet(lines, lineNum);
            const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},6 +${lineNum},10 @@\n 'use server';\n+import { z } from 'zod';\n+\n+const ActionSchema = z.object({ id: z.string(), payload: z.string().max(500) });\n \n export async function updateItemAction(formData: FormData) {\n+  const validated = ActionSchema.parse(Object.fromEntries(formData));\n   await db.update(...);`;
            findings.push({
                id: findingId,
                ruleId: 3006,
                type: 'INFRA_DATABASE',
                title: 'Next.js Server Action Executes Database Mutation Without Schema Validation Guard',
                severity: 'HIGH',
                category: 'Next.js Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Inspect Next.js Server Action in "${file.path}" at line ${lineNum}.`,
                    `Function performs direct database write/update operations from client-submitted arguments.`,
                    `No Zod schema validation (.parse / .safeParse) is performed before invoking the database client.`,
                    `Malicious clients can invoke Server Action POST endpoints with arbitrary unvalidated payloads.`
                ],
                remediationPrompt: `Validate Server Action inputs using a strict Zod schema before database operations:\nconst validated = MySchema.parse(inputData);`,
                diffPatch,
                status: 'OPEN',
                owner: 'Backend & Security',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ [INFRA-06] HIGH: Server action lacks input schema validation in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3007 (INFRA-07): Kubernetes Deployment Missing Container Resource Limits
    // =========================================================================
    const isK8sYaml = (lowerPath.endsWith('.yaml') || lowerPath.endsWith('.yml')) &&
        (cleanContent.includes('kind: Deployment') || cleanContent.includes('kind: Pod') || cleanContent.includes('kind: StatefulSet'));
    if (isK8sYaml && cleanContent.includes('containers:') && !cleanContent.includes('resources:') && !cleanContent.includes('limits:')) {
        const matchLineIdx = lines.findIndex(l => l.includes('containers:'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
        const snippet = extractSnippet(lines, lineNum);
        const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},5 +${lineNum},11 @@\n       containers:\n       - name: app\n         image: registry.example.com/app:latest\n+        resources:\n+          limits:\n+            cpu: "500m"\n+            memory: "512Mi"\n+          requests:\n+            cpu: "100m"\n+            memory: "128Mi"`;
        findings.push({
            id: findingId,
            ruleId: 3007,
            type: 'INFRA_DATABASE',
            title: 'Kubernetes Workload Manifest Missing CPU/Memory Resource Limits (DoS Risk)',
            severity: 'HIGH',
            category: 'Cloud Infrastructure',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned Kubernetes manifest at ${file.path}:${lineNum}.`,
                'Detected container spec running without explicit resources.limits (CPU and Memory).',
                'Unbounded containers can exhaust node memory causing Out-Of-Memory (OOM) cascading pod evictions and noisy-neighbor outages.'
            ],
            remediationPrompt: `Specify strict CPU and Memory limits (resources.limits) and requests (resources.requests) for all containers in ${file.path} to guarantee cluster stability and prevent resource starvation.`,
            diffPatch,
            status: 'OPEN',
            owner: 'DevOps & SRE',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-07] HIGH: Kubernetes manifest lacks container resource limits in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3008 (INFRA-08): Production Container Manifest Missing Health Check Probe
    // =========================================================================
    const isProdDockerfile = lowerPath.includes('dockerfile') && !lowerPath.includes('dev') && !lowerPath.includes('test');
    if (isProdDockerfile && !cleanContent.includes('HEALTHCHECK') && cleanContent.includes('EXPOSE')) {
        const matchLineIdx = lines.findIndex(l => l.includes('EXPOSE'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
        const snippet = extractSnippet(lines, lineNum);
        const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},3 +${lineNum},5 @@\n EXPOSE 3000\n+\n+HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD wget -qO- http://localhost:3000/api/health || exit 1`;
        findings.push({
            id: findingId,
            ruleId: 3008,
            type: 'INFRA_DATABASE',
            title: 'Production Dockerfile Missing Automated Health Check (HEALTHCHECK) Directive',
            severity: 'MEDIUM',
            category: 'Cloud Infrastructure',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned Dockerfile container definition at ${file.path}:${lineNum}.`,
                'Detected production image with exposed network port but without a HEALTHCHECK instruction.',
                'Orchestrators (Kubernetes, AWS ECS, Docker Swarm) cannot accurately detect deadlocks, crashed processes, or unready services without a container health check.'
            ],
            remediationPrompt: `Add HEALTHCHECK instruction to ${file.path} (e.g. HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:3000/api/health || exit 1) or configure livenessProbe in deployment manifests.`,
            diffPatch,
            status: 'OPEN',
            owner: 'DevOps & SRE',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-08] MEDIUM: Dockerfile missing HEALTHCHECK directive in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3009 (INFRA-09): Serverless Connection Pool Exhaustion in Next.js / Prisma
    // =========================================================================
    const isPrismaOrDbInit = (lowerPath.includes('lib/') || lowerPath.includes('db') || lowerPath.includes('prisma')) && /\.(?:ts|js)$/i.test(lowerPath);
    if (isPrismaOrDbInit && cleanContent.includes('new PrismaClient()') && !cleanContent.includes('globalThis')) {
        const matchLineIdx = lines.findIndex(l => l.includes('new PrismaClient()'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3009,
            type: 'INFRA_DATABASE',
            title: 'Serverless Connection Pool Exhaustion Hazard (Prisma Missing Global Singleton)',
            severity: 'CRITICAL',
            category: 'Serverless & Database Reliability',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned database initialization at ${file.path}:${lineNum}.`,
                'Detected new PrismaClient() instantiated without globalThis caching, causing connection pool exhaustion across serverless function re-invocations.'
            ],
            remediationPrompt: `Instantiate PrismaClient via globalThis singleton pattern in ${file.path} to reuse database connection pools across serverless lambdas.`,
            diffPatch: `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},1 +${lineNum},4 @@\n-export const prisma = new PrismaClient();\n+const globalForPrisma = globalThis as unknown as { prisma: PrismaClient };\n+export const prisma = globalForPrisma.prisma || new PrismaClient();\n+if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;`,
            status: 'OPEN',
            owner: 'Database Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-09] CRITICAL: PrismaClient missing globalThis singleton in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3010 (INFRA-10): Serverless Function Execution Timeout & Memory Misconfiguration
    // =========================================================================
    const isServerlessHeavyRoute = lowerPath.includes('app/api/') && (cleanContent.includes('streamText') || cleanContent.includes('openai.chat') || cleanContent.includes('exportPdf'));
    if (isServerlessHeavyRoute && !cleanContent.includes('maxDuration')) {
        const matchLineIdx = lines.findIndex(l => /export\s+async\s+function\s+(?:POST|GET)/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3010,
            type: 'INFRA_DATABASE',
            title: 'Missing maxDuration Timeout Declaration on Long-Running Serverless Route',
            severity: 'HIGH',
            category: 'Cloud & Serverless Infrastructure',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned API route handler at ${file.path}:${lineNum}.`,
                'Detected heavy compute, AI streaming, or PDF export route without export const maxDuration declaration, risking premature 504 gateway timeout on Vercel/AWS Lambda.'
            ],
            remediationPrompt: `Export maxDuration configuration: export const maxDuration = 60; in ${file.path} to prevent 10s serverless termination.`,
            diffPatch: `--- a/${file.path}\n+++ b/${file.path}\n@@ -1,2 +1,3 @@\n+export const maxDuration = 60;\n export const dynamic = 'force-dynamic';`,
            status: 'OPEN',
            owner: 'DevOps & SRE',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-10] HIGH: Serverless route missing maxDuration in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3011 (INFRA-11): Unencrypted Database & Cache In-Transit (Missing SSL / rediss://)
    // =========================================================================
    const unencryptedRedisRegex = /['"]redis:\/\/(?!localhost|127\.0\.0\.1|test)[^'"]+['"]/i;
    if (unencryptedRedisRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && unencryptedRedisRegex.test(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 3011,
                type: 'INFRA_DATABASE',
                title: 'Unencrypted Cache Connection URI (Missing rediss:// TLS Protocol)',
                severity: 'CRITICAL',
                category: 'Transport Layer Security & Privacy',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned remote connection string at ${file.path}:${lineNum}.`,
                    'Detected unencrypted redis:// protocol connecting to remote cache host without TLS encryption in transit.'
                ],
                remediationPrompt: `Enforce TLS in-transit: replace redis:// with rediss:// in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Infrastructure Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ☁️ [INFRA-11] CRITICAL: Unencrypted Redis URI in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3012 (INFRA-12): S3 / R2 Bucket Public ACL Misconfiguration
    // =========================================================================
    const isCloudStorageConfig = lowerPath.includes('s3') || lowerPath.includes('bucket') || lowerPath.includes('storage') || lowerPath.endsWith('.tf');
    if (isCloudStorageConfig && (cleanContent.includes('public-read') || cleanContent.includes('BlockPublicAcls = false'))) {
        const matchLineIdx = lines.findIndex(l => l.includes('public-read') || l.includes('BlockPublicAcls = false'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3012,
            type: 'INFRA_DATABASE',
            title: 'Public Read ACL Detected on Cloud Storage Bucket Configuration',
            severity: 'CRITICAL',
            category: 'Cloud Storage Security',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned storage configuration at ${file.path}:${lineNum}.`,
                'Detected public-read ACL or disabled public access blocks on storage bucket, risking unauthorized data exposure.'
            ],
            remediationPrompt: `Set bucket ACL to private and enable Block Public Access settings in ${file.path}:${lineNum}.`,
            status: 'OPEN',
            owner: 'Cloud Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-12] CRITICAL: Storage bucket public ACL in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3013 (INFRA-13): Container Read-Only Root Filesystem (Docker read_only: true)
    // =========================================================================
    const isComposeFile = lowerPath.includes('docker-compose') || lowerPath.includes('compose.yaml');
    if (isComposeFile && cleanContent.includes('services:') && !cleanContent.includes('read_only: true')) {
        const matchLineIdx = lines.findIndex(l => l.includes('image:') || l.includes('build:'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3013,
            type: 'INFRA_DATABASE',
            title: 'Container Compose Definition Missing Read-Only Root Filesystem Guard',
            severity: 'HIGH',
            category: 'Container Hardening',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned Docker Compose configuration at ${file.path}:${lineNum}.`,
                'Detected container service running with writable root filesystem without read_only: true constraint.'
            ],
            remediationPrompt: `Add read_only: true and mount temporary writable directories via tmpfs in ${file.path}:${lineNum}.`,
            status: 'OPEN',
            owner: 'DevOps & SRE',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-13] HIGH: Container missing read_only filesystem in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3016 (INFRA-16): Production Process Missing Graceful Shutdown (SIGTERM/SIGINT)
    // =========================================================================
    const isCustomServer = (lowerPath.endsWith('server.js') || lowerPath.endsWith('server.ts')) && !lowerPath.includes('test');
    if (isCustomServer && cleanContent.includes('.listen(') && !cleanContent.includes('SIGTERM')) {
        const matchLineIdx = lines.findIndex(l => l.includes('.listen('));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3016,
            type: 'INFRA_DATABASE',
            title: 'Production Server Missing Graceful Shutdown SIGTERM/SIGINT Signal Handlers',
            severity: 'MEDIUM',
            category: 'Server Resilience',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned HTTP server startup at ${file.path}:${lineNum}.`,
                'Detected Node.js HTTP server without process.on("SIGTERM") listeners, risking aborted database transactions during rolling deployments.'
            ],
            remediationPrompt: `Register process.on('SIGTERM', () => { server.close(); pool.end(); }) in ${file.path}:${lineNum} to guarantee zero-downtime rolling updates.`,
            status: 'OPEN',
            owner: 'DevOps Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-16] MEDIUM: Server missing SIGTERM handler in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3017 (INFRA-17): Dangerous Docker Socket Mount (/var/run/docker.sock)
    // =========================================================================
    if ((isComposeFile || isProdDockerfile) && cleanContent.includes('/var/run/docker.sock')) {
        const matchLineIdx = lines.findIndex(l => l.includes('/var/run/docker.sock'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3017,
            type: 'INFRA_DATABASE',
            title: 'Dangerous Host Docker Socket Mount (/var/run/docker.sock Exposed)',
            severity: 'CRITICAL',
            category: 'Container Security',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned container volume mounts at ${file.path}:${lineNum}.`,
                'Detected /var/run/docker.sock mounted into container, effectively granting full host root privilege escalation.'
            ],
            remediationPrompt: `Remove /var/run/docker.sock mount from ${file.path}:${lineNum}. Use rootless builds or isolated Kaniko pods instead.`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ [INFRA-17] CRITICAL: Docker socket mount in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3018 (INFRA-18): Firebase Permissive Security Rules (allow read, write: if true;)
    // =========================================================================
    const isFirebaseRules = lowerPath.endsWith('.rules') ||
        lowerPath.includes('firestore') ||
        lowerPath.includes('storage.rules') ||
        lowerPath.includes('firebase.json') ||
        cleanContent.includes('service cloud.firestore') ||
        cleanContent.includes('rules_version');
    const firebaseOpenPermsRegex = /allow\s+(?:read\s*,\s*write|write\s*,\s*read|read|write)\s*:\s*if\s+true\s*;/i;
    if (isFirebaseRules && firebaseOpenPermsRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => firebaseOpenPermsRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = extractSnippet(lines, lineNum);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3018,
            type: 'SECURITY',
            title: 'Firebase Security Rules: Permissive Unauthenticated Read/Write Access (allow read, write: if true)',
            severity: 'CRITICAL',
            category: 'Access Control',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet,
            reproductionSteps: [
                `Scanned Firebase security rules at ${file.path}:${lineNum}.`,
                'Detected completely unauthenticated public access clause ("allow read, write: if true;"), exposing sensitive database or storage bucket to public read and write.'
            ],
            remediationPrompt: `Enforce authenticated user checks in ${file.path}:${lineNum}: "allow read, write: if request.auth != null && request.auth.uid == userId;". Never ship "if true;" to production.`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] 🔒 [INFRA-18] CRITICAL: Firebase open read/write rule in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // RULE 3019 (INFRA-19): Docker Compose Database Port Exposed on Host & Default Insecure Passwords
    // =========================================================================
    if (isComposeFile) {
        const exposedDbPortRegex = /(?:^|\s)["']?(?:5432:5432|3306:3306|27017:27017|6379:6379|9200:9200)["']?/m;
        const defaultPasswordRegex = /(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[:=]\s*["']?(?:postgres|root|password|admin|123456|secret)["']?/i;
        if (exposedDbPortRegex.test(cleanContent) || defaultPasswordRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => exposedDbPortRegex.test(l) || defaultPasswordRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            const hasExposedPort = exposedDbPortRegex.test(cleanContent);
            const title = hasExposedPort
                ? 'Docker Compose Database Port Exposed Directly on Host (0.0.0.0 Exposure Risk)'
                : 'Docker Compose Container Configured with Insecure Default Hardcoded Database Password';
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 3019,
                type: 'INFRA_DATABASE',
                title,
                severity: 'HIGH',
                category: 'Container Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned Docker Compose manifest at ${file.path}:${lineNum}.`,
                    hasExposedPort
                        ? 'Detected raw database port mapping without loopback binding (e.g. 5432:5432), exposing the database to the public network.'
                        : 'Detected default predictable database password in compose configuration (e.g. POSTGRES_PASSWORD=postgres or root).'
                ],
                remediationPrompt: hasExposedPort
                    ? `Bind database ports strictly to localhost ("127.0.0.1:5432:5432") or remove port mapping so services communicate only over the internal Docker network.`
                    : `Replace hardcoded default passwords with strong secrets loaded from environment variables (\${POSTGRES_PASSWORD}) or Docker secrets.`,
                status: 'OPEN',
                owner: 'DevOps & SRE',
                falsePositive: false
            });
            logs.push(`[${ts}] ☁️ [INFRA-19] HIGH: Docker compose database exposure in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3020 (INFRA-20): MongoDB Injection via $where JavaScript or Unsanitized Query Object
    // =========================================================================
    const isJsTsPy = lowerPath.endsWith('.js') || lowerPath.endsWith('.ts') || lowerPath.endsWith('.mjs') || lowerPath.endsWith('.py');
    if (isJsTsPy) {
        const mongoWhereRegex = /\$where\s*:/i;
        const mongoRawQueryRegex = /(?:collection|db\.[a-zA-Z0-9_]+)\.(?:find|findOne|update|delete|count)\s*\(\s*(?:req\.body|req\.query|params)\b/i;
        if (mongoWhereRegex.test(cleanContent) || mongoRawQueryRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => mongoWhereRegex.test(l) || mongoRawQueryRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 3020,
                type: 'SECURITY',
                title: 'MongoDB NoSQL Injection via $where JavaScript Evaluation or Raw Request Query Object',
                severity: 'CRITICAL',
                category: 'NoSQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Audited database query logic at ${file.path}:${lineNum}.`,
                    'Detected MongoDB query utilizing $where JavaScript evaluation or passing unsanitized HTTP request objects (req.body/req.query) directly into query filters.'
                ],
                remediationPrompt: `Avoid using $where JavaScript execution in MongoDB queries. Sanitize query filters with mongo-sanitize or validate request parameters using strict Zod schemas before querying.`,
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [INFRA-20] CRITICAL: MongoDB NoSQL injection in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // RULE 3021 (INFRA-21): Node.js Database SQL Query String Concatenation (SQLi)
    // =========================================================================
    const isJsTs = lowerPath.endsWith('.js') || lowerPath.endsWith('.ts') || lowerPath.endsWith('.mjs');
    if (isJsTs && !lowerPath.includes('test') && !lowerPath.includes('spec')) {
        const rawSqlConcatRegex = /(?:connection|pool|db|client)\.query\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+|\`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{)/i;
        if (rawSqlConcatRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => rawSqlConcatRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 3021,
                type: 'SECURITY',
                title: 'SQL Injection: String Concatenation in Node.js Database Client Query',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet,
                reproductionSteps: [
                    `Scanned database query execution at ${file.path}:${lineNum}.`,
                    'Detected SQL statement constructed via dynamic string concatenation or template literals rather than parameterized queries ($1, ?).'
                ],
                remediationPrompt: `Use parameterized queries: pool.query('SELECT * FROM users WHERE id = $1', [userId]) or use an ORM with automatic query parameter escaping.`,
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [INFRA-21] CRITICAL: Node.js SQL injection in ${file.path}:${lineNum}`);
        }
    }
    return { findings, logs };
}
