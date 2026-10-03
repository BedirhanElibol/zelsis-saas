/**
 * Zelsis Master evaluateApiRules Engine (50 Rules)
 * Rules API-01 to API-50 (Rule IDs 7201 to 7250).
 * Removed as unsound (ids never reused): 7201 7202 7204 7205 7206 7208 7209 7211 7216 7217 7222 7224
 * 7225 7227 7231 7234 7236 7240 7241 7244 7248 (absence-of-X, style, wrong premise or made-up names),
 * 7228 (duplicate of GraphQL 13703).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { RATE_LIMIT_GUARD } from './shared/stack-signals';
import { locateMatchLine } from './shared/locate';
/** API key from a request compared with a plain equality operator (timing side channel). */
const API_KEY_PLAIN_EQ = /\b\w*(?:apiKey|api_key)\w*\s*(?:===|!==)\s*(?:storedApiKey|secretKey|configuredKey|process\.env\.\w+)\b(?!\s*[.(\[])|\btoken\s*===\s*(?:storedApiKey|secretKey|configuredKey)\b|headers(?:\.get\s*\(\s*|\[\s*)["']x-api-key["']\s*[\])]\s*(?:===|!==)\s*process\.env\.\w+/i;
/** Supabase-style auth callback: `next` read from the query and appended to the origin. */
const NEXT_PARAM_FROM_QUERY = /\bnext\s*=\s*(?:\w+\.)?searchParams\.get\(\s*["']next["']\s*\)/;
const REDIRECT_ORIGIN_PLUS_NEXT = /NextResponse\.redirect\s*\(\s*`\$\{\s*(?:\w+\.)?origin\s*\}\$\{\s*next\s*\}`\s*\)/;
const REDIRECT_RAW_PARAM = /NextResponse\.redirect\s*\(\s*(?:searchParams\.get\(["']next["']\)|req\.query\.returnUrl)\s*\)/i;

/** First line of a public tRPC procedure whose mutation deletes records without looking at the caller. */
function publicDeleteMutationLine(lines: string[]): number {
    for (let i = 0; i < lines.length; i++) {
        if (!/\b(?:publicProcedure|t\.procedure)\b/.test(lines[i])) continue;
        let body = lines[i];
        for (let j = i + 1; j < Math.min(lines.length, i + 20) && !/\b\w*[pP]rocedure\b/.test(lines[j]); j++) body += '\n' + lines[j];
        if (/\.mutation\s*\(/.test(body) && /\.(?:delete|deleteMany)\s*\(/.test(body) && !/ctx\.(?:session|user|auth|userId)|token|secret|signature/i.test(body)) return i;
    }
    return -1;
}
export interface ApiRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateApiRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ApiRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // API-03: Collection Endpoint Missing Pagination Boundary
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /findMany\(\s*\)(?!\s*\.take|\s*\.limit)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/findMany\(\s*\)(?!\s*\.take|\s*\.limit)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7203,
            type: 'SECURITY',
            title: "API-03: Collection Endpoint Missing Pagination Boundary",
            severity: 'MEDIUM',
            category: "API Scalability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Collection Endpoint Missing Pagination Boundary: GET endpoints returning arrays of entities without limit or pageSize bounds, causing OOM when tables grow."
            ],
            remediationPrompt: "Enforce pagination query params: const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '20'))).",
            status: 'OPEN',
            owner: "REST Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-03: Collection Endpoint Missing Pagination Boundary detected (${file.path}:${lineNum})`);
    }
    // API-07: Health Check Endpoint Exposing Internal System Credentials
    if (/(?:health|healthz)/i.test(lowerPath) && /return\s+NextResponse\.json\([^)]*(?:database_?url|db_password|secret_key|env:\s*process\.env\b|\.\.\.process\.env\b)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/return\s+NextResponse\.json\([^)]*(?:database_?url|db_password|secret_key|env:\s*process\.env\b|\.\.\.process\.env\b)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7207,
            type: 'SECURITY',
            title: "API-07: Health Check Endpoint Exposing Internal System Credentials",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Health Check Endpoint Exposing Internal System Credentials: Health checks (/healthz, /api/health) returning database passwords, full connection strings, or internal hostnames."
            ],
            remediationPrompt: "Sanitize health check output to boolean status indicators; never expose raw error stacks or hostnames.",
            status: 'OPEN',
            owner: "Health Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-07: Health Check Endpoint Exposing Internal System Credentials detected (${file.path}:${lineNum})`);
    }
    // API-13: API Endpoint Missing Strict JSON Schema / Zod Validation
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && /const\s+\w+\s*=\s*\(?\s*await\s+(?:req|request)\.json\(\)\s*\)?\s*as\s+any\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+\w+\s*=\s*\(?\s*await\s+(?:req|request)\.json\(\)\s*\)?\s*as\s+any\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7213,
            type: 'SECURITY',
            title: "API-13: API Endpoint Missing Strict JSON Schema / Zod Validation",
            severity: 'MEDIUM',
            category: "Input Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected API Endpoint Missing Strict JSON Schema / Zod Validation: Accepting request body as any without schema parsing, vulnerable to unexpected property injection."
            ],
            remediationPrompt: "Validate request with Zod: const data = RequestSchema.parse(await req.json()).",
            status: 'OPEN',
            owner: "Data Contracts",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-13: API Endpoint Missing Strict JSON Schema / Zod Validation detected (${file.path}:${lineNum})`);
    }
    // API-15: GET Endpoint Performing State-Mutating Actions
    const getFuncMatch = cleanContent.match(/export\s+async\s+function\s+GET[\s\S]*?(?=export\s+(?:async\s+)?function|$)/i);
    const getBody = getFuncMatch ? getFuncMatch[0] : '';
    const sanitizedGetBody = getBody.replace(/createHmac\s*\([^)]*\)\s*\.update\s*\([^)]*\)/gi, '').replace(/createHash\s*\([^)]*\)\s*\.update\s*\([^)]*\)/gi, '');
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && sanitizedGetBody && /(?:\.(?:from|table|collection)\s*\([^)]*\)\s*\.(?:delete|update|insert|upsert)\b|\bprisma\.\w+\.(?:delete|update|create|upsert)(?:Many)?\s*\(|\bdb\.(?:delete|update|insert)\s*\(|DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO)/i.test(sanitizedGetBody)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/(?:\.(?:delete|update|insert|upsert|create)(?:Many)?\(|DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO)/i.test(l) || /export\s+async\s+function\s+GET/i.test(l)));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7215,
            type: 'SECURITY',
            title: "API-15: GET Endpoint Performing State-Mutating Actions",
            severity: 'HIGH',
            category: "REST Semantics",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected GET Endpoint Performing State-Mutating Actions: Using GET /api/v1/users/delete?id=123 causing search engine crawlers and browser prefetching to trigger mutations."
            ],
            remediationPrompt: "Refactor deletion and mutations to DELETE or POST verbs with CSRF protection.",
            status: 'OPEN',
            owner: "HTTP Methods",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-15: GET Endpoint Performing State-Mutating Actions detected (${file.path}:${lineNum})`);
    }
    // API-18: Unauthenticated Debug or Metric Endpoint in Production
    if (/(?:api\/debug|api\/pprof)/i.test(lowerPath) && !/auth|session|admin/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-18|unauthenticated/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7218,
            type: 'SECURITY',
            title: "API-18: Unauthenticated Debug or Metric Endpoint in Production",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unauthenticated Debug or Metric Endpoint in Production: Exposing /api/debug, /api/metrics, or /api/pprof without administrator authentication."
            ],
            remediationPrompt: "Protect metric and debug endpoints with API key validation or bind strictly to internal port.",
            status: 'OPEN',
            owner: "API Security",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-18: Unauthenticated Debug or Metric Endpoint in Production detected (${file.path}:${lineNum})`);
    }
    // API-19: Wildcard Allowed Methods in CORS (Access-Control-Allow-Methods: '*')
    if (/Access-Control-Allow-Methods[\'"]?\s*[:=]\s*[\'"]\*[\'"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/Access-Control-Allow-Methods[\'"]?\s*[:=]\s*[\'"]\*[\'"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7219,
            type: 'SECURITY',
            title: "API-19: Wildcard Allowed Methods in CORS (Access-Control-Allow-Methods: '*')",
            severity: 'LOW',
            category: "CORS Configuration",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Wildcard Allowed Methods in CORS (Access-Control-Allow-Methods: '*'): Permitting all HTTP verbs in CORS headers instead of whitelisting explicitly supported methods."
            ],
            remediationPrompt: "Set Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS instead of wildcard *.",
            status: 'OPEN',
            owner: "CORS Security",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-19: Wildcard Allowed Methods in CORS (Access-Control-Allow-Methods: '*') detected (${file.path}:${lineNum})`);
    }
    // API-20: Missing Rate Limiting on Authentication / Login Endpoints
    if (/api\/(?:v\d+\/)?(?:auth\/)?(?:login|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|magic-link|otp|verify-otp|token)(?:\/|$|\b)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && !RATE_LIMIT_GUARD.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+async\s+function\s+POST/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7220,
            type: 'SECURITY',
            title: "API-20: Missing Rate Limiting on Authentication / Login Endpoints",
            severity: 'CRITICAL',
            category: "Brute Force Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Rate Limiting on Authentication / Login Endpoints: Login, register, and password reset endpoints operating without strict IP and account rate limits."
            ],
            remediationPrompt: "Integrate RateLimiter on /api/auth/ endpoints to reject excess attempts with 429.",
            status: 'OPEN',
            owner: "Auth Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-20: Missing Rate Limiting on Authentication / Login Endpoints detected (${file.path}:${lineNum})`);
    }
    // API-21: Leaking Stack Traces in 500 Server Error Responses
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /status:\s*500/i.test(cleanContent) && /(?:stack|error|details):\s*(?:err|error|e)\.stack\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/status:\s*500/i, /(?:stack|error|details):\s*(?:err|error|e)\.stack\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7221,
            type: 'SECURITY',
            title: "API-21: Leaking Stack Traces in 500 Server Error Responses",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Leaking Stack Traces in 500 Server Error Responses: Returning err.stack or database error details to client in 500 Internal Server Error responses."
            ],
            remediationPrompt: "Return { error: 'Internal Server Error' } and log err.stack internally with correlation ID.",
            status: 'OPEN',
            owner: "Error Handling",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-21: Leaking Stack Traces in 500 Server Error Responses detected (${file.path}:${lineNum})`);
    }
    // API-23: Webhook Delivery Missing Cryptographic HMAC Signature
    if (/(?:function\s+(?:dispatch|send)Webhook|const\s+(?:dispatch|send)Webhook\s*=)/i.test(cleanContent) && !/createHmac|sha256|signature|signPayload|svix|standardwebhooks/i.test(cleanContent) && !/slack|discord/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:function\s+(?:dispatch|send)Webhook|const\s+(?:dispatch|send)Webhook\s*=)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7223,
            type: 'SECURITY',
            title: "API-23: Webhook Delivery Missing Cryptographic HMAC Signature",
            severity: 'MEDIUM',
            category: "Webhook Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Webhook Delivery Missing Cryptographic HMAC Signature: Sending outgoing webhooks to customer endpoints without signing payload with HMAC-SHA256."
            ],
            remediationPrompt: "Sign outgoing webhook payloads using crypto.createHmac('sha256', secret).update(payload).digest('hex').",
            status: 'OPEN',
            owner: "Outgoing Webhooks",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-23: Webhook Delivery Missing Cryptographic HMAC Signature detected (${file.path}:${lineNum})`);
    }
    // API-26: Unbounded Query Filter Parameters Exposing Full Table Scans
    // The client's query/body object handed to the ORM as the whole `where` clause: callers choose any
    // column and operator (e.g. filter on passwordHash with startsWith) and can drop every bound.
    const api26Re = /\bwhere\s*:\s*(?:req\.(?:query|body)(?:\.(?:where|filter))?|JSON\.parse\(\s*(?:(?:\w+\.)?searchParams\.get\(\s*['"](?:where|filter)['"]\s*\)|req\.query\.(?:where|filter))[^)]*\))\s*(?:[,}]|$)/;
    const api26Idx = lines.findIndex(l => api26Re.test(l));
    if (api26Idx !== -1) {
        const matchLineIdx = api26Idx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `api26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7226,
            type: 'SECURITY',
            title: "API-26: Unbounded Query Filter Parameters Exposing Full Table Scans",
            severity: 'MEDIUM',
            category: "Query Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Query Filter Parameters Exposing Full Table Scans: Allowing clients to pass arbitrary filter keys (/api/v1/items?where[anything]=1) into database queries."
            ],
            remediationPrompt: "Whitelist allowed filter parameters and reject unrecognized query keys.",
            status: 'OPEN',
            owner: "API Filtering",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-26: Unbounded Query Filter Parameters Exposing Full Table Scans detected (${file.path}:${lineNum})`);
    }
    // API-30: tRPC Procedure Missing Caller Context Authentication
    if (/\.mutation\s*\(/.test(cleanContent) && publicDeleteMutationLine(lines) !== -1) {
        const matchLineIdx = publicDeleteMutationLine(lines);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7230,
            type: 'SECURITY',
            title: "API-30: tRPC Procedure Missing Caller Context Authentication",
            severity: 'HIGH',
            category: "tRPC Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected tRPC Procedure Missing Caller Context Authentication: Exporting sensitive tRPC queries as publicProcedure instead of protectedProcedure."
            ],
            remediationPrompt: "Use protectedProcedure instead of publicProcedure for non-public data operations.",
            status: 'OPEN',
            owner: "tRPC Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-30: tRPC Procedure Missing Caller Context Authentication detected (${file.path}:${lineNum})`);
    }
    // API-35: Unsanitized User-Controlled Filename in Content-Disposition
    if (/headers\.set\(\s*[\'"]Content-Disposition[\'"]\s*,\s*[\'"]attachment;\s*filename=[\'"]\s*\+\s*[\w.]+\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/headers\.set\(\s*[\'"]Content-Disposition[\'"]\s*,\s*[\'"]attachment;\s*filename=[\'"]\s*\+\s*[\w.]+\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7235,
            type: 'SECURITY',
            title: "API-35: Unsanitized User-Controlled Filename in Content-Disposition",
            severity: 'MEDIUM',
            category: "Header Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsanitized User-Controlled Filename in Content-Disposition: Setting Content-Disposition: attachment; filename=\"...\" without escaping quotes or newlines."
            ],
            remediationPrompt: "Sanitize filename or encode: filename*=UTF-8''${encodeURIComponent(filename)}.",
            status: 'OPEN',
            owner: "Download Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-35: Unsanitized User-Controlled Filename in Content-Disposition detected (${file.path}:${lineNum})`);
    }
    // API-37: Exposing Internal Database Errors in 400 Bad Request
    // The raw driver error (Sequelize err.original / err.parent) returned in the same 400 response
    const api37Idx = /(?:app\/api|pages\/api)/i.test(lowerPath)
        ? lines.findIndex((l, i) => /\b(?:error|details?|message)\s*:\s*(?:err|error|e)\.(?:original|parent)\b/.test(l) && /status\s*:\s*400\b|\.status\(\s*400\s*\)/.test(lines.slice(Math.max(0, i - 2), i + 3).join('\n')))
        : -1;
    if (api37Idx !== -1) {
        const matchLineIdx = api37Idx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `api37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7237,
            type: 'SECURITY',
            title: "API-37: Exposing Internal Database Errors in 400 Bad Request",
            severity: 'MEDIUM',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Exposing Internal Database Errors in 400 Bad Request: Directly returning raw Postgres error messages (e.g. 'duplicate key value violates unique constraint') to user."
            ],
            remediationPrompt: "Map database error codes (23505) to friendly messages like 'An account with this email already exists'.",
            status: 'OPEN',
            owner: "Database Exceptions",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-37: Exposing Internal Database Errors in 400 Bad Request detected (${file.path}:${lineNum})`);
    }
    // API-42: Missing Strict Origin Validation in WebSocket Handshake
    if (/new\s+WebSocketServer\s*\(\s*\{(?![^}]*verifyClient)/i.test(cleanContent) && !/localhost/i.test(cleanContent) && !/headers\.origin|headers\[['"]origin['"]\]|allowedOrigins/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+WebSocketServer\s*\(\s*\{(?![^}]*verifyClient)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7242,
            type: 'SECURITY',
            title: "API-42: Missing Strict Origin Validation in WebSocket Handshake",
            severity: 'HIGH',
            category: "WebSocket Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Strict Origin Validation in WebSocket Handshake: WebSocket server accepting connection upgrades without validating the Origin header against trusted domains."
            ],
            remediationPrompt: "Verify incoming WebSocket connection origin against allowed domain list before completing upgrade.",
            status: 'OPEN',
            owner: "WebSockets",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-42: Missing Strict Origin Validation in WebSocket Handshake detected (${file.path}:${lineNum})`);
    }
    // API-43: Unbounded WebSocket Message Payload Size
    if (/new\s+(?:WebSocketServer|WebSocket\.Server)\s*\(\s*\{(?![^}]*maxPayload)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+(?:WebSocketServer|WebSocket\.Server)\s*\(\s*\{(?![^}]*maxPayload)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7243,
            type: 'SECURITY',
            title: "API-43: Unbounded WebSocket Message Payload Size",
            severity: 'MEDIUM',
            category: "DoS Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded WebSocket Message Payload Size: WebSocket listeners processing incoming frames without maxPayload limits, vulnerable to memory exhaustion."
            ],
            remediationPrompt: "Configure maxPayload: 65536 on WebSocket server configuration.",
            status: 'OPEN',
            owner: "WebSockets",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-43: Unbounded WebSocket Message Payload Size detected (${file.path}:${lineNum})`);
    }
    // API-45: API Token Generation Using Math.random Instead of Crypto
    if (/const\s+(?:token|apiKey|secret|otp)\s*=\s*Math\.random\(\)\.toString\(36\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+(?:token|apiKey|secret|otp)\s*=\s*Math\.random\(\)\.toString\(36\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7245,
            type: 'SECURITY',
            title: "API-45: API Token Generation Using Math.random Instead of Crypto",
            severity: 'HIGH',
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected API Token Generation Using Math.random Instead of Crypto: Generating API keys, password reset tokens, or OTP codes using Math.random().toString(36)."
            ],
            remediationPrompt: "Use crypto.randomBytes(32).toString('hex') or crypto.getRandomValues() for token generation.",
            status: 'OPEN',
            owner: "Token Generation",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-45: API Token Generation Using Math.random Instead of Crypto detected (${file.path}:${lineNum})`);
    }
    // API-46: Missing Timing-Safe Comparison on API Key Authentication
    if (API_KEY_PLAIN_EQ.test(cleanContent) && !/timingSafeEqual|safeCompare|constantTime/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [API_KEY_PLAIN_EQ], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7246,
            type: 'SECURITY',
            title: "API-46: Missing Timing-Safe Comparison on API Key Authentication",
            severity: 'MEDIUM',
            category: "Timing Attacks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Timing-Safe Comparison on API Key Authentication: Comparing provided API keys with stored hashes using standard string equality (apiKey === storedKey)."
            ],
            remediationPrompt: "Compare hashes using crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)).",
            status: 'OPEN',
            owner: "Auth Security",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-46: Missing Timing-Safe Comparison on API Key Authentication detected (${file.path}:${lineNum})`);
    }
    // API-47: API Endpoint Returning Unfiltered Sensitive PII in User Objects
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /return\s+NextResponse\.json\(\s*user\s*\)/i.test(cleanContent) && /password_hash|stripe_customer_id/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/return\s+NextResponse\.json\(\s*user\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7247,
            type: 'SECURITY',
            title: "API-47: API Endpoint Returning Unfiltered Sensitive PII in User Objects",
            severity: 'HIGH',
            category: "Data Minimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected API Endpoint Returning Unfiltered Sensitive PII in User Objects: Returning full user database rows including password_hash, stripe_customer_id, or ssn to client API responses."
            ],
            remediationPrompt: "Strip sensitive fields before returning user object: const { password_hash, ...safeUser } = user.",
            status: 'OPEN',
            owner: "Privacy",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-47: API Endpoint Returning Unfiltered Sensitive PII in User Objects detected (${file.path}:${lineNum})`);
    }
    // API-49: Unsafe URL Redirection in OAuth Callback Handler
    if (/auth\/callback/i.test(lowerPath) && (REDIRECT_RAW_PARAM.test(cleanContent) || (NEXT_PARAM_FROM_QUERY.test(cleanContent) && REDIRECT_ORIGIN_PLUS_NEXT.test(cleanContent))) && !/startsWith\([\'"]\/[\'"]\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [REDIRECT_RAW_PARAM, REDIRECT_ORIGIN_PLUS_NEXT], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7249,
            type: 'SECURITY',
            title: "API-49: Unsafe URL Redirection in OAuth Callback Handler",
            severity: 'HIGH',
            category: "Open Redirect (CWE-601)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsafe URL Redirection in OAuth Callback Handler: OAuth callback handler redirecting to unvalidated returnUrl or next query parameter from untrusted origin."
            ],
            remediationPrompt: "Validate redirect target: target.startsWith('/') && !target.startsWith('//') before redirecting.",
            status: 'OPEN',
            owner: "OAuth Security",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-49: Unsafe URL Redirection in OAuth Callback Handler detected (${file.path}:${lineNum})`);
    }
    // API-50: Exposing Internal Microservice Hostname in Public API Response
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /return\s+NextResponse\.json\([^)]*\.svc\.cluster\.local/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/return\s+NextResponse\.json\([^)]*\.svc\.cluster\.local/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7250,
            type: 'SECURITY',
            title: "API-50: Exposing Internal Microservice Hostname in Public API Response",
            severity: 'LOW',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Exposing Internal Microservice Hostname in Public API Response: Returning internal Kubernetes service DNS names (e.g. payment-svc.default.svc.cluster.local) in error payloads."
            ],
            remediationPrompt: "Sanitize host headers and internal cluster domain names from public responses.",
            status: 'OPEN',
            owner: "Microservices",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-50: Exposing Internal Microservice Hostname in Public API Response detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
