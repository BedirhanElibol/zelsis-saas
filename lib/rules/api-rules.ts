/**
 * Zelsis Master evaluateApiRules Engine (50 Rules)
 * Rules API-01 to API-50 (Rule IDs 7201 to 7250).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
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
    if (lowerPath.includes('data/catalogs/') || lowerPath.includes('data/mockdata') || lowerPath.includes('data/workspacefiles') || lowerPath.includes('data/schema') || lowerPath.includes('scratch/') || lowerPath.includes('.agent/') || lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // API-01: Mutating Payment/Order Endpoint Missing Idempotency Key
    if (/(?:payment|checkout|order|subscription\/create)/i.test(lowerPath) && !lowerPath.includes("verify") && /export\s+async\s+function\s+POST/i.test(cleanContent) && !/idempotency-key|idempotencykey/i.test(cleanContent) && !lowerPath.includes("webhook")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-01|mutating/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7201,
            type: 'SECURITY',
            title: "API-01: Mutating Payment/Order Endpoint Missing Idempotency Key",
            severity: 'CRITICAL',
            category: "API Idempotency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Mutating Payment/Order Endpoint Missing Idempotency Key: POST endpoints that charge cards, deduct credits, or create orders lacking Idempotency-Key header support."
            ],
            remediationPrompt: "Read Idempotency-Key header, check cached response in Redis/DB, and reject duplicate concurrent requests.",
            status: 'OPEN',
            owner: "Payment & Order APIs",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-01: Mutating Payment/Order Endpoint Missing Idempotency Key detected (${file.path}:${lineNum})`);
    }
    // API-02: Unversioned Public REST API Route Handler
    if (/app\/api\/(?!(?:v\d+|auth|health|webhooks?|mock|trpc|subscription))[a-zA-Z0-9_-]+\/route\.ts$/i.test(file.path) && /export\s+async\s+function\s+(?:GET|POST)/i.test(cleanContent) && !lowerPath.includes("v1") && !lowerPath.includes("v2")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-02|unversioned/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7202,
            type: 'SECURITY',
            title: "API-02: Unversioned Public REST API Route Handler",
            severity: 'MEDIUM',
            category: "API Versioning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unversioned Public REST API Route Handler: Exposing API endpoints under /api/users instead of /api/v1/users, preventing non-breaking API evolution."
            ],
            remediationPrompt: "Relocate route handlers under /api/v1/ directory.",
            status: 'OPEN',
            owner: "REST Architecture",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-02: Unversioned Public REST API Route Handler detected (${file.path}:${lineNum})`);
    }
    // API-03: Collection Endpoint Missing Pagination Boundary
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /findMany\(\s*\)(?!\s*\.take|\s*\.limit)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-03|collection/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7203,
            type: 'SECURITY',
            title: "API-03: Collection Endpoint Missing Pagination Boundary",
            severity: 'HIGH',
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
    // API-04: Body Parser Missing Maximum Request Payload Limit
    if (/express\.json\(\s*(?:\)|\{\s*(?![^}]*limit))/i.test(cleanContent) || /bodyParser\.json\(\s*(?:\)|\{\s*(?![^}]*limit))/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-04|body/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7204,
            type: 'SECURITY',
            title: "API-04: Body Parser Missing Maximum Request Payload Limit",
            severity: 'HIGH',
            category: "DoS Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Body Parser Missing Maximum Request Payload Limit: Configuring express.json() or bodyParser without { limit: '100kb' } allowing multi-megabyte payloads to trigger memory DoS."
            ],
            remediationPrompt: "Configure express.json({ limit: '100kb' }) or validate request Content-Length header in Next.js routes.",
            status: 'OPEN',
            owner: "HTTP Servers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-04: Body Parser Missing Maximum Request Payload Limit detected (${file.path}:${lineNum})`);
    }
    // API-05: Non-Standard Error Response Violating RFC 7807
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /return\s+NextResponse\.json\(\s*\{\s*err:\s*/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-05|non-standard/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7205,
            type: 'SECURITY',
            title: "API-05: Non-Standard Error Response Violating RFC 7807",
            severity: 'MEDIUM',
            category: "Error Contracts",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Non-Standard Error Response Violating RFC 7807: Returning arbitrary error shapes ({ err: 'failed' } vs { msg: 'error' }) instead of standardized RFC 7807 Problem Details."
            ],
            remediationPrompt: "Adopt standardized error schema: { type, title, status, detail, instance } conforming to RFC 7807.",
            status: 'OPEN',
            owner: "API Design",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-05: Non-Standard Error Response Violating RFC 7807 detected (${file.path}:${lineNum})`);
    }
    // API-06: Inconsistent Property Casing in API Schema
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /NextResponse\.json\(\s*\{[^}]*\b[a-z]+_[a-z]+\b:[^}]*\b[a-z]+[A-Z][a-z]+\b:/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-06|inconsistent/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7206,
            type: 'SECURITY',
            title: "API-06: Inconsistent Property Casing in API Schema",
            severity: 'LOW',
            category: "Contract Consistency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Inconsistent Property Casing in API Schema: Mixing camelCase (firstName) and snake_case (last_name) within the same API response payload."
            ],
            remediationPrompt: "Normalize all API response keys to camelCase using a serialization transform or Zod schema.",
            status: 'OPEN',
            owner: "JSON Schemas",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-06: Inconsistent Property Casing in API Schema detected (${file.path}:${lineNum})`);
    }
    // API-07: Health Check Endpoint Exposing Internal System Credentials
    if (/(?:health|healthz)/i.test(lowerPath) && /return\s+NextResponse\.json\([^)]*(?:database_url|db_password|secret_key)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-07|health/i.test(l) || lines.indexOf(l) === 0));
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
    // API-08: Missing 'Retry-After' Header on Rate Limit Throttling (429)
    if (/(?:status:\s*429|res\.status\(429\))/i.test(cleanContent) && !/Retry-After/i.test(cleanContent) && /(?:app\/api|pages\/api)/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-08|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7208,
            type: 'SECURITY',
            title: "API-08: Missing 'Retry-After' Header on Rate Limit Throttling (429)",
            severity: 'MEDIUM',
            category: "HTTP Standard Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing 'Retry-After' Header on Rate Limit Throttling (429): Returning 429 Too Many Requests without Retry-After header indicating seconds until quota reset."
            ],
            remediationPrompt: "Set response header: headers.set('Retry-After', String(Math.ceil(cooldownSeconds))).",
            status: 'OPEN',
            owner: "Rate Limiting",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-08: Missing 'Retry-After' Header on Rate Limit Throttling (429) detected (${file.path}:${lineNum})`);
    }
    // API-09: CORS Preflight (OPTIONS) Missing Access-Control-Max-Age
    if (/export\s+async\s+function\s+OPTIONS/i.test(cleanContent) && /Access-Control-Allow-Origin/i.test(cleanContent) && !/Access-Control-Max-Age/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-09|cors/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7209,
            type: 'SECURITY',
            title: "API-09: CORS Preflight (OPTIONS) Missing Access-Control-Max-Age",
            severity: 'LOW',
            category: "Network Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CORS Preflight (OPTIONS) Missing Access-Control-Max-Age: OPTIONS preflight responses omitting Access-Control-Max-Age, forcing browsers to re-send preflights on every API call."
            ],
            remediationPrompt: "Add Access-Control-Max-Age: 86400 to CORS preflight handler responses.",
            status: 'OPEN',
            owner: "CORS",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-09: CORS Preflight (OPTIONS) Missing Access-Control-Max-Age detected (${file.path}:${lineNum})`);
    }
    // API-10: Sensitive ID Exposure Using Sequential Integers
    if (/app\/api\/.*\/\[id\]\/route\.ts$/i.test(file.path) && /parseInt\s*\(\s*params\.id\s*,\s*10\s*\)/i.test(cleanContent) && /orders|billing|users/i.test(lowerPath)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-10|sensitive/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7210,
            type: 'SECURITY',
            title: "API-10: Sensitive ID Exposure Using Sequential Integers",
            severity: 'HIGH',
            category: "Insecure Direct Object Reference (IDOR)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Sensitive ID Exposure Using Sequential Integers: Exposing autoincrementing integer IDs (/api/v1/orders/42) allowing attackers to enumerate all records."
            ],
            remediationPrompt: "Use UUIDv7 or nanoid for public-facing identifiers instead of sequential database serial integers.",
            status: 'OPEN',
            owner: "Data Modeling",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-10: Sensitive ID Exposure Using Sequential Integers detected (${file.path}:${lineNum})`);
    }
    // API-11: Missing Content-Type Validation on POST/PUT Endpoints
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+(?:POST|PUT)/i.test(cleanContent) && /await\s+req\.json\(\)/i.test(cleanContent) && !/content-type/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-11|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7211,
            type: 'SECURITY',
            title: "API-11: Missing Content-Type Validation on POST/PUT Endpoints",
            severity: 'MEDIUM',
            category: "Input Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Content-Type Validation on POST/PUT Endpoints: State-mutating endpoints processing body without verifying Content-Type is application/json."
            ],
            remediationPrompt: "Return 415 Unsupported Media Type if Content-Type does not match application/json.",
            status: 'OPEN',
            owner: "HTTP Requests",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-11: Missing Content-Type Validation on POST/PUT Endpoints detected (${file.path}:${lineNum})`);
    }
    // API-12: Dangerous HTTP Method Override Header Allowed
    if (/X-HTTP-Method-Override/i.test(cleanContent) && !/verifyAdmin|trustedProxy/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-12|dangerous/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7212,
            type: 'SECURITY',
            title: "API-12: Dangerous HTTP Method Override Header Allowed",
            severity: 'HIGH',
            category: "Method Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dangerous HTTP Method Override Header Allowed: Honoring X-HTTP-Method-Override or _method query parameter without authentication, bypassing route restrictions."
            ],
            remediationPrompt: "Disable method override middleware unless specifically required for legacy client compatibility.",
            status: 'OPEN',
            owner: "HTTP Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-12: Dangerous HTTP Method Override Header Allowed detected (${file.path}:${lineNum})`);
    }
    // API-13: API Endpoint Missing Strict JSON Schema / Zod Validation
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && /const\s+body\s*=\s*await\s+req\.json\(\)\s*as\s+any/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-13|api/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7213,
            type: 'SECURITY',
            title: "API-13: API Endpoint Missing Strict JSON Schema / Zod Validation",
            severity: 'HIGH',
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
    // API-14: Missing Cache-Control Header on Authenticated User Data
    if (/(?:user\/profile|account\/billing)/i.test(lowerPath) && /export\s+async\s+function\s+GET/i.test(cleanContent) && !/Cache-Control/i.test(cleanContent) && /getUser|session/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-14|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7214,
            type: 'SECURITY',
            title: "API-14: Missing Cache-Control Header on Authenticated User Data",
            severity: 'HIGH',
            category: "Privacy & Caching",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Cache-Control Header on Authenticated User Data: Returning private user profile or billing data without Cache-Control: no-store, private."
            ],
            remediationPrompt: "Add Cache-Control: no-store, private, max-age=0 to all authenticated API responses.",
            status: 'OPEN',
            owner: "API Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-14: Missing Cache-Control Header on Authenticated User Data detected (${file.path}:${lineNum})`);
    }
    // API-15: GET Endpoint Performing State-Mutating Actions
    const getFuncMatch = cleanContent.match(/export\s+async\s+function\s+GET[\s\S]*?(?=export\s+(?:async\s+)?function|$)/i);
    const getBody = getFuncMatch ? getFuncMatch[0] : '';
    const sanitizedGetBody = getBody.replace(/createHmac\s*\([^)]*\)\s*\.update\s*\([^)]*\)/gi, '').replace(/createHash\s*\([^)]*\)\s*\.update\s*\([^)]*\)/gi, '');
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && sanitizedGetBody && /(?:\.(?:from|table|collection)\s*\([^)]*\)\s*\.(?:delete|update|insert)\b|\.delete\s*\([^)]*\)|\.update\s*\([^)]*\)|\.insert\s*\([^)]*\)|DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO)/i.test(sanitizedGetBody)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/(?:\.delete\(|\.update\(|\.insert\(|DELETE\s+FROM)/i.test(l) || /export\s+async\s+function\s+GET/i.test(l)));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7215,
            type: 'SECURITY',
            title: "API-15: GET Endpoint Performing State-Mutating Actions",
            severity: 'CRITICAL',
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
    // API-16: Missing ETag Header on Cacheable Entity Endpoints
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+GET/i.test(cleanContent) && !/ETag/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-16|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7216,
            type: 'SECURITY',
            title: "API-16: Missing ETag Header on Cacheable Entity Endpoints",
            severity: 'LOW',
            category: "Caching & Concurrency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing ETag Header on Cacheable Entity Endpoints: Returning large JSON resources on GET without ETag, preventing conditional 304 Not Modified caching."
            ],
            remediationPrompt: "Generate ETag from content hash and return 304 if request If-None-Match matches.",
            status: 'OPEN',
            owner: "HTTP Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-16: Missing ETag Header on Cacheable Entity Endpoints detected (${file.path}:${lineNum})`);
    }
    // API-17: Missing If-Match Header for Optimistic Concurrency Control
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+(?:PUT|PATCH)/i.test(cleanContent) && !/if-match/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-17|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7217,
            type: 'SECURITY',
            title: "API-17: Missing If-Match Header for Optimistic Concurrency Control",
            severity: 'MEDIUM',
            category: "Concurrency & Race Conditions",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing If-Match Header for Optimistic Concurrency Control: PUT / PATCH updating shared resources without If-Match or version number, causing lost update race conditions."
            ],
            remediationPrompt: "Enforce If-Match header matching current version or ETag before applying updates.",
            status: 'OPEN',
            owner: "REST Updates",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-17: Missing If-Match Header for Optimistic Concurrency Control detected (${file.path}:${lineNum})`);
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
            severity: 'CRITICAL',
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
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-19|wildcard/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7219,
            type: 'SECURITY',
            title: "API-19: Wildcard Allowed Methods in CORS (Access-Control-Allow-Methods: '*')",
            severity: 'MEDIUM',
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
    if (/api\/(?:v\d+\/)?(?:auth\/)?(?:login|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|magic-link|otp|verify-otp|token)(?:\/|$|\b)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && !/rateLimit|limiter|checkLimit/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-20|missing/i.test(l) || lines.indexOf(l) === 0));
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
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /status:\s*500/i.test(cleanContent) && /(?:stack:\s*err\.stack|error:\s*err\.stack)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-21|leaking/i.test(l) || lines.indexOf(l) === 0));
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
    // API-22: Webhook Receiver Missing Replay Attack Protection (Timestamp Check)
    if (/webhook/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && /signature/i.test(cleanContent) && !/timestamp|webhook-timestamp/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-22|webhook/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7222,
            type: 'SECURITY',
            title: "API-22: Webhook Receiver Missing Replay Attack Protection (Timestamp Check)",
            severity: 'HIGH',
            category: "Webhook Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Webhook Receiver Missing Replay Attack Protection (Timestamp Check): Processing webhook payloads without verifying webhook-timestamp is within past 5 minutes."
            ],
            remediationPrompt: "Reject webhook requests if timestamp difference exceeds 300 seconds to prevent replay attacks.",
            status: 'OPEN',
            owner: "Webhooks",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-22: Webhook Receiver Missing Replay Attack Protection (Timestamp Check) detected (${file.path}:${lineNum})`);
    }
    // API-23: Webhook Delivery Missing Cryptographic HMAC Signature
    if (/(?:function\s+(?:dispatch|send)Webhook|const\s+(?:dispatch|send)Webhook\s*=)/i.test(cleanContent) && !/createHmac|sha256/i.test(cleanContent) && !/slack|discord/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-23|webhook/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7223,
            type: 'SECURITY',
            title: "API-23: Webhook Delivery Missing Cryptographic HMAC Signature",
            severity: 'HIGH',
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
    // API-24: Missing Strict Type Validation on Webhook Event Type
    if (/webhook/i.test(lowerPath) && /switch\s*\(\s*event\.type\s*\)/i.test(cleanContent) && !/default\s*:/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-24|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7224,
            type: 'SECURITY',
            title: "API-24: Missing Strict Type Validation on Webhook Event Type",
            severity: 'MEDIUM',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Strict Type Validation on Webhook Event Type: Handling incoming webhook event strings using loose switch-case without exhaustive enum validation."
            ],
            remediationPrompt: "Validate event.type against known schema or exhaustive TypeScript switch with never fallback.",
            status: 'OPEN',
            owner: "Webhook Handlers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-24: Missing Strict Type Validation on Webhook Event Type detected (${file.path}:${lineNum})`);
    }
    // API-25: Missing Correlation ID (X-Request-ID) in API Responses
    if (/app\/api\/v1\/enterprise-gateway/i.test(lowerPath) && !/x-request-id/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-25|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7225,
            type: 'SECURITY',
            title: "API-25: Missing Correlation ID (X-Request-ID) in API Responses",
            severity: 'LOW',
            category: "Distributed Tracing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Correlation ID (X-Request-ID) in API Responses: API responses omitting X-Request-ID or traceparent header, hindering cross-service distributed debugging."
            ],
            remediationPrompt: "Generate crypto.randomUUID() for X-Request-ID and attach to response headers and log context.",
            status: 'OPEN',
            owner: "Observability",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-25: Missing Correlation ID (X-Request-ID) in API Responses detected (${file.path}:${lineNum})`);
    }
    // API-26: Unbounded Query Filter Parameters Exposing Full Table Scans
    if (/(?:where:\s*searchParams\.get\([\'"]filter[\'"]\)|where:\s*req\.query\.where)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-26|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
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
    // API-27: Missing Deprecation Notice on Sunsetting API Endpoints
    if (/(?:legacy|deprecated)/i.test(lowerPath) && /export\s+async\s+function\s+GET/i.test(cleanContent) && !/Deprecation|Sunset/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-27|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7227,
            type: 'SECURITY',
            title: "API-27: Missing Deprecation Notice on Sunsetting API Endpoints",
            severity: 'LOW',
            category: "API Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Deprecation Notice on Sunsetting API Endpoints: Sunsetting legacy API endpoints without Deprecation and Sunset HTTP standard headers (RFC 8594)."
            ],
            remediationPrompt: "Add Deprecation: true and Sunset: Wed, 11 Nov 2026 00:00:00 GMT headers to deprecated routes.",
            status: 'OPEN',
            owner: "API Lifecycle",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-27: Missing Deprecation Notice on Sunsetting API Endpoints detected (${file.path}:${lineNum})`);
    }
    // API-28: GraphQL Schema Exposing Introspection in Production
    if (/new\s+ApolloServer\s*\(\s*\{[^}]*introspection:\s*true/i.test(cleanContent) && !/process\.env\.NODE_ENV/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-28|graphql/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7228,
            type: 'SECURITY',
            title: "API-28: GraphQL Schema Exposing Introspection in Production",
            severity: 'MEDIUM',
            category: "API Reconnaissance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected GraphQL Schema Exposing Introspection in Production: Production GraphQL endpoints enabling __schema and introspection queries for anonymous users."
            ],
            remediationPrompt: "Set introspection: process.env.NODE_ENV !== 'production' in Apollo/Yoga server config.",
            status: 'OPEN',
            owner: "GraphQL",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-28: GraphQL Schema Exposing Introspection in Production detected (${file.path}:${lineNum})`);
    }
    // API-29: GraphQL Mutation Missing Field-Level Authorization Checks
    if (/Mutation:\s*\{[^}]*deleteAccount:\s*async\s*\([^)]*\)\s*=>\s*\{(?![^}]*context\.user)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-29|graphql/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7229,
            type: 'SECURITY',
            title: "API-29: GraphQL Mutation Missing Field-Level Authorization Checks",
            severity: 'HIGH',
            category: "GraphQL Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected GraphQL Mutation Missing Field-Level Authorization Checks: Relying solely on query-level authentication while individual field resolvers lack object ownership checks."
            ],
            remediationPrompt: "Enforce context.user.id === resource.owner_id in mutation resolvers.",
            status: 'OPEN',
            owner: "GraphQL Resolvers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-29: GraphQL Mutation Missing Field-Level Authorization Checks detected (${file.path}:${lineNum})`);
    }
    // API-30: tRPC Procedure Missing Caller Context Authentication
    if (/t\.procedure\.mutation/i.test(cleanContent) && /deleteUser|updateBilling/i.test(cleanContent) && !/protectedProcedure|enforceUserIsAuthed/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-30|trpc/i.test(l) || lines.indexOf(l) === 0));
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
    // API-31: Accept-Encoding Missing Support for Brotli (br)
    if (/compressionMiddleware/i.test(cleanContent) && /gzip/i.test(cleanContent) && !/br|brotli/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-31|accept-encoding/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7231,
            type: 'SECURITY',
            title: "API-31: Accept-Encoding Missing Support for Brotli (br)",
            severity: 'LOW',
            category: "Payload Compression",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Accept-Encoding Missing Support for Brotli (br): Custom API server handling gzip compression but lacking modern Brotli (br) compression support."
            ],
            remediationPrompt: "Configure compression middleware with Brotli compression algorithm support.",
            status: 'OPEN',
            owner: "API Performance",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-31: Accept-Encoding Missing Support for Brotli (br) detected (${file.path}:${lineNum})`);
    }
    // API-32: Insecure Direct File Download via Relative Path Parameter
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /createReadStream\s*\(\s*(?:req\.query\.file|searchParams\.get\([\'"]file[\'"]\))\s*\)/i.test(cleanContent) && !/basename/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-32|insecure/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7232,
            type: 'SECURITY',
            title: "API-32: Insecure Direct File Download via Relative Path Parameter",
            severity: 'CRITICAL',
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Direct File Download via Relative Path Parameter: API route accepting /api/v1/download?file=../../etc/passwd without canonical path sandboxing."
            ],
            remediationPrompt: "Sanitize filename with path.basename() and verify resolved path starts with safe storage directory.",
            status: 'OPEN',
            owner: "File Endpoints",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-32: Insecure Direct File Download via Relative Path Parameter detected (${file.path}:${lineNum})`);
    }
    // API-33: API Bulk Creation Endpoint Lacking Batch Item Limit
    if (/(?:bulk|batch)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && !/max\(|length\s*>\s*\d+|limit/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-33|api/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7233,
            type: 'SECURITY',
            title: "API-33: API Bulk Creation Endpoint Lacking Batch Item Limit",
            severity: 'HIGH',
            category: "DoS Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected API Bulk Creation Endpoint Lacking Batch Item Limit: POST /api/v1/items/bulk accepting infinite array lengths, causing event loop starvation on 10,000+ items."
            ],
            remediationPrompt: "Enforce z.array(...).min(1).max(100) on bulk mutation request payloads.",
            status: 'OPEN',
            owner: "Bulk Operations",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-33: API Bulk Creation Endpoint Lacking Batch Item Limit detected (${file.path}:${lineNum})`);
    }
    // API-34: Missing Content-Security-Policy on API JSON Endpoints
    if (/servePublicJsonDocs/i.test(cleanContent) && !/Content-Type-Options/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-34|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7234,
            type: 'SECURITY',
            title: "API-34: Missing Content-Security-Policy on API JSON Endpoints",
            severity: 'LOW',
            category: "Browser Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Content-Security-Policy on API JSON Endpoints: API endpoints omitting basic security headers allowing browser JSON viewer MIME confusion attacks."
            ],
            remediationPrompt: "Add X-Content-Type-Options: nosniff and Content-Type: application/json to all API responses.",
            status: 'OPEN',
            owner: "API Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-34: Missing Content-Security-Policy on API JSON Endpoints detected (${file.path}:${lineNum})`);
    }
    // API-35: Unsanitized User-Controlled Filename in Content-Disposition
    if (/headers\.set\(\s*[\'"]Content-Disposition[\'"]\s*,\s*[\'"]attachment;\s*filename=[\'"]\s*\+\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-35|unsanitized/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7235,
            type: 'SECURITY',
            title: "API-35: Unsanitized User-Controlled Filename in Content-Disposition",
            severity: 'HIGH',
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
    // API-36: Missing Vary Header on Content-Negotiated Responses
    if (/req\.headers\.get\([\'"]accept[\'"]\)[\s\S]*?text\/csv[\s\S]*?application\/json/i.test(cleanContent) && !/Vary/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-36|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7236,
            type: 'SECURITY',
            title: "API-36: Missing Vary Header on Content-Negotiated Responses",
            severity: 'LOW',
            category: "HTTP Caching",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Vary Header on Content-Negotiated Responses: API endpoint serving different representations (JSON vs CSV) based on Accept header without Vary: Accept."
            ],
            remediationPrompt: "Set Vary: Accept, Accept-Encoding on endpoints supporting content negotiation.",
            status: 'OPEN',
            owner: "API Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-36: Missing Vary Header on Content-Negotiated Responses detected (${file.path}:${lineNum})`);
    }
    // API-37: Exposing Internal Database Errors in 400 Bad Request
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /status:\s*400/i.test(cleanContent) && /error:\s*err\.original/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-37|exposing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
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
    // API-38: Session Cookie Omission of SameSite=Lax/Strict on API Auth
    if (/cookies\(\)\.set\s*\(\s*[\'"](?:session|token|auth)[\'"][^)]*sameSite:\s*[\'"]none[\'"](?![^)]*secure:\s*true)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-38|session/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7238,
            type: 'SECURITY',
            title: "API-38: Session Cookie Omission of SameSite=Lax/Strict on API Auth",
            severity: 'HIGH',
            category: "CSRF Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Session Cookie Omission of SameSite=Lax/Strict on API Auth: Setting auth token cookies with SameSite=None without Secure flag, exposing sessions to cross-site CSRF."
            ],
            remediationPrompt: "Set cookie options: { sameSite: 'lax', secure: true, httpOnly: true }.",
            status: 'OPEN',
            owner: "Auth Cookies",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-38: Session Cookie Omission of SameSite=Lax/Strict on API Auth detected (${file.path}:${lineNum})`);
    }
    // API-39: Client IP Resolution Vulnerable to Spoofed X-Forwarded-For
    if (/function\s+getClientIp/i.test(cleanContent) && /req\.headers\.get\([\'"]x-forwarded-for[\'"]\)\?\.split\([\'"],[\'"]\)\[0\]/i.test(cleanContent) && !/cf-connecting-ip|x-real-ip/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-39|client/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7239,
            type: 'SECURITY',
            title: "API-39: Client IP Resolution Vulnerable to Spoofed X-Forwarded-For",
            severity: 'HIGH',
            category: "IP Spoofing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Client IP Resolution Vulnerable to Spoofed X-Forwarded-For: Reading the first entry in x-forwarded-for without validating reverse proxy hop count, allowing IP spoofing."
            ],
            remediationPrompt: "Prioritize cf-connecting-ip or validate trusted reverse proxy headers to prevent IP spoofing.",
            status: 'OPEN',
            owner: "Rate Limiting",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-39: Client IP Resolution Vulnerable to Spoofed X-Forwarded-For detected (${file.path}:${lineNum})`);
    }
    // API-40: Missing 204 No Content Status on Successful Empty Response
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+DELETE/i.test(cleanContent) && /return\s+NextResponse\.json\(\s*\{\s*\}\s*,\s*\{\s*status:\s*200\s*\}\s*\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-40|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7240,
            type: 'SECURITY',
            title: "API-40: Missing 204 No Content Status on Successful Empty Response",
            severity: 'LOW',
            category: "HTTP Semantics",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing 204 No Content Status on Successful Empty Response: Returning 200 OK with empty string or null body on DELETE or empty PUT operations instead of 204 No Content."
            ],
            remediationPrompt: "Return new NextResponse(null, { status: 204 }) for empty successful responses.",
            status: 'OPEN',
            owner: "REST Standards",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-40: Missing 204 No Content Status on Successful Empty Response detected (${file.path}:${lineNum})`);
    }
    // API-41: Missing 201 Created Status on Successful Resource Creation
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+POST/i.test(cleanContent) && /prisma\.[a-zA-Z0-9_]+\.create/i.test(cleanContent) && /return\s+NextResponse\.json\([^,)]+\s*,\s*\{\s*status:\s*200\s*\}\s*\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-41|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7241,
            type: 'SECURITY',
            title: "API-41: Missing 201 Created Status on Successful Resource Creation",
            severity: 'LOW',
            category: "HTTP Semantics",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing 201 Created Status on Successful Resource Creation: POST endpoints creating persistent database records returning 200 OK instead of 201 Created."
            ],
            remediationPrompt: "Return NextResponse.json(newEntity, { status: 201, headers: { Location: `/api/v1/items/${newEntity.id}` } }).",
            status: 'OPEN',
            owner: "REST Standards",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-41: Missing 201 Created Status on Successful Resource Creation detected (${file.path}:${lineNum})`);
    }
    // API-42: Missing Strict Origin Validation in WebSocket Handshake
    if (/new\s+WebSocketServer\s*\(\s*\{(?![^}]*verifyClient)/i.test(cleanContent) && !/localhost/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-42|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7242,
            type: 'SECURITY',
            title: "API-42: Missing Strict Origin Validation in WebSocket Handshake",
            severity: 'CRITICAL',
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
    if (/new\s+WebSocketServer\s*\(\s*\{(?![^}]*maxPayload)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-43|unbounded/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7243,
            type: 'SECURITY',
            title: "API-43: Unbounded WebSocket Message Payload Size",
            severity: 'HIGH',
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
    // API-44: Missing Heartbeat / Ping-Pong Keepalive on Long-Lived WebSockets
    if (/wss\.on\([\'"]connection[\'"][\s\S]*?ws\.on\([\'"]message[\'"]/i.test(cleanContent) && !/ping|pong|heartbeat/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-44|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7244,
            type: 'SECURITY',
            title: "API-44: Missing Heartbeat / Ping-Pong Keepalive on Long-Lived WebSockets",
            severity: 'MEDIUM',
            category: "Connection Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Heartbeat / Ping-Pong Keepalive on Long-Lived WebSockets: WebSocket connections lacking periodic 30-second ping/pong heartbeat, leading to ghost connections and socket leaks."
            ],
            remediationPrompt: "Implement 30-second ping/pong heartbeat interval on active WebSocket connections.",
            status: 'OPEN',
            owner: "WebSockets",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-44: Missing Heartbeat / Ping-Pong Keepalive on Long-Lived WebSockets detected (${file.path}:${lineNum})`);
    }
    // API-45: API Token Generation Using Math.random Instead of Crypto
    if (/const\s+(?:token|apiKey|secret|otp)\s*=\s*Math\.random\(\)\.toString\(36\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-45|api/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7245,
            type: 'SECURITY',
            title: "API-45: API Token Generation Using Math.random Instead of Crypto",
            severity: 'CRITICAL',
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
    if (/(?:apiKey|api_key|token)\s*===\s*(?:storedApiKey|secretKey|configuredKey)\b/i.test(cleanContent) && !/timingSafeEqual/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-46|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7246,
            type: 'SECURITY',
            title: "API-46: Missing Timing-Safe Comparison on API Key Authentication",
            severity: 'HIGH',
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
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-47|api/i.test(l) || lines.indexOf(l) === 0));
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
    // API-48: Missing OpenAPI / Swagger Contract Documentation
    if (/exportApiDocumentation/i.test(cleanContent) && !/openapi:\s*[\'"]3\./i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-48|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `api48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7248,
            type: 'SECURITY',
            title: "API-48: Missing OpenAPI / Swagger Contract Documentation",
            severity: 'LOW',
            category: "API Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected API-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing OpenAPI / Swagger Contract Documentation: Public or partner-facing API services operating without machine-readable OpenAPI 3.1 specification."
            ],
            remediationPrompt: "Generate or maintain openapi.json / swagger.json documenting endpoints and schemas.",
            status: 'OPEN',
            owner: "API Specs",
            falsePositive: false
        });
        logs.push(`[${ts}] 🌐 API-48: Missing OpenAPI / Swagger Contract Documentation detected (${file.path}:${lineNum})`);
    }
    // API-49: Unsafe URL Redirection in OAuth Callback Handler
    if (/auth\/callback/i.test(lowerPath) && /NextResponse\.redirect\s*\(\s*(?:searchParams\.get\([\'"]next[\'"]\)|req\.query\.returnUrl)\s*\)/i.test(cleanContent) && !/startsWith\([\'"]\/[\'"]\)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-49|unsafe/i.test(l) || lines.indexOf(l) === 0));
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
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/api-50|exposing/i.test(l) || lines.indexOf(l) === 0));
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
