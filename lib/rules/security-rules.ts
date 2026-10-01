import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
export function evaluateSecurityRules(file: CodeFile, lines: string[], cleanContentOrCounter: string | {
    count: number;
}, counterMaybe?: {
    count: number;
}): {
    findings: Finding[];
    logs: string[];
} {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const cleanContent = typeof cleanContentOrCounter === 'string' ? cleanContentOrCounter : file.content;
    const findingCounter = typeof cleanContentOrCounter === 'object' ? cleanContentOrCounter : (counterMaybe || { count: 1 });
    const ts = new Date().toLocaleTimeString();
    const lowerPath = file.path.toLowerCase();
    if (lowerPath.includes('data/catalogs/')) {
        return { findings, logs };
    }
    // Rule 1: Exposed Stripe/OpenAI API Keys (SEC-01)
    if (cleanContent.includes('sk_live_') || cleanContent.includes('sk-proj-') || /api[_-]?key\s*=\s*["']sk-[a-zA-Z0-9_-]{20,}/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (l.includes('sk_live_') || l.includes('sk-proj-') || /sk-[a-zA-Z0-9_-]{20,}/i.test(l)));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1,
            type: 'SECURITY',
            title: 'Exposed Hardcoded OpenAI/Stripe Secret API Key',
            severity: 'CRITICAL',
            category: 'Secret Isolation',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || 'const API_KEY = "sk-live-..."',
            reproductionSteps: [
                `Scanned source file at ${file.path}:${lineNum}.`,
                'Detected hardcoded live secret token pattern in client/server code.'
            ],
            remediationPrompt: `Extract secret API key in ${file.path} to process.env.OPENAI_API_KEY. Never commit secret tokens to version control.`,
            status: 'OPEN',
            owner: 'Security Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: SEC-01 Hardcoded Secret API Key in ${file.path}:${lineNum}`);
    }
    // Rule 3: Supabase Permissive Row Level Security (RLS) (SEC-03)
    if (cleanContent.includes('USING (true)') || cleanContent.includes('FOR ALL USING (true)')) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('--') && l.includes('USING (true)'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 3,
            type: 'SECURITY',
            title: 'Permissive Row Level Security (RLS) Policy (USING true)',
            severity: 'CRITICAL',
            category: 'Database',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'USING (true);',
            reproductionSteps: [
                `Scanned database migration SQL at ${file.path}:${lineNum}.`,
                'Detected default allow-all policy using (true).'
            ],
            remediationPrompt: `Replace permissive RLS policy in ${file.path}. Write strict auth.uid() = user_id checks.`,
            status: 'OPEN',
            owner: 'Backend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: SEC-03 Permissive RLS Policy in ${file.path}:${lineNum}`);
    }
    // Rule 8: Restrict CORS to Production Domains (SEC-08)
    if (cleanContent.includes("origin: '*'") || cleanContent.includes('Access-Control-Allow-Origin: *') || cleanContent.includes('"Access-Control-Allow-Origin", "*"')) {
        const matchLineIdx = lines.findIndex(l => l.includes("origin: '*'") || l.includes('Access-Control-Allow-Origin') && l.includes('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8,
            type: 'SECURITY',
            title: 'Wildcard Access-Control-Allow-Origin (*) CORS Vulnerability',
            severity: 'HIGH',
            category: 'Network & CORS',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "origin: '*'",
            reproductionSteps: [
                `Scanned API server setup at ${file.path}:${lineNum}.`,
                'Detected wildcard Access-Control-Allow-Origin header allowing unauthorized origins.'
            ],
            remediationPrompt: `Restrict CORS origin in ${file.path} to process.env.PRODUCTION_CLIENT_URL.`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚠️ HIGH: SEC-08 Wildcard CORS configuration in ${file.path}:${lineNum}`);
    }
    // Rule 16: Dangerously Set Inner HTML (XSS) (SEC-16)
    const isSafeMdxOrJsonLd = file.path.includes('mdx-components') || file.path.includes('syntax-highlight') || cleanContent.includes('application/ld+json');
    if (!isSafeMdxOrJsonLd && (cleanContent.includes('dangerouslySetInnerHTML') || cleanContent.includes('innerHTML ='))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && (l.includes('dangerouslySetInnerHTML') || l.includes('innerHTML')));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16,
            type: 'SECURITY',
            title: 'Unsanitized Direct InnerHTML DOM Mutation (XSS Risk)',
            severity: 'HIGH',
            category: 'Input & Files',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'dangerouslySetInnerHTML={{ __html: content }}',
            reproductionSteps: [
                `Scanned frontend component rendering at ${file.path}:${lineNum}.`,
                'Detected unescaped DOM insertion susceptible to Cross-Site Scripting.'
            ],
            remediationPrompt: `Sanitize input in ${file.path} using DOMPurify before setting innerHTML.`,
            status: 'OPEN',
            owner: 'Frontend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚠️ HIGH: SEC-16 Unsanitized innerHTML in ${file.path}:${lineNum}`);
    }
    // Rule 20 / SEC-20 (SEC-SCA-01): Vulnerable Dependency & Wildcard Version
    if (lowerPath.endsWith('package.json')) {
        const KNOWN_VULNERABLE_PACKAGES: Record<string, {
            minSafe: string;
            reason: string;
        }> = {
            lodash: {
                minSafe: '4.17.21',
                reason: 'Prototype pollution & command injection vulnerabilities (CVE-2020-8203, CVE-2021-23337)'
            },
            axios: {
                minSafe: '1.7.4',
                reason: 'Server-Side Request Forgery (SSRF) and header injection vulnerabilities (CVE-2023-45857, CVE-2024-39338)'
            },
            moment: {
                minSafe: 'DEPRECATED',
                reason: 'Deprecated library with known Regular Expression Denial of Service (ReDoS) issues and high bundle size'
            },
            minimist: {
                minSafe: '1.2.6',
                reason: 'Prototype pollution vulnerability (CVE-2021-44906)'
            },
            jsonwebtoken: {
                minSafe: '9.0.0',
                reason: 'Key confusion and signature verification bypass vulnerabilities'
            },
            express: {
                minSafe: '4.19.2',
                reason: 'Open redirect and IP spoofing vulnerabilities (CVE-2024-29041)'
            }
        };
        const isVersionLessThan = (actual: string, minSafe: string): boolean => {
            const cleanActual = actual.replace(/^[^\d]*/, '').split('-')[0].trim();
            const cleanMinSafe = minSafe.replace(/^[^\d]*/, '').split('-')[0].trim();
            if (!cleanActual || !cleanMinSafe)
                return false;
            const actualParts = cleanActual.split('.').map((p) => parseInt(p, 10) || 0);
            const minSafeParts = cleanMinSafe.split('.').map((p) => parseInt(p, 10) || 0);
            for (let i = 0; i < 3; i++) {
                const a = actualParts[i] ?? 0;
                const m = minSafeParts[i] ?? 0;
                if (a < m)
                    return true;
                if (a > m)
                    return false;
            }
            return false;
        };
        const processDep = (depName: string, version: string) => {
            const v = String(version).trim();
            const isWildcard = v === '*' || v === 'latest' || v === 'x' || v === '' || v.startsWith('>=0.');
            const vulnDef = KNOWN_VULNERABLE_PACKAGES[depName.toLowerCase()];
            const isDeprecated = vulnDef?.minSafe === 'DEPRECATED';
            const isOutdated = vulnDef && !isDeprecated && isVersionLessThan(v, vulnDef.minSafe);
            if (isWildcard || isDeprecated || isOutdated) {
                const matchLineIdx = lines.findIndex((l) => l.includes(`"${depName}"`));
                const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                let issueDescription = '';
                let remediation = '';
                if (isWildcard) {
                    issueDescription = `Detected unpinned wildcard version "${v}" for package "${depName}". Wildcard dependencies create non-deterministic builds and supply chain injection risks.`;
                    remediation = `Pin exact dependency version in ${file.path} for "${depName}". Replace "${v}" with a safe pinned semver release (e.g. "^1.0.0").`;
                }
                else if (isDeprecated) {
                    issueDescription = `Detected package "${depName}" (${v}) is deprecated: ${vulnDef?.reason}.`;
                    remediation = `Replace deprecated "${depName}" in ${file.path} with a modern maintained alternative such as "date-fns" or "dayjs".`;
                }
                else if (isOutdated && vulnDef) {
                    issueDescription = `Detected dependency "${depName}": "${v}" with published security CVE vulnerability advisory (${vulnDef.reason}). Minimum safe version is >= ${vulnDef.minSafe}.`;
                    remediation = `Upgrade "${depName}" from ${v} to >= ${vulnDef.minSafe} in ${file.path} to resolve published CVE vulnerabilities.`;
                }
                findings.push({
                    id: `real-find-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 20,
                    type: 'SECURITY',
                    title: 'Vulnerable Dependency or Wildcard Version in package.json',
                    severity: 'HIGH',
                    category: 'Supply Chain & Deps',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || `"${depName}": "${version}"`,
                    reproductionSteps: [
                        `Scanned package manifest at ${file.path}:${lineNum}.`,
                        issueDescription
                    ],
                    remediationPrompt: remediation,
                    status: 'OPEN',
                    owner: 'DevOps & Security Lead',
                    falsePositive: false
                });
                logs.push(`[${ts}] 📦 HIGH: SEC-20 ${depName}@${version} in ${file.path}:${lineNum}`);
            }
        };
        try {
            const pkg = JSON.parse(file.content);
            const allDeps: Record<string, string> = {
                ...(pkg.dependencies || {}),
                ...(pkg.devDependencies || {}),
                ...(pkg.peerDependencies || {})
            };
            for (const [depName, version] of Object.entries(allDeps)) {
                processDep(depName, version);
            }
        }
        catch {
            const depRegex = /"([^"]+)"\s*:\s*"([^"]+)"/g;
            let match: RegExpExecArray | null;
            while ((match = depRegex.exec(file.content)) !== null) {
                const [, depName, version] = match;
                if (depName && version && (depName.toLowerCase() in KNOWN_VULNERABLE_PACKAGES || version === '*' || version === 'latest')) {
                    processDep(depName, version);
                }
            }
        }
    }
    // Rule 21 / SEC-21 (SEC-LOG-01): Potential Secret or PII Log Leakage
    const isCodeFile = /\.(?:tsx?|jsx?|mjs|cjs|py|go|rs|php|cs|java|rb|cpp|c|h|hpp)$/i.test(file.path);
    if (isCodeFile && !lowerPath.endsWith('package.json')) {
        const logCallRegex = /(?:console\.(?:log|error|warn|info|debug)|logger\.(?:info|error|warn|debug)|print|System\.out\.println)\s*\(/i;
        const sensitiveVarRegex = /(?:\$\{[^}]*(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|(?:\+\s*|,\s*|:\s*)(?:[a-zA-Z0-9_.]+\.)?(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|\{\s*(?:[a-zA-Z0-9_]+(?::\s*[^,}]+)?,\s*)*(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|\(\s*(?:[a-zA-Z0-9_.]+\.)?(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\s*[\),]|(?:req\.headers(?:\.authorization)?|headers\[['"]authorization['"]\]))/i;
        const safeMaskRegex = /(?:mask|redact|hash|\[REDACTED\]|\*\*\*)/i;
        let logMatchesInFile = 0;
        for (let idx = 0; idx < lines.length; idx++) {
            const line = lines[idx];
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*'))
                continue;
            if (logCallRegex.test(line) && sensitiveVarRegex.test(line) && !safeMaskRegex.test(line)) {
                if (logMatchesInFile >= 5)
                    break; // Cap per file to avoid telemetry flooding
                logMatchesInFile++;
                const lineNum = idx + 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                findings.push({
                    id: `real-find-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 21,
                    type: 'SECURITY',
                    title: 'Potential Secret or PII Log Leakage in Application Telemetry',
                    severity: 'HIGH',
                    category: 'Secret Isolation',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || line.trim(),
                    reproductionSteps: [
                        `Scanned application source file at ${file.path}:${lineNum}.`,
                        'Detected logging statement printing unredacted sensitive credential (token, secret, password, or PII) to stdout/telemetry stream.'
                    ],
                    remediationPrompt: `Remove plain-text credential logging in ${file.path}:${lineNum}. Use structured server-side logging with automated PII masking and redaction filters (lib/logger.ts) instead of outputting raw tokens or request headers.`,
                    status: 'OPEN',
                    owner: 'Security Lead',
                    falsePositive: false
                });
                logs.push(`[${ts}] 🪵 HIGH: SEC-21 Potential secret/PII log leakage in ${file.path}:${lineNum}`);
            }
        }
    }
    // Rule 22 / SEC-22 (SEC-LLM-01): Client-Side Direct LLM API SDK Exposure
    const isClientComponent = /['"]use client['"]/i.test(cleanContent) || /['"]use client['"]/i.test(file.content);
    if (isClientComponent && /\.(?:tsx?|jsx?)$/i.test(file.path)) {
        const LLM_SDK_IMPORT_REGEX = /(?:import\s+.*?from\s+['"](?:openai|@anthropic-ai\/sdk|@google\/genai|@google\/generative-ai|groq-sdk|replicate)['"]|require\(['"](?:openai|@anthropic-ai\/sdk|@google\/genai|@google\/generative-ai|groq-sdk|replicate)['"]\))/i;
        const DANGEROUS_BROWSER_REGEX = /dangerouslyAllowBrowser\s*:\s*true/i;
        const SYSTEM_PROMPT_LEAK_REGEX = /(?:role\s*:\s*['"]system['"]|const\s+(?:systemPrompt|SYSTEM_PROMPT|systemInstruction)\s*=\s*['"`])/i;
        const hasLlmImport = LLM_SDK_IMPORT_REGEX.test(cleanContent);
        const hasDangerousBrowser = DANGEROUS_BROWSER_REGEX.test(cleanContent);
        const hasSystemPromptLeak = SYSTEM_PROMPT_LEAK_REGEX.test(cleanContent);
        if (hasLlmImport || hasDangerousBrowser || hasSystemPromptLeak) {
            let matchLineIdx = lines.findIndex((l) => !l.trim().startsWith('//') && (LLM_SDK_IMPORT_REGEX.test(l) || DANGEROUS_BROWSER_REGEX.test(l) || SYSTEM_PROMPT_LEAK_REGEX.test(l)));
            if (matchLineIdx === -1) {
                matchLineIdx = lines.findIndex((l) => /openai|anthropic|dangerouslyAllowBrowser|genai/i.test(l));
            }
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            let detail = 'Detected direct import of backend LLM API SDK in a client bundle ("use client"), exposing API keys and proprietary logic to browser DevTools.';
            if (hasDangerousBrowser) {
                detail = 'Detected dangerouslyAllowBrowser: true flag in client component, bypassing SDK security boundaries and exposing client-side API keys.';
            }
            else if (hasSystemPromptLeak && !hasLlmImport) {
                detail = 'Detected proprietary system prompt strings hardcoded directly inside client-side component.';
            }
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 22,
                type: 'SECURITY',
                title: 'Client-Side Direct LLM API SDK Exposure',
                severity: 'CRITICAL',
                category: 'AI & LLM Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || "import OpenAI from 'openai';",
                reproductionSteps: [
                    `Scanned client component at ${file.path}:${lineNum}.`,
                    detail
                ],
                remediationPrompt: `Refactor ${file.path} to remove client-side LLM SDK invocations and dangerouslyAllowBrowser flags. Route all model requests through a secure server-side API endpoint (e.g. app/api/chat/route.ts) with server-only environment variables and system prompts.`,
                status: 'OPEN',
                owner: 'AI Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-22 Client-side direct LLM API SDK exposure in ${file.path}:${lineNum}`);
        }
    }
    // Rule 14 / SEC-14: Insecure JWT & Session Secret Hardcoded Fallbacks
    const jwtFallbackRegex = /(?:JWT_SECRET|SESSION_SECRET|AUTH_SECRET|COOKIE_SECRET|NEXTAUTH_SECRET)\s*(?:\|\||\?\?)\s*['"`][^'"`]+['"`]/i;
    if (isCodeFile && jwtFallbackRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && jwtFallbackRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14,
            type: 'SECURITY',
            title: 'Insecure Hardcoded Fallback for Cryptographic Session / JWT Secret',
            severity: 'CRITICAL',
            category: 'Authentication & Tokens',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || "const secret = process.env.JWT_SECRET || 'secret';",
            reproductionSteps: [
                `Scanned authentication token signing in ${file.path}:${lineNum}.`,
                'Detected hardcoded default fallback string for JWT/Session secret token, allowing attackers to forge arbitrary authentication cookies and tokens if environment variable is unset.'
            ],
            remediationPrompt: `Remove insecure default fallback in ${file.path}:${lineNum}. Enforce a strict runtime assertion: if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET must be configured in production');`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: SEC-14 Insecure JWT secret fallback in ${file.path}:${lineNum}`);
    }
    // Rule 15 / SEC-15: Unauthenticated Next.js API Mutation Route Handler
    const isApiRoute = (lowerPath.includes('app/api/') || lowerPath.includes('pages/api/')) && /\.(?:ts|js)$/i.test(file.path);
    const isPublicWebhookOrHealth = lowerPath.includes('webhook') || lowerPath.includes('health') || lowerPath.includes('ping') || lowerPath.includes('auth/callback');
    if (isApiRoute && !isPublicWebhookOrHealth) {
        const hasMutationExport = /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(cleanContent);
        const hasAuthCheck = /(?:auth|session|supabase\.auth|verify|currentUser|getUser|getSession|apiKey|checkRateLimit|rateLimiter|req\.headers\.get\(['"]authorization['"]\))/i.test(cleanContent);
        if (hasMutationExport && !hasAuthCheck) {
            const matchLineIdx = lines.findIndex(l => /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 15,
                type: 'SECURITY',
                title: 'Unauthenticated API Mutation Route Handler (Missing Session / Auth Guard)',
                severity: 'HIGH',
                category: 'API Security & Auth',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'export async function POST(req: NextRequest) {',
                reproductionSteps: [
                    `Scanned API route handler at ${file.path}:${lineNum}.`,
                    'Detected state-mutating HTTP handler (POST/PUT/DELETE) without session verification, authentication check, or rate-limiting middleware.'
                ],
                remediationPrompt: `Protect ${file.path}:${lineNum} with authentication verification (e.g. check authenticated user session or API token) and apply rate limiting before processing state mutations.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ HIGH: SEC-15 Unauthenticated API mutation route in ${file.path}:${lineNum}`);
        }
    }
    // Rule 16 / SEC-16: SSRF in Webhook & Outbound Fetch Dispatch
    if (isCodeFile && !isPublicWebhookOrHealth) {
        const outboundFetchRegex = /fetch\s*\(\s*(?:req\.(?:body|query|params)\.[a-zA-Z0-9_]+|url|targetUrl|webhookUrl|callbackUrl)/i;
        const ssrfGuardRegex = /(?:validateSafeTargetUrl|isAllowedWebhookUrl|isPrivateIp|ssrfGuard|allowedDomains|new URL\([^)]*\)\.hostname)/i;
        if (outboundFetchRegex.test(cleanContent) && !ssrfGuardRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && outboundFetchRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 16,
                type: 'SECURITY',
                title: 'Server-Side Request Forgery (SSRF) in Outbound Fetch / Webhook Dispatch',
                severity: 'CRITICAL',
                category: 'Network & SSRF',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await fetch(targetUrl);',
                reproductionSteps: [
                    `Scanned outbound network request at ${file.path}:${lineNum}.`,
                    'Detected dynamic HTTP request dispatch accepting user-controlled target URL without private IP or DNS rebinding validation.'
                ],
                remediationPrompt: `Validate destination URLs before dispatching HTTP requests in ${file.path}:${lineNum}. Reject internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254) and enforce an explicit domain whitelist.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-16 Unvalidated outbound fetch / SSRF risk in ${file.path}:${lineNum}`);
        }
    }
    // Rule 17 / SEC-17: Broken Object Level Authorization (BOLA / IDOR)
    if (isApiRoute) {
        const dbQueryWithParamRegex = /(?:prisma\.[a-zA-Z0-9_]+\.(?:findUnique|findFirst|update|delete)|supabase\.from\([^)]+\)\.(?:select|update|delete))\s*\([^)]*(?:params\.id|query\.id|req\.params|req\.query)/i;
        const tenantCheckRegex = /(?:auth\.uid\(\)|user_id|userId|session\.user\.id|tenantId|orgId|account_id)/i;
        if (dbQueryWithParamRegex.test(cleanContent) && !tenantCheckRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && dbQueryWithParamRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 17,
                type: 'SECURITY',
                title: 'Potential Broken Object Level Authorization (BOLA / IDOR)',
                severity: 'CRITICAL',
                category: 'Authentication & Access Control',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await prisma.record.findUnique({ where: { id: params.id } })',
                reproductionSteps: [
                    `Scanned database query in API route at ${file.path}:${lineNum}.`,
                    'Detected resource access keyed exclusively by user-provided ID without verifying record ownership against the authenticated session user ID.'
                ],
                remediationPrompt: `Scope query to authenticated session user in ${file.path}:${lineNum}. Ensure database queries include { where: { id: params.id, userId: session.user.id } }.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-17 Potential BOLA/IDOR in ${file.path}:${lineNum}`);
        }
    }
    // Rule 18 / SEC-18: Prompt Injection Risk via Direct User String Interpolation (LLM01)
    if (isCodeFile) {
        const promptConcatRegex = /(?:messages:\s*\[[^\]]*(?:content:\s*`[^`]*\$\{(?:req\.body|prompt|userInput|query|text)|content:\s*(?:userInput|prompt|text)\s*\+))/i;
        const promptGuardRegex = /(?:sanitizePrompt|validatePrompt|systemGuard|delimiter|guardrails|zod)/i;
        if (promptConcatRegex.test(cleanContent) && !promptGuardRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && promptConcatRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18,
                type: 'SECURITY',
                title: 'Direct User Input Interpolation into LLM Prompt (OWASP LLM01 Prompt Injection)',
                severity: 'HIGH',
                category: 'AI & LLM Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'messages: [{ role: "user", content: `User query: ${req.body.query}` }]',
                reproductionSteps: [
                    `Scanned LLM message preparation at ${file.path}:${lineNum}.`,
                    'Detected raw user input template literal interpolation without delimiters, input sanitization, or defensive guardrails.'
                ],
                remediationPrompt: `Isolate untrusted user input using XML/triple-quote delimiters and validate inputs with defensive guardrails in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'AI Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ HIGH: SEC-18 Prompt injection risk in ${file.path}:${lineNum}`);
        }
    }
    // Rule 19 / SEC-19: Excessive Agency & Unbounded Function Calling (OWASP LLM08)
    if (isCodeFile) {
        const llmToolCallRegex = /(?:tools:\s*\[[^\]]*(?:exec|deleteDatabase|dropTable|eval|sendEmail|transferFunds)|autoRun:\s*true)/i;
        const humanInLoopRegex = /(?:confirmWithUser|requireApproval|humanInTheLoop|dryRun)/i;
        if (llmToolCallRegex.test(cleanContent) && !humanInLoopRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && llmToolCallRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 19,
                type: 'SECURITY',
                title: 'Autonomous Destructive LLM Tool Calling (OWASP LLM08 Excessive Agency)',
                severity: 'CRITICAL',
                category: 'AI & LLM Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'tools: [deleteDatabaseTool], autoRun: true',
                reproductionSteps: [
                    `Scanned LLM agent tools at ${file.path}:${lineNum}.`,
                    'Detected autonomous tool binding with destructive capabilities without mandatory human confirmation or approval gate.'
                ],
                remediationPrompt: `Require explicit human approval before executing destructive actions (data deletion, financial mutations, arbitrary execution) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'AI Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-19 Excessive agency in LLM tools in ${file.path}:${lineNum}`);
        }
    }
    // Rule 23 / SEC-23: Mass Assignment in Database Mutations
    if (isApiRoute) {
        const massAssignRegex = /(?:prisma\.[a-zA-Z0-9_]+\.(?:create|update)\s*\(\s*\{\s*data:\s*(?:req\.body|await req\.json\(\)|body)|db\.[a-zA-Z0-9_]+\.create\s*\(\s*(?:req\.body|body)\s*\))/i;
        const schemaParseRegex = /(?:parse|safeParse|validate|pick|whitelist|allowedFields)/i;
        if (massAssignRegex.test(cleanContent) && !schemaParseRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && massAssignRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 23,
                type: 'SECURITY',
                title: 'Mass Assignment Vulnerability in Database Mutation (CWE-915)',
                severity: 'HIGH',
                category: 'Database & API Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await prisma.user.update({ data: req.body });',
                reproductionSteps: [
                    `Scanned database mutation at ${file.path}:${lineNum}.`,
                    'Detected unparsed client request body passed directly into database persistence layer, allowing attackers to overwrite sensitive columns (role, isAdmin, balance).'
                ],
                remediationPrompt: `Validate and sanitize incoming payload with Zod schema (e.g. UpdateUserSchema.parse(body)) before persisting to database in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ HIGH: SEC-23 Mass assignment risk in ${file.path}:${lineNum}`);
        }
    }
    // Rule 24 / SEC-24: Path Traversal in File Operations (CWE-22)
    if (isCodeFile) {
        const pathTraversalRegex = /(?:fs\.(?:readFile|createReadStream|promises\.readFile|readFileSync))\s*\([^)]*(?:req\.(?:query|params|body)|searchParams\.get|params\.)/i;
        const pathSanitizeRegex = /(?:path\.resolve|path\.basename|sanitizeFilename|starts_with|startsWith)/i;
        if (pathTraversalRegex.test(cleanContent) && !pathSanitizeRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && pathTraversalRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 24,
                type: 'SECURITY',
                title: 'Path Traversal in Filesystem Operations (CWE-22)',
                severity: 'CRITICAL',
                category: 'Application Security / Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'fs.readFile(req.query.file, "utf8")',
                reproductionSteps: [
                    `Scanned filesystem interaction at ${file.path}:${lineNum}.`,
                    'Detected user-controlled request parameter passed directly into filesystem read operation without canonical base path validation.'
                ],
                remediationPrompt: `Sanitize filename with path.basename() and assert resolvedPath.startsWith(BASE_DIR + path.sep) in ${file.path}:${lineNum}.`,
                diffPatch: `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},2 +${lineNum},4 @@\n-const content = await fs.promises.readFile(req.query.file);\n+const safeName = path.basename(req.query.file);\n+const resolved = path.resolve(BASE_DIR, safeName);\n+if (!resolved.startsWith(BASE_DIR)) throw new Error('Forbidden');\n+const content = await fs.promises.readFile(resolved);`,
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-24 Path Traversal (CWE-22) in ${file.path}:${lineNum}`);
        }
    }
    // Rule 25 / SEC-25: Open Redirects via Unvalidated Return URLs (CWE-601)
    if (isCodeFile && (isApiRoute || file.path.includes('app/'))) {
        const openRedirectRegex = /(?:NextResponse\.redirect|res\.redirect)\s*\(\s*(?:req\.query|searchParams\.get|params\.)/i;
        const urlValidationRegex = /(?:startsWith\(['"]\/['"]\)|new URL\([^)]*\)\.origin|allowedOrigins|isValidRedirect)/i;
        if (openRedirectRegex.test(cleanContent) && !urlValidationRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && openRedirectRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 25,
                type: 'SECURITY',
                title: 'Open Redirect via Unvalidated Return URL (CWE-601)',
                severity: 'HIGH',
                category: 'Authentication & Session',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'return NextResponse.redirect(searchParams.get("returnUrl"));',
                reproductionSteps: [
                    `Scanned redirect handler at ${file.path}:${lineNum}.`,
                    'Detected HTTP redirect accepting unvalidated return URL parameter, allowing phishing attackers to redirect authenticated users to external malicious domains.'
                ],
                remediationPrompt: `Validate redirect destination: enforce relative paths (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) or verify against trusted host origins in ${file.path}:${lineNum}.`,
                diffPatch: `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},2 +${lineNum},3 @@\n-return NextResponse.redirect(url);\n+const safeUrl = (url.startsWith('/') && !url.startsWith('//')) ? url : '/dashboard';\n+return NextResponse.redirect(new URL(safeUrl, req.url));`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ HIGH: SEC-25 Open Redirect (CWE-601) in ${file.path}:${lineNum}`);
        }
    }
    // Rule 26 / SEC-26: GraphQL Query Depth & Complexity Limits (DoS Prevention)
    if (isCodeFile && (cleanContent.includes('ApolloServer') || cleanContent.includes('createYoga') || cleanContent.includes('createHandler'))) {
        const hasDepthLimit = /validationRules.*depthLimit|createComplexityLimitRule|graphql-depth-limit/i.test(cleanContent);
        if (!hasDepthLimit) {
            const matchLineIdx = lines.findIndex(l => /ApolloServer|createYoga|createHandler/i.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 26,
                type: 'SECURITY',
                title: 'GraphQL Query Depth & Complexity Limits Missing (DoS Prevention)',
                severity: 'HIGH',
                category: 'API Security & DoS',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'const server = new ApolloServer({ typeDefs, resolvers });',
                reproductionSteps: [
                    `Scanned GraphQL server initialization at ${file.path}:${lineNum}.`,
                    'Detected GraphQL endpoint without validationRules enforcing query depth or complexity limits, exposing server to circular query denial of service.'
                ],
                remediationPrompt: `Add graphql-depth-limit (max depth <= 7) to validationRules in GraphQL server configuration in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'API Team',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ HIGH: SEC-26 GraphQL missing depth limit in ${file.path}:${lineNum}`);
        }
    }
    // Rule 27 / SEC-27: Catastrophic Backtracking Regular Expression (ReDoS CWE-1333)
    if (isCodeFile) {
        const redosRegex = /\/\((?:[^\)\(]+[+*]){2,}\)[+*]\/|\/\((?:[a-zA-Z0-9_]+[\s|]+)+[a-zA-Z0-9_]+\)[+*]\//;
        if (redosRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && redosRegex.test(l));
            if (matchLineIdx !== -1) {
                const lineNum = matchLineIdx + 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                findings.push({
                    id: `real-find-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 27,
                    type: 'SECURITY',
                    title: 'Catastrophic Backtracking Regular Expression (ReDoS CWE-1333)',
                    severity: 'HIGH',
                    category: 'API Security & DoS',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || lines[matchLineIdx] || 'const pattern = /([a-z]+)+$/;',
                    reproductionSteps: [
                        `Scanned regular expression pattern at ${file.path}:${lineNum}.`,
                        'Detected nested quantifiers in regular expression vulnerable to polynomial or exponential backtracking denial of service.'
                    ],
                    remediationPrompt: `Refactor regular expression to avoid nested quantifiers or validate maximum input length before regex evaluation in ${file.path}:${lineNum}.`,
                    status: 'OPEN',
                    owner: 'Security Lead',
                    falsePositive: false
                });
                logs.push(`[${ts}] ⚠️ HIGH: SEC-27 ReDoS pattern in ${file.path}:${lineNum}`);
            }
        }
    }
    // Rule 28 / SEC-28: JWT Algorithm Confusion & None Algorithm Acceptance
    if (isCodeFile && cleanContent.includes('jwt.verify')) {
        const jwtVerifyWithoutAlgRegex = /jwt\.verify\s*\([^,]+,\s*[^,)]+\s*\)/;
        const noneAlgorithmRegex = /algorithms\s*:\s*\[[^\]]*['"]none['"]/i;
        if (jwtVerifyWithoutAlgRegex.test(cleanContent) || noneAlgorithmRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && (jwtVerifyWithoutAlgRegex.test(l) || noneAlgorithmRegex.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 28,
                type: 'SECURITY',
                title: 'JWT Algorithm Confusion Vulnerability (Missing Algorithms Whitelist)',
                severity: 'CRITICAL',
                category: 'Cryptographic & Auth Failures',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'jwt.verify(token, secret);',
                reproductionSteps: [
                    `Scanned JWT token verification at ${file.path}:${lineNum}.`,
                    'Detected jwt.verify() without explicit algorithms whitelist ({ algorithms: ["HS256"] }), allowing attackers to forge tokens using algorithm confusion or unsigned none algorithm.'
                ],
                remediationPrompt: `Provide explicit algorithms whitelist to jwt.verify(token, secret, { algorithms: ['HS256'] }) in ${file.path}:${lineNum}.`,
                diffPatch: `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},1 +${lineNum},1 @@\n-jwt.verify(token, secret);\n+jwt.verify(token, secret, { algorithms: ['HS256'] });`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-28 JWT Algorithm Confusion risk in ${file.path}:${lineNum}`);
        }
    }
    // Rule 30 / SEC-30: Sensitive Cookie Domain Scope (Domain=.example.com Leaks)
    if (isCodeFile && (cleanContent.includes('domain:') || cleanContent.includes('Domain='))) {
        const looseCookieDomainRegex = /domain\s*:\s*['"]\.[a-zA-Z0-9.-]+['"]|Domain=\.[a-zA-Z0-9.-]+/i;
        if (looseCookieDomainRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && looseCookieDomainRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 30,
                type: 'SECURITY',
                title: 'Sensitive Cookie Loose Parent Domain Scope (Wildcard Domain Leak)',
                severity: 'MEDIUM',
                category: 'Cookie & Session Management',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'cookies().set({ name: "token", domain: ".example.com" });',
                reproductionSteps: [
                    `Scanned cookie configuration at ${file.path}:${lineNum}.`,
                    'Detected wildcard parent domain attribute on cookie, exposing sensitive session tokens to all current and future subdomains.'
                ],
                remediationPrompt: `Remove leading dot or wildcard domain attribute from cookie configuration in ${file.path}:${lineNum} so cookies remain scoped to origin host.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🍪 MEDIUM: SEC-30 Loose cookie domain scope in ${file.path}:${lineNum}`);
        }
    }
    // Rule 31 / SEC-31: Insecure File Deserialization / YAML / XML External Entity (XXE)
    if (isCodeFile && (cleanContent.includes('yaml.load') || cleanContent.includes('xml2js'))) {
        const unsafeYamlRegex = /yaml\.load\s*\([^,)]+\)/;
        if (unsafeYamlRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && unsafeYamlRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 31,
                type: 'SECURITY',
                title: 'Insecure YAML Deserialization (CWE-502 Remote Code Execution)',
                severity: 'CRITICAL',
                category: 'Injection & Deserialization',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'const data = yaml.load(userFile);',
                reproductionSteps: [
                    `Scanned YAML parser execution at ${file.path}:${lineNum}.`,
                    'Detected unsafe yaml.load() call vulnerable to arbitrary object instantiation and remote code execution.'
                ],
                remediationPrompt: `Replace unsafe yaml.load() with YAML.parse() or yaml.load(file, { schema: yaml.FAILSAFE_SCHEMA }) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-31 Insecure YAML deserialization in ${file.path}:${lineNum}`);
        }
    }
    // Rule 4001 / LLM-01: Unbounded Token Consumption & Cost Quota Exhaustion (OWASP LLM04)
    if (isCodeFile && (cleanContent.includes('openai.chat.completions.create') || cleanContent.includes('anthropic.messages.create'))) {
        const missingMaxTokensRegex = /(?:openai\.chat\.completions\.create|anthropic\.messages\.create)\s*\(\s*\{(?![^}]*(?:max_tokens|maxTokens|maxOutputTokens))/;
        if (missingMaxTokensRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && /openai\.chat\.completions\.create|anthropic\.messages\.create/.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 4001,
                type: 'SECURITY',
                title: 'Unbounded LLM Token Consumption (OWASP LLM04 Model Denial of Service)',
                severity: 'HIGH',
                category: 'AI & LLM Resource Management',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await openai.chat.completions.create({ model: "gpt-4", messages })',
                reproductionSteps: [
                    `Scanned LLM completion request at ${file.path}:${lineNum}.`,
                    'Detected LLM invocation missing max_tokens parameter, permitting unbounded generation and exposing system to API quota exhaustion and financial denial of wallet.'
                ],
                remediationPrompt: `Specify max_tokens limit (e.g. max_tokens: 1500) and enforce user quota checks in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'AI Engineering Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🤖 HIGH: LLM-01 Missing max_tokens limit in ${file.path}:${lineNum}`);
        }
    }
    // Rule 4003 / LLM-03: Untrusted LLM Output Execution / eval (LLM05)
    if (isCodeFile) {
        const untrustedLlmExecRegex = /(?:eval|child_process\.exec|execSync)\s*\([^)]*(?:completion|aiResponse|llmOutput|assistantMessage)/i;
        if (untrustedLlmExecRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && untrustedLlmExecRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 4003,
                type: 'SECURITY',
                title: 'Untrusted LLM Output Execution (OWASP LLM05 Code Execution)',
                severity: 'CRITICAL',
                category: 'AI Security & Code Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'eval(aiResponse);',
                reproductionSteps: [
                    `Scanned dynamic evaluation statement at ${file.path}:${lineNum}.`,
                    'Detected raw LLM output passed directly into eval or child_process.exec, enabling prompt injection attacks to execute arbitrary code on host server.'
                ],
                remediationPrompt: `Never execute LLM outputs using eval() or shell exec. Use sandboxed environments (isolated-vm or Firecracker microVMs) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'AI Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: LLM-03 Untrusted LLM execution in ${file.path}:${lineNum}`);
        }
    }
    // Rule 4004 / LLM-04: Insecure Vector Search / Cross-Tenant Retrieval
    if (isCodeFile && (cleanContent.includes('vectorStore') || cleanContent.includes('pinecone') || cleanContent.includes('match_documents'))) {
        const vectorQueryRegex = /(?:pinecone.*\.query|supabase\.rpc\(['"]match_documents['"])\s*\(\s*\{(?![^}]*(?:tenant_id|tenantId|user_id|userId))/;
        if (vectorQueryRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && /pinecone.*\.query|match_documents/.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 4004,
                type: 'SECURITY',
                title: 'Insecure Multi-Tenant Vector Search (Cross-Tenant Retrieval Hazard)',
                severity: 'CRITICAL',
                category: 'RAG Architecture & Multi-Tenancy',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await pinecone.query({ vector, topK: 5 });',
                reproductionSteps: [
                    `Scanned vector embedding retrieval at ${file.path}:${lineNum}.`,
                    'Detected vector similarity query executed without mandatory tenant_id or user_id metadata filter, risking cross-tenant data leakage.'
                ],
                remediationPrompt: `Attach mandatory tenant filter to vector queries: filter: { tenant_id: { $eq: tenantId } } in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'AI Engineering Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: LLM-04 Cross-tenant vector search hazard in ${file.path}:${lineNum}`);
        }
    }
    // ==============================================================================
    // FAZ 3 (F-25 & F-37 Remediation): Core OWASP & Next.js/Express Vulnerability Gate
    // Rules SEC-32 to SEC-45 covering eval, command injection, SSRF, path traversal,
    // weak hashes, Math.random, insecure cookies, open redirect, $where, secrets in config.
    // ==============================================================================
    // Rule 32 / SEC-32: Dynamic Code Execution / Remote Code Execution (eval, Function)
    if (isCodeFile && (cleanContent.includes('eval(') || cleanContent.includes('new Function('))) {
        const evalRegex = /\beval\s*\([^)]+\)|\bnew\s+Function\s*\([^)]+\)/;
        if (evalRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && evalRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 32,
                type: 'SECURITY',
                title: 'Dynamic Code Execution (eval / Function Remote Code Execution)',
                severity: 'CRITICAL',
                category: 'Remote Code Execution',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'eval(userInput);',
                reproductionSteps: [
                    `Scanned executable JavaScript at ${file.path}:${lineNum}.`,
                    'Detected dynamic code evaluation using eval() or Function constructor on untrusted inputs, allowing arbitrary server-side code execution.'
                ],
                remediationPrompt: `Eliminate eval() and dynamic Function invocation in ${file.path}:${lineNum}. Use structured JSON parsing or safe domain-specific interpreters.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-32 Dynamic Code Execution detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 33 / SEC-33: Command Injection via Unsanitized Child Process Execution
    if (isCodeFile && (cleanContent.includes('child_process') || cleanContent.includes('execSync(') || cleanContent.includes('exec('))) {
        const cmdInjRegex = /(?:child_process\.(?:exec|execSync|spawn|spawnSync)|\bexec\s*\(|\bexecSync\s*\()\s*(?:`[^`]*\$\{[^}]+\}|['"][^'"]*['"]\s*\+|[a-zA-Z0-9_.]+\s*\+|[^,\)]*\b(?:req\.|params\.|query\.|body\.|userInput|cmd|command|host|input))/;
        if (cmdInjRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && cmdInjRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 33,
                type: 'SECURITY',
                title: 'Command Injection via Unsanitized Child Process Execution',
                severity: 'CRITICAL',
                category: 'Operating System Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'exec(`ping ${ip}`);',
                reproductionSteps: [
                    `Scanned child process execution at ${file.path}:${lineNum}.`,
                    'Detected string concatenation or template interpolation inside system command execution, enabling OS command injection.'
                ],
                remediationPrompt: `Use child_process.execFile or spawn with an explicit arguments array instead of shell execution in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-33 Command Injection risk detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 34 / SEC-34: Server-Side Request Forgery (SSRF) via Unvalidated HTTP Request
    if (isCodeFile && (cleanContent.includes('fetch(') || cleanContent.includes('axios.') || cleanContent.includes('http.get('))) {
        const ssrfRegex = /(?:fetch|axios\.(?:get|post|request)|http\.get|https\.get)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]+|userInput|targetUrl|url)\b/;
        if (ssrfRegex.test(cleanContent) && !cleanContent.includes('validateSafeTargetUrl') && !cleanContent.includes('isAllowedWebhookUrl')) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && ssrfRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 34,
                type: 'SECURITY',
                title: 'Server-Side Request Forgery (SSRF) via Unvalidated Target URL',
                severity: 'CRITICAL',
                category: 'Network & Network Requests',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'await fetch(req.query.url);',
                reproductionSteps: [
                    `Scanned outgoing network request at ${file.path}:${lineNum}.`,
                    'Detected direct fetch/axios request utilizing user-supplied URL parameter without IP/domain allowlist or SSRF validation.'
                ],
                remediationPrompt: `Validate target URL with SSRF guards (block 127.0.0.1, 10.0.0.0/8, 169.254.169.254) before initiating requests in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-34 SSRF vulnerability detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 35 / SEC-35: Path Traversal Vulnerability via User-Controlled File Path
    if (isCodeFile && (cleanContent.includes('fs.') || cleanContent.includes('readFile') || cleanContent.includes('createReadStream'))) {
        const pathTraversalRegex = /(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink))\s*\([^;\n]*(?:path\.join\([^)]*|req\.(?:query|params|body)|\b(?:file|filePath|userInput|targetPath)\b)/;
        if (pathTraversalRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && pathTraversalRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 35,
                type: 'SECURITY',
                title: 'Path Traversal Vulnerability via User-Controlled File Path',
                severity: 'HIGH',
                category: 'File System Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'fs.readFile(path.join(dir, req.params.file));',
                reproductionSteps: [
                    `Scanned file system operation at ${file.path}:${lineNum}.`,
                    'Detected file reading or writing path derived from user input without sanitization against directory traversal sequences (../).'
                ],
                remediationPrompt: `Sanitize path with path.normalize and assert that resolved path starts within expected root directory in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-35 Path Traversal risk detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 36 / SEC-36: Public Exposure of Backend Secrets via NEXT_PUBLIC_ Variables
    const nextPublicSecretRegex = /NEXT_PUBLIC_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|ADMIN_KEY|STRIPE_SECRET|DATABASE_URL|DB_PASS)/i;
    if (nextPublicSecretRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && nextPublicSecretRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 36,
            type: 'SECURITY',
            title: 'Public Exposure of Backend Secret via NEXT_PUBLIC_ Environment Variable',
            severity: 'CRITICAL',
            category: 'Secret Isolation',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || 'NEXT_PUBLIC_SERVICE_ROLE_KEY=...',
            reproductionSteps: [
                `Scanned environment variable declarations at ${file.path}:${lineNum}.`,
                'Detected high-privilege server secret prefixed with NEXT_PUBLIC_, which compiles directly into publicly accessible client JavaScript bundles.'
            ],
            remediationPrompt: `Remove NEXT_PUBLIC_ prefix from backend secrets in ${file.path}:${lineNum}. Access service-role keys exclusively on server-side runtimes.`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 CRITICAL: SEC-36 Client secret leakage via NEXT_PUBLIC_ in ${file.path}:${lineNum}`);
    }
    // Rule 37 / SEC-37: Broken Cryptographic Hash Function (MD5 / SHA-1)
    if (isCodeFile && cleanContent.includes('createHash')) {
        const weakHashRegex = /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|crypto\.createHash\(['"](?:md5|sha1)['"]\)/i;
        if (weakHashRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && weakHashRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 37,
                type: 'SECURITY',
                title: 'Use of Broken Cryptographic Hash Function (MD5 / SHA-1)',
                severity: 'HIGH',
                category: 'Cryptography',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || "crypto.createHash('md5')",
                reproductionSteps: [
                    `Scanned cryptographic operations at ${file.path}:${lineNum}.`,
                    'Detected broken MD5/SHA-1 hashing algorithm susceptible to collision and length extension attacks.'
                ],
                remediationPrompt: `Upgrade hashing algorithms to SHA-256 (crypto.createHash('sha256')) or Argon2/bcrypt for passwords in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-37 Broken cryptographic hash (MD5/SHA1) detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 38 / SEC-38: Insecure Cryptographic Pseudo-Random Generation (Math.random)
    if (isCodeFile && !file.path.includes('live-deployment/bundle-') && cleanContent.includes('Math.random()')) {
        const mathRandomRegex = /(?:token|secret|password|session|nonce|key|auth|salt)\s*[=:]\s*[^;\n]*Math\.random\s*\(\)|Math\.random\s*\(\)\.toString\s*\(\s*(?:36|16)\s*\)/i;
        if (mathRandomRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && mathRandomRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 38,
                type: 'SECURITY',
                title: 'Insecure Pseudo-Random Number Generator Used in Security Context (Math.random)',
                severity: 'HIGH',
                category: 'Cryptography',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'const token = Math.random().toString(36);',
                reproductionSteps: [
                    `Scanned token/secret generation at ${file.path}:${lineNum}.`,
                    'Detected Math.random() used to create tokens or security credentials. Math.random is predictable and not cryptographically secure.'
                ],
                remediationPrompt: `Use crypto.randomUUID() or crypto.randomBytes() for secure tokens in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-38 Insecure Math.random in security context detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 39 / SEC-39: Insecure Unverified JWT Decoding (Missing Signature Verification)
    if (isCodeFile && cleanContent.includes('jwt.decode(')) {
        const jwtDecodeRegex = /\bjwt\.decode\s*\([^)]+\)/;
        if (jwtDecodeRegex.test(cleanContent) && !cleanContent.includes('jwt.verify(')) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && jwtDecodeRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 39,
                type: 'SECURITY',
                title: 'Unverified JWT Token Decoding without Cryptographic Signature Verification',
                severity: 'HIGH',
                category: 'Authentication',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'const user = jwt.decode(token);',
                reproductionSteps: [
                    `Scanned authentication verification at ${file.path}:${lineNum}.`,
                    'Detected jwt.decode() used without jwt.verify(), allowing attackers to forge arbitrary claims with self-signed tokens.'
                ],
                remediationPrompt: `Always verify signatures with jwt.verify(token, secret, { algorithms: ['HS256'] }) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-39 Unverified JWT decode detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 40 / SEC-40: Insecure Cookie Flags (Missing HttpOnly / Missing Secure Flag)
    if (isCodeFile && (cleanContent.includes('cookie(') || cleanContent.includes('cookies().set') || cleanContent.includes('response.cookies.set'))) {
        const insecureCookieRegex = /(?:res\.cookie|cookies\(\)\.set|response\.cookies\.set)\s*\([^)]*\{\s*[^}]*(?:httpOnly\s*:\s*false|secure\s*:\s*false)/i;
        if (insecureCookieRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && insecureCookieRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 40,
                type: 'SECURITY',
                title: 'Insecure Session Cookie Configuration (Missing HttpOnly or Secure Flag)',
                severity: 'HIGH',
                category: 'Session Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || "res.cookie('session', sid, { httpOnly: false });",
                reproductionSteps: [
                    `Scanned HTTP cookie configuration at ${file.path}:${lineNum}.`,
                    'Detected session cookie explicitly setting httpOnly: false or secure: false, exposing authentication sessions to XSS theft and MITM interception.'
                ],
                remediationPrompt: `Set httpOnly: true, secure: true, and sameSite: 'lax' for all authentication cookies in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Backend Team',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-40 Insecure cookie flags detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 41 / SEC-41: Open Redirection Vulnerability via Untrusted URL Target
    if (isCodeFile && cleanContent.includes('redirect(')) {
        const redirectTarget = String.raw`\b(?:next|url|redirectUrl|redirectTo|target|targetUrl|returnTo|returnUrl|callbackUrl)\b`;
        const openRedirectRegex = new RegExp(
            String.raw`(?:res\.redirect|redirect|NextResponse\.redirect)\s*\(\s*(?:req\.(?:query|body|params)|searchParams\.get|` +
            redirectTarget + String.raw`(?:\s+as\s+\w+)?\s*(?:[),]|\|\||\?\?)|` + '`' + String.raw`\$\{\s*` + redirectTarget + String.raw`\s*\}|new\s+URL\(\s*` + redirectTarget + ')',
            'i'
        );
        // Explicit same-origin helpers mark the redirect as validated
        const redirectGuardRegex = /isSafeRedirect|isRelativeUrl|allowedRedirect|isSameOrigin/i;
        if (openRedirectRegex.test(cleanContent) && !redirectGuardRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && openRedirectRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 41,
                type: 'SECURITY',
                title: 'Unvalidated Open Redirection Vulnerability (Open Redirect)',
                severity: 'MEDIUM',
                category: 'Input Validation',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'res.redirect(req.query.next);',
                reproductionSteps: [
                    `Scanned HTTP redirection at ${file.path}:${lineNum}.`,
                    'Detected HTTP redirect directly derived from query parameter without origin validation, enabling phishing redirects.'
                ],
                remediationPrompt: `Validate redirection URLs against a strict whitelist of relative paths (/dashboard) or known trusted domains in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚠️ MEDIUM: SEC-41 Open redirect vulnerability detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 42 / SEC-42: NoSQL Injection via $where Expression Evaluation
    if (isCodeFile && cleanContent.includes('$where')) {
        const nosqlWhereRegex = /\$where\s*:\s*(?:['"`][^'"`]*\$\{[^}]+\}['"`]|req\.|function\s*\(|['"][^'"]*\+)/i;
        if (nosqlWhereRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && nosqlWhereRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 42,
                type: 'SECURITY',
                title: 'NoSQL Injection via Arbitrary JavaScript $where Evaluation',
                severity: 'CRITICAL',
                category: 'Database Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || "$where: 'this.name == ' + req.body.name",
                reproductionSteps: [
                    `Scanned database query at ${file.path}:${lineNum}.`,
                    'Detected MongoDB $where clause evaluating user-controlled JavaScript expression on the database server.'
                ],
                remediationPrompt: `Replace dynamic $where clauses with parameterized MongoDB query operators ($eq, $in) in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Database Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-42 NoSQL $where injection detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 43 / SEC-43: Hardcoded Application Credential / Crypto Secret in Configuration
    const staticSecretRegex = /(?:cookieSecret|sessionSecret|cryptoKey|databasePassword)\s*:\s*['"][a-zA-Z0-9_\-\.\$\!\#\%]{6,}['"]/i;
    if (isCodeFile && staticSecretRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && staticSecretRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawLine = lines[matchLineIdx] || '';
        const maskedSnippet = rawLine.replace(/:\s*['"]([^'"]+)['"]/i, (m, val) => `: '${val.slice(0, 3)}****${val.slice(-2)}'`);
        findings.push({
            id: `real-find-${Date.now()}-${findingCounter.count++}`,
            ruleId: 43,
            type: 'SECURITY',
            title: 'Hardcoded Session or Crypto Secret Key in Application Configuration',
            severity: 'HIGH',
            category: 'Secret Isolation',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: maskedSnippet || lines[matchLineIdx] || "cookieSecret: '****'",
            reproductionSteps: [
                `Scanned application configuration file at ${file.path}:${lineNum}.`,
                'Detected hardcoded cryptographic secret or session encryption key string in source code.'
            ],
            remediationPrompt: `Extract configuration secrets in ${file.path}:${lineNum} to server-only environment variables (process.env.SESSION_SECRET).`,
            status: 'OPEN',
            owner: 'Security Lead',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛑 HIGH: SEC-43 Hardcoded config secret detected in ${file.path}:${lineNum}`);
    }
    // Rule 44 / SEC-44: Insecure Reflected / Wildcard CORS with Credentials Allowed
    if (isCodeFile && (cleanContent.includes('cors(') || cleanContent.includes('Access-Control-Allow-Credentials'))) {
        const corsCredsRegex = /(?:origin:\s*(?:true|['"]\*['"])|Access-Control-Allow-Origin[^;]+(?:\*|true))\s*[^;\}]*(?:credentials:\s*true|Access-Control-Allow-Credentials:\s*true)/i;
        if (corsCredsRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && corsCredsRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 44,
                type: 'SECURITY',
                title: 'Insecure CORS Configuration (Wildcard Origin with Allowed Credentials)',
                severity: 'HIGH',
                category: 'Network & CORS',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'cors({ origin: true, credentials: true });',
                reproductionSteps: [
                    `Scanned CORS header configuration at ${file.path}:${lineNum}.`,
                    'Detected origin: true or wildcard origin combined with credentials: true, allowing external sites to read sensitive authenticated responses.'
                ],
                remediationPrompt: `Restrict CORS origin to an explicit allowlist of authorized production origins in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 HIGH: SEC-44 Insecure CORS credentials configuration detected in ${file.path}:${lineNum}`);
        }
    }
    // Rule 45 / SEC-45: Permissive Database Row Level Security (RLS) Bypass Policy
    if (cleanContent.includes('CREATE POLICY') && (cleanContent.includes('USING (true)') || cleanContent.includes('WITH CHECK (true)'))) {
        const rlsBypassRegex = /CREATE\s+POLICY\s+[^;]+(?:USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\))/i;
        if (rlsBypassRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('--') && rlsBypassRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `real-find-${Date.now()}-${findingCounter.count++}`,
                ruleId: 45,
                type: 'SECURITY',
                title: 'Permissive Database Row Level Security (RLS) Bypass Policy',
                severity: 'CRITICAL',
                category: 'Database Security',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'CREATE POLICY bypass ON table FOR ALL USING (true);',
                reproductionSteps: [
                    `Scanned database migration or schema SQL at ${file.path}:${lineNum}.`,
                    'Detected permissive RLS policy allowing universal access to table records.'
                ],
                remediationPrompt: `Scope RLS policy with explicit user ownership checks: auth.uid() = user_id in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Database Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🛑 CRITICAL: SEC-45 Permissive RLS policy bypass detected in ${file.path}:${lineNum}`);
        }
    }
    return { findings, logs };
}
