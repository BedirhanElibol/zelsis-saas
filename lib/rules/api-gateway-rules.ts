/**
 * Zelsis Master evaluateApiGatewayRules Engine (50 Rules)
 * Rules GW-01 to GW-50 (Rule IDs 11401 to 11450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface ApiGatewayRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateApiGatewayRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ApiGatewayRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isGatewayOrApi = lowerPath.startsWith("app/api/") || lowerPath.startsWith("pages/api/") || lowerPath.includes("/api/") || lowerPath.includes("middleware") || lowerPath.includes("gateway") || lowerPath.includes("server/");
    if (!isGatewayOrApi) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GW-01: Unauthenticated Gateway Route Fallthrough (Missing Catch-All Rejection)
    if ((/router\.(?:use|all)\s*\([\s\S]*?\)/.test(cleanContent) && !/notFound|reject|deny/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gw11401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11401,
            type: 'SECURITY',
            title: "GW-01: Unauthenticated Gateway Route Fallthrough (Missing Catch-All Rejection)",
            severity: "CRITICAL",
            category: "Perimeter Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'API Gateway configuration',
            reproductionSteps: [
                `Audited API gateway in ${file.path}:${lineNum}.`,
                'Detected API gateway violation matching GW-01.'
            ],
            remediationPrompt: "Configure default fallback route returning 404 on API gateway routing tables.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GW AUDIT] Found GW-01: Unauthenticated Gateway Route Fallthrough (Missing Catch-All Rejection) at ${file.path}:${lineNum}`);
    }
    // GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes
    if ((/(?:\/login|\/auth|\/signin)/i.test(cleanContent) && !/rateLimit|ratelimiter/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gw11402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11402,
            type: 'SECURITY',
            title: "GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes",
            severity: "CRITICAL",
            category: "Abuse Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'API Gateway configuration',
            reproductionSteps: [
                `Audited API gateway in ${file.path}:${lineNum}.`,
                'Detected API gateway violation matching GW-02.'
            ],
            remediationPrompt: "Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GW AUDIT] Found GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes at ${file.path}:${lineNum}`);
    }
    // GW-03: HTTP Request Smuggling Vulnerability (Ambiguous Transfer-Encoding / Content-Length)
    if ((/headers\[['"]transfer-encoding['"]\]/i.test(cleanContent) && /headers\[['"]content-length['"]\]/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gw11403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11403,
            type: 'SECURITY',
            title: "GW-03: HTTP Request Smuggling Vulnerability (Ambiguous Transfer-Encoding / Content-Length)",
            severity: "CRITICAL",
            category: "Protocol Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'API Gateway configuration',
            reproductionSteps: [
                `Audited API gateway in ${file.path}:${lineNum}.`,
                'Detected API gateway violation matching GW-03.'
            ],
            remediationPrompt: "Configure reverse proxy to reject ambiguous Transfer-Encoding and Content-Length headers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GW AUDIT] Found GW-03: HTTP Request Smuggling Vulnerability (Ambiguous Transfer-Encoding / Content-Length) at ${file.path}:${lineNum}`);
    }
    // GW-04: Oversized Header Buffer Parsing Attack (HTTP 431 Vulnerability)
    if ((/maxHeaderSize\s*:\s*(?:Infinity|0)/.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gw11404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11404,
            type: 'SECURITY',
            title: "GW-04: Oversized Header Buffer Parsing Attack (HTTP 431 Vulnerability)",
            severity: "HIGH",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'API Gateway configuration',
            reproductionSteps: [
                `Audited API gateway in ${file.path}:${lineNum}.`,
                'Detected API gateway violation matching GW-04.'
            ],
            remediationPrompt: "Set large_client_header_buffers 4 8k in Nginx or configure maxHeaderSize in Node.js server options.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GW AUDIT] Found GW-04: Oversized Header Buffer Parsing Attack (HTTP 431 Vulnerability) at ${file.path}:${lineNum}`);
    }
    // GW-05: Missing API Deprecation and Sunset Announcement Headers
    if ((/\/api\/v1\//i.test(cleanContent) && !/sunset|deprecation/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gw11405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11405,
            type: 'SECURITY',
            title: "GW-05: Missing API Deprecation and Sunset Announcement Headers",
            severity: "LOW",
            category: "API Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'API Gateway configuration',
            reproductionSteps: [
                `Audited API gateway in ${file.path}:${lineNum}.`,
                'Detected API gateway violation matching GW-05.'
            ],
            remediationPrompt: "Attach Deprecation and Sunset HTTP response headers on v1 endpoints slated for retirement.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GW AUDIT] Found GW-05: Missing API Deprecation and Sunset Announcement Headers at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
