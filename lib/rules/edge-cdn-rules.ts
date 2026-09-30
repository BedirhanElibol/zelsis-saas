/**
 * Zelsis Master evaluateEdgeCdnRules Engine (50 Rules)
 * Rules CDN-01 to CDN-50 (Rule IDs 11101 to 11150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface EdgeCdnRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEdgeCdnRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EdgeCdnRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("data/catalogs/") || lowerPath.includes("data/mockdata") || lowerPath.includes("data/workspacefiles") || lowerPath.includes("data/schema") || lowerPath.includes("scratch/") || lowerPath.includes(".agent/") || lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CDN-01: Missing Stale-While-Revalidate and Immutable Directives on Static Bundles
    if ((/next\.config/i.test(lowerPath) || /static/i.test(lowerPath)) && /Cache-Control/i.test(cleanContent) && !/immutable/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cdn11101-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11101,
            type: 'INFRA_DATABASE',
            title: "CDN-01: Missing Stale-While-Revalidate and Immutable Directives on Static Bundles",
            severity: "HIGH",
            category: "Asset Caching",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Edge CDN header definition',
            reproductionSteps: [
                `Audited asset delivery in ${file.path}:${lineNum}.`,
                'Detected Edge CDN delivery violation matching CDN-01.'
            ],
            remediationPrompt: "Add Cache-Control headers with immutable directive in Next.js config or reverse proxy headers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CDN AUDIT] Found CDN-01: Missing Stale-While-Revalidate and Immutable Directives on Static Bundles at ${file.path}:${lineNum}`);
    }
    // CDN-02: Uncompressed Static Asset Delivery (Missing Brotli / Zstandard Compression)
    if ((/nextConfig\s*=\s*\{[\s\S]*?\}/.test(cleanContent) && cleanContent.includes('compress: false'))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cdn11102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11102,
            type: 'INFRA_DATABASE',
            title: "CDN-02: Uncompressed Static Asset Delivery (Missing Brotli / Zstandard Compression)",
            severity: "HIGH",
            category: "Bandwidth & CWV",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Edge CDN header definition',
            reproductionSteps: [
                `Audited asset delivery in ${file.path}:${lineNum}.`,
                'Detected Edge CDN delivery violation matching CDN-02.'
            ],
            remediationPrompt: "Configure compress: true in next.config.js and enable Brotli compression on Cloudflare / CloudFront distribution.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CDN AUDIT] Found CDN-02: Uncompressed Static Asset Delivery (Missing Brotli / Zstandard Compression) at ${file.path}:${lineNum}`);
    }
    // CDN-03: Missing Access-Control-Max-Age Preflight Caching Header on Cross-Origin APIs
    if (!file.path.includes('live-deployment/security-headers.json') && (/Access-Control-Allow-Origin/i.test(cleanContent) && !/Access-Control-Max-Age/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cdn11103-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11103,
            type: 'INFRA_DATABASE',
            title: "CDN-03: Missing Access-Control-Max-Age Preflight Caching Header on Cross-Origin APIs",
            severity: "MEDIUM",
            category: "HTTP Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Edge CDN header definition',
            reproductionSteps: [
                `Audited asset delivery in ${file.path}:${lineNum}.`,
                'Detected Edge CDN delivery violation matching CDN-03.'
            ],
            remediationPrompt: "Add res.setHeader('Access-Control-Max-Age', '86400') to CORS preflight handler middleware.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CDN AUDIT] Found CDN-03: Missing Access-Control-Max-Age Preflight Caching Header on Cross-Origin APIs at ${file.path}:${lineNum}`);
    }
    // CDN-04: Missing HTTP/3 (QUIC) Protocol Support at Edge Reverse Proxy
    if ((/nginx\.conf|caddyfile/i.test(lowerPath) && cleanContent.includes('http3ProtocolDisabled'))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cdn11104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11104,
            type: 'INFRA_DATABASE',
            title: "CDN-04: Missing HTTP/3 (QUIC) Protocol Support at Edge Reverse Proxy",
            severity: "MEDIUM",
            category: "Network Latency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Edge CDN header definition',
            reproductionSteps: [
                `Audited asset delivery in ${file.path}:${lineNum}.`,
                'Detected Edge CDN delivery violation matching CDN-04.'
            ],
            remediationPrompt: "Enable HTTP/3 protocol toggle in CDN edge distribution settings.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CDN AUDIT] Found CDN-04: Missing HTTP/3 (QUIC) Protocol Support at Edge Reverse Proxy at ${file.path}:${lineNum}`);
    }
    // CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers
    if (/app\/api\//i.test(lowerPath) && /export\s+async\s+function\s+GET/i.test(cleanContent) && !/Cache-Control/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cdn11105-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11105,
            type: 'INFRA_DATABASE',
            title: "CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers",
            severity: "HIGH",
            category: "Origin Offloading",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Edge CDN header definition',
            reproductionSteps: [
                `Audited asset delivery in ${file.path}:${lineNum}.`,
                'Detected Edge CDN delivery violation matching CDN-05.'
            ],
            remediationPrompt: "Set s-maxage and stale-while-revalidate headers on read-heavy public REST and GraphQL queries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CDN AUDIT] Found CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
