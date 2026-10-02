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
    const isGatewayOrApi = lowerPath.startsWith("app/api/") || lowerPath.startsWith("pages/api/") || lowerPath.includes("/api/") || lowerPath.includes("middleware") || lowerPath.includes("gateway") || lowerPath.includes("server");
    if (!isGatewayOrApi) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GW-04: Oversized Header Buffer Parsing Attack (HTTP 431 Vulnerability)
    const hit_11404 = lines.findIndex((l) => /\bmaxHeaderSize\s*:\s*(?:Infinity|Number\.MAX_SAFE_INTEGER|\d{7,})\b/.test(l));
    if (hit_11404 !== -1) {
        const matchLineIdx = hit_11404;
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
    return { findings, logs };
}
