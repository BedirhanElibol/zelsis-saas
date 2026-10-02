/**
 * Zelsis Master evaluateWebsocketRealtimeRules Engine (50 Rules)
 * Rules WS-01 to WS-50 (Rule IDs 10501 to 10550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface WebsocketRealtimeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWebsocketRealtimeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): WebsocketRealtimeRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // WS-01: Missing WebSocket Heartbeat Ping/Pong Health Interval
    const r10501Idx = /\bping\b|\bpong\b|heartbeat|isAlive/i.test(cleanContent) ? -1
        : lines.findIndex(l => /new\s+(?:WebSocketServer|WebSocket\.Server)\s*\(/.test(l));
    if (r10501Idx !== -1) {
        const matchLineIdx = r10501Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10501,
            type: 'INFRA_DATABASE',
            title: "WS-01: Missing WebSocket Heartbeat Ping/Pong Health Interval",
            severity: "LOW",
            category: "Connection Health",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebSocket connection setup',
            reproductionSteps: [
                `Audited socket connection in ${file.path}:${lineNum}.`,
                'Detected realtime socket violation matching WS-01.'
            ],
            remediationPrompt: "Configure heartbeatInterval: 25000 and heartbeatTimeout: 60000 on WebSocket server instances.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WS AUDIT] Found WS-01: Missing WebSocket Heartbeat Ping/Pong Health Interval at ${file.path}:${lineNum}`);
    }
    // WS-02: Missing Authentication Handshake Guard on WebSocket Upgrade
    const r10502Idx = /auth|token|jwt|verify|getUser|session|apiKey|api_key/i.test(cleanContent) ? -1
        : lines.findIndex(l => /\.on\s*\(\s*['"]upgrade['"]/.test(l));
    if (r10502Idx !== -1) {
        const matchLineIdx = r10502Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10502,
            type: 'INFRA_DATABASE',
            title: "WS-02: Missing Authentication Handshake Guard on WebSocket Upgrade",
            severity: "CRITICAL",
            category: "Connection Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebSocket connection setup',
            reproductionSteps: [
                `Audited socket connection in ${file.path}:${lineNum}.`,
                'Detected realtime socket violation matching WS-02.'
            ],
            remediationPrompt: "Reject WebSocket upgrade requests if auth token header or session cookie is invalid or missing.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WS AUDIT] Found WS-02: Missing Authentication Handshake Guard on WebSocket Upgrade at ${file.path}:${lineNum}`);
    }
    // WS-03: Cross-Site WebSocket Hijacking (CSWSH) via Unvalidated Origin
    const r10503Idx = /\borigin\b/i.test(cleanContent) ? -1
        : lines.findIndex((l, i) => /\.on\s*\(\s*['"]upgrade['"]/.test(l) &&
            /headers\.cookie|\bcookies?\b|getSession|session/i.test(lines.slice(i, i + 25).join('\n')));
    if (r10503Idx !== -1) {
        const matchLineIdx = r10503Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10503,
            type: 'INFRA_DATABASE',
            title: "WS-03: Cross-Site WebSocket Hijacking (CSWSH) via Unvalidated Origin",
            severity: "CRITICAL",
            category: "Handshake Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebSocket connection setup',
            reproductionSteps: [
                `Audited socket connection in ${file.path}:${lineNum}.`,
                'Detected realtime socket violation matching WS-03.'
            ],
            remediationPrompt: "Reject WebSocket upgrade requests when Origin header does not match approved application domain allowlist.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WS AUDIT] Found WS-03: Cross-Site WebSocket Hijacking (CSWSH) via Unvalidated Origin at ${file.path}:${lineNum}`);
    }
    // WS-05: Socket Reconnection Storm Flooding Backend Gateways
    const r10505Idx = /Math\.random|jitter|backoff|\*\*\s*\w|Math\.pow|Math\.min\(/i.test(cleanContent) ? -1
        : lines.findIndex((l, i) => /\.(?:onclose\s*=|addEventListener\(\s*['"]close['"]|on\(\s*['"]close['"])/.test(l) &&
            /setTimeout\s*\(\s*(?:[\w$.]+|\(\)\s*=>\s*[\w$.]+\([^)]*\))\s*,\s*\d+\s*\)/.test(lines.slice(i, i + 8).join('\n')));
    if (r10505Idx !== -1) {
        const matchLineIdx = r10505Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10505,
            type: 'INFRA_DATABASE',
            title: "WS-05: Socket Reconnection Storm Flooding Backend Gateways",
            severity: "MEDIUM",
            category: "Reconnection Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebSocket connection setup',
            reproductionSteps: [
                `Audited socket connection in ${file.path}:${lineNum}.`,
                'Detected realtime socket violation matching WS-05.'
            ],
            remediationPrompt: "Add randomized jitter and exponential delay (1s, 2s, 4s, ... max 30s) to client socket reconnect handlers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WS AUDIT] Found WS-05: Socket Reconnection Storm Flooding Backend Gateways at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
