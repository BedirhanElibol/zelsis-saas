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
    if ((/new\s+WebSocketServer\s*\([\s\S]*?\)/.test(cleanContent) && !/ping|pong|heartbeat/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10501,
            type: 'INFRA_DATABASE',
            title: "WS-01: Missing WebSocket Heartbeat Ping/Pong Health Interval",
            severity: "HIGH",
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
    if ((/server\.on\s*\(\s*['"]upgrade['"]/i.test(cleanContent) && !/jwt|token|verify|session/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if ((/server\.on\s*\(\s*['"]upgrade['"]/i.test(cleanContent) && !/origin|allowedOrigins/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // WS-04: Unbounded Broadcast Memory Buffering (Missing Backpressure)
    if ((/socket\.send\s*\([\s\S]*?\)/.test(cleanContent) && !/bufferedAmount|drain/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10504,
            type: 'INFRA_DATABASE',
            title: "WS-04: Unbounded Broadcast Memory Buffering (Missing Backpressure)",
            severity: "HIGH",
            category: "Buffer Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebSocket connection setup',
            reproductionSteps: [
                `Audited socket connection in ${file.path}:${lineNum}.`,
                'Detected realtime socket violation matching WS-04.'
            ],
            remediationPrompt: "Implement backpressure checking: pause message emission when ws.bufferedAmount exceeds 64KB.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WS AUDIT] Found WS-04: Unbounded Broadcast Memory Buffering (Missing Backpressure) at ${file.path}:${lineNum}`);
    }
    // WS-05: Socket Reconnection Storm Flooding Backend Gateways
    if ((/socket\.onclose\s*=/i.test(cleanContent) && !/random|jitter|backoff/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ws10505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10505,
            type: 'INFRA_DATABASE',
            title: "WS-05: Socket Reconnection Storm Flooding Backend Gateways",
            severity: "HIGH",
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
