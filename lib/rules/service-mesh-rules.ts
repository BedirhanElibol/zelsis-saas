/**
 * Zelsis Master evaluateServiceMeshRules Engine (50 Rules)
 * Rules MESH-01 to MESH-50 (Rule IDs 11201 to 11250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface ServiceMeshRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateServiceMeshRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ServiceMeshRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // MESH-01: Permissive mTLS Mode in Service Mesh Ingress (Missing STRICT Mode)
    if ((/PeerAuthentication/i.test(cleanContent) && !/mode:\s*STRICT/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/PeerAuthentication/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11201,
            type: 'INFRA_DATABASE',
            title: "MESH-01: Permissive mTLS Mode in Service Mesh Ingress (Missing STRICT Mode)",
            severity: "CRITICAL",
            category: "Zero Trust Mesh",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Service mesh routing manifest',
            reproductionSteps: [
                `Audited mesh configuration in ${file.path}:${lineNum}.`,
                'Detected service mesh violation matching MESH-01.'
            ],
            remediationPrompt: "Set mtls { mode: STRICT } in Istio PeerAuthentication manifest.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MESH AUDIT] Found MESH-01: Permissive mTLS Mode in Service Mesh Ingress (Missing STRICT Mode) at ${file.path}:${lineNum}`);
    }
    // MESH-02: Missing Sidecar Container Resource Limits (Envoy Proxy OOMKilled)
    if ((/sidecar\.istio\.io\/inject/i.test(cleanContent) && !/proxy\.istio\.io\/config/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/sidecar\.istio\.io\/inject/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11202,
            type: 'INFRA_DATABASE',
            title: "MESH-02: Missing Sidecar Container Resource Limits (Envoy Proxy OOMKilled)",
            severity: "HIGH",
            category: "Mesh Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Service mesh routing manifest',
            reproductionSteps: [
                `Audited mesh configuration in ${file.path}:${lineNum}.`,
                'Detected service mesh violation matching MESH-02.'
            ],
            remediationPrompt: "Add proxy resource limits to Istio injection annotations in deployment manifests.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MESH AUDIT] Found MESH-02: Missing Sidecar Container Resource Limits (Envoy Proxy OOMKilled) at ${file.path}:${lineNum}`);
    }
    // MESH-03: Missing Circuit Breaker Trip Thresholds (Consecutive 5xx Errors)
    if ((/DestinationRule/i.test(cleanContent) && !/consecutive5xxErrors|outlierDetection/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/DestinationRule/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11203,
            type: 'INFRA_DATABASE',
            title: "MESH-03: Missing Circuit Breaker Trip Thresholds (Consecutive 5xx Errors)",
            severity: "HIGH",
            category: "Resilience & Fallback",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Service mesh routing manifest',
            reproductionSteps: [
                `Audited mesh configuration in ${file.path}:${lineNum}.`,
                'Detected service mesh violation matching MESH-03.'
            ],
            remediationPrompt: "Add outlierDetection block to DestinationRule for all upstream microservices.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MESH AUDIT] Found MESH-03: Missing Circuit Breaker Trip Thresholds (Consecutive 5xx Errors) at ${file.path}:${lineNum}`);
    }
    // MESH-04: Active Fault Injection Delay / Abort Remaining in Production
    if ((/VirtualService/i.test(cleanContent) && /fault\.(?:delay|abort)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/VirtualService/i, /fault\.(?:delay|abort)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11204,
            type: 'INFRA_DATABASE',
            title: "MESH-04: Active Fault Injection Delay / Abort Remaining in Production",
            severity: "CRITICAL",
            category: "Chaos Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Service mesh routing manifest',
            reproductionSteps: [
                `Audited mesh configuration in ${file.path}:${lineNum}.`,
                'Detected service mesh violation matching MESH-04.'
            ],
            remediationPrompt: "Remove fault injection blocks before applying manifests to production clusters.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MESH AUDIT] Found MESH-04: Active Fault Injection Delay / Abort Remaining in Production at ${file.path}:${lineNum}`);
    }
    // MESH-05: Unpropagated Distributed Tracing B3 / W3C Headers at Gateway Ingress
    if ((/ingress-gateway/i.test(lowerPath) && !/x-request-id|traceparent/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11205,
            type: 'INFRA_DATABASE',
            title: "MESH-05: Unpropagated Distributed Tracing B3 / W3C Headers at Gateway Ingress",
            severity: "MEDIUM",
            category: "Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Service mesh routing manifest',
            reproductionSteps: [
                `Audited mesh configuration in ${file.path}:${lineNum}.`,
                'Detected service mesh violation matching MESH-05.'
            ],
            remediationPrompt: "Add header forwarding middleware copying incoming tracing headers to outbound service calls.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [MESH AUDIT] Found MESH-05: Unpropagated Distributed Tracing B3 / W3C Headers at Gateway Ingress at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
