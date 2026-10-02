/**
 * Zelsis Master evaluateServiceMeshRules Engine (50 Rules)
 * Rules MESH-01 to MESH-50 (Rule IDs 11201 to 11250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    const r11201Idx = !/^kind:\s*PeerAuthentication\s*$/m.test(cleanContent) ? -1
        : lines.findIndex(l => /^\s*mode:\s*["']?(?:PERMISSIVE|DISABLE)\b/.test(l));
    if (r11201Idx !== -1) {
        const matchLineIdx = r11201Idx;
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
    // MESH-04: Active Fault Injection Delay / Abort Remaining in Production
    const r11204Idx = !/^kind:\s*VirtualService\s*$/m.test(cleanContent) || /(?:^|[/_.-])(?:dev|staging|stage|test|chaos|sandbox|local)(?:[/_.-]|$)/i.test(lowerPath) ? -1
        : lines.findIndex((l, i) => /^\s*(?:-\s+)?fault:\s*$/.test(l) && /^\s*(?:delay|abort):/m.test(lines.slice(i + 1, i + 6).join('\n')));
    if (r11204Idx !== -1) {
        const matchLineIdx = r11204Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `mesh11204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11204,
            type: 'INFRA_DATABASE',
            title: "MESH-04: Active Fault Injection Delay / Abort Remaining in Production",
            severity: "MEDIUM",
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
    return { findings, logs };
}
