/**
 * Zelsis Master evaluateK8sHardeningRules Engine (50 Rules)
 * Rules K8S-01 to K8S-50 (Rule IDs 8901 to 8950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
import { capabilityAdds, yamlLine } from './iac-rules';
export interface K8sHardeningRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateK8sHardeningRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): K8sHardeningRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-k8s paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isK8s = (lowerPath.endsWith(".yaml") || lowerPath.endsWith(".yml")) &&
        (cleanContent.includes("apiVersion:") || cleanContent.includes("kind: Pod") || cleanContent.includes("kind: Deployment") || lowerPath.includes("k8s/") || lowerPath.includes("helm/"));
    if (!isK8s)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // K8S-01: Privileged Container Execution (privileged: true)
    const k8s01Line = yamlLine(lines, /^\s*privileged\s*:\s*true\b/);
    if (k8s01Line !== -1) {
        const matchLineIdx = k8s01Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8901,
            type: 'INFRA_DATABASE',
            title: "K8S-01: Privileged Container Execution (privileged: true)",
            severity: "CRITICAL",
            category: "Container Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-01.'
            ],
            remediationPrompt: "Set securityContext.privileged: false in all container specifications.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-01: Privileged Container Execution (privileged: true) at ${file.path}:${lineNum}`);
    }
    // K8S-02: Container Allowed to Run as Root User
    // Only an explicit `runAsUser: 0` (not every Deployment)
    const k8s02Line = yamlLine(lines, /^\s*runAsUser\s*:\s*0\s*(?:#.*)?$/);
    if (k8s02Line !== -1) {
        const matchLineIdx = k8s02Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8902,
            type: 'INFRA_DATABASE',
            title: "K8S-02: Container Allowed to Run as Root User",
            severity: "MEDIUM",
            category: "User Privilege",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-02.'
            ],
            remediationPrompt: "Configure securityContext.runAsNonRoot: true and securityContext.runAsUser: 10001.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-02: Container Allowed to Run as Root User at ${file.path}:${lineNum}`);
    }
    // K8S-04: Dangerous Host Path Volume Mount (/ or /etc or /var/run)
    // The `path:` of a hostPath volume (next lines, or inline `hostPath: { path: / }`) is the host root,
    // /etc, /root, the runtime dirs or a container runtime socket; e.g. /var/log/app is fine
    const dangerousHostPath = /^\/(?:|etc|root|var\/run|run|var\/lib\/kubelet|(?:var\/)?run\/(?:docker|containerd\/containerd|crio\/crio)\.sock)\/?$/;
    const k8s04Line = (() => {
        for (let i = 0; i < lines.length; i++) {
            if (lines[i].trim().startsWith('#') || !/\bhostPath\s*:/.test(lines[i])) continue;
            for (let j = i; j < Math.min(lines.length, i + 4); j++) {
                const p = /(?:^\s*|\{\s*)path\s*:\s*['"]?([^'"\s,}#]+)/.exec(lines[j]);
                if (p) {
                    if (dangerousHostPath.test(p[1])) return j;
                    break;
                }
            }
        }
        return -1;
    })();
    if (k8s04Line !== -1) {
        const matchLineIdx = k8s04Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8904,
            type: 'INFRA_DATABASE',
            title: "K8S-04: Dangerous Host Path Volume Mount (/ or /etc or /var/run)",
            severity: "CRITICAL",
            category: "Host Escape",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-04.'
            ],
            remediationPrompt: "Remove hostPath volume mounts and replace with persistent volume claims or Kubernetes secrets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-04: Dangerous Host Path Volume Mount (/ or /etc or /var/run) at ${file.path}:${lineNum}`);
    }
    // K8S-05: AutomountServiceAccountToken Enabled by Default
    const k8s05Line = yamlLine(lines, /^\s*automountServiceAccountToken\s*:\s*true\b/);
    if (k8s05Line !== -1) {
        const matchLineIdx = k8s05Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8905,
            type: 'INFRA_DATABASE',
            title: "K8S-05: AutomountServiceAccountToken Enabled by Default",
            severity: "MEDIUM",
            category: "Credential Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-05.'
            ],
            remediationPrompt: "Add automountServiceAccountToken: false to pod spec.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-05: AutomountServiceAccountToken Enabled by Default at ${file.path}:${lineNum}`);
    }
    // K8S-08: Writable Root Filesystem (readOnlyRootFilesystem: false)
    if (/readOnlyRootFilesystem\s*:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/readOnlyRootFilesystem\s*:\s*false/i], l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8908-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8908,
            type: 'INFRA_DATABASE',
            title: "K8S-08: Writable Root Filesystem (readOnlyRootFilesystem: false)",
            severity: 'MEDIUM',
            category: "Runtime Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-08.'
            ],
            remediationPrompt: "Configure securityContext.readOnlyRootFilesystem: true and mount emptyDir on /tmp.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-08: Writable Root Filesystem (readOnlyRootFilesystem: false) at ${file.path}:${lineNum}`);
    }
    // K8S-09: Container Insecure Capability Allocation (ALL or CAP_SYS_ADMIN)
    // capabilities.add containing ALL or SYS_ADMIN (flow or block list); `drop: [ALL]` is the hardening idiom
    const k8s09Line = capabilityAdds(lines).find((a) => a.caps.some((c) => c === 'ALL' || c === 'SYS_ADMIN' || c === 'CAP_SYS_ADMIN'))?.line ?? -1;
    if (k8s09Line !== -1) {
        const matchLineIdx = k8s09Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `k8s8909-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8909,
            type: 'INFRA_DATABASE',
            title: "K8S-09: Container Insecure Capability Allocation (ALL or CAP_SYS_ADMIN)",
            severity: "CRITICAL",
            category: "Linux Capabilities",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Kubernetes manifest item',
            reproductionSteps: [
                `Audited Kubernetes manifest in ${file.path}:${lineNum}.`,
                'Detected configuration violation matching K8S-09.'
            ],
            remediationPrompt: "Add capabilities.drop: ['ALL'] in container securityContext.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [K8S AUDIT] Found K8S-09: Container Insecure Capability Allocation (ALL or CAP_SYS_ADMIN) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
