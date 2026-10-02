/**
 * Zelsis Master evaluateContainerSecurityRules Engine (50 Rules)
 * Rules CONTAINER-01 to CONTAINER-50 (Rule IDs 12201 to 12250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
import { isYamlPath, yamlLine } from './iac-rules';
export interface ContainerSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateContainerSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ContainerSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") || lowerPath.endsWith(".tsx") || lowerPath.endsWith(".jsx")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CONTAINER-01: Privileged Container Execution with Full Host Access
    const isYaml = isYamlPath(lowerPath);
    const c01Line = isYaml && /securityContext\s*:/.test(cleanContent) ? yamlLine(lines, /^\s*privileged\s*:\s*true\b/) : -1;
    if (c01Line !== -1) {
        const matchLineIdx = c01Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `container12201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12201,
            type: 'INFRA_DATABASE',
            title: "CONTAINER-01: Privileged Container Execution with Full Host Access",
            severity: "CRITICAL",
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Container Security configuration',
            reproductionSteps: [
                `Audited Container Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CONTAINER-01.'
            ],
            remediationPrompt: "Disable privileged execution mode (set privileged: false) in container securityContext.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-01: Privileged Container Execution with Full Host Access at ${file.path}:${lineNum}`);
    }
    // CONTAINER-02: Root User Execution in Container Runtime Image
    // The last USER instruction of the final build stage is root/0 (switching to root temporarily
    // for package installs and back to an unprivileged user is fine)
    const c02Line = (() => {
        if (!/(?:^|\/)(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/.test(lowerPath)) return -1;
        let lastUser = -1;
        lines.forEach((l, i) => {
            if (/^\s*FROM\s/i.test(l)) lastUser = -1;
            else if (/^\s*USER\s+\S/i.test(l)) lastUser = i;
        });
        return lastUser !== -1 && /^\s*USER\s+(?:root|0)(?::(?:root|0))?\s*$/i.test(lines[lastUser]) ? lastUser : -1;
    })();
    if (c02Line !== -1) {
        const matchLineIdx = c02Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `container12202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12202,
            type: 'INFRA_DATABASE',
            title: "CONTAINER-02: Root User Execution in Container Runtime Image",
            severity: "HIGH",
            category: "Privilege Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Container Security configuration',
            reproductionSteps: [
                `Audited Container Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CONTAINER-02.'
            ],
            remediationPrompt: "Specify non-root USER directive in Dockerfile and configure runAsNonRoot: true.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-02: Root User Execution in Container Runtime Image at ${file.path}:${lineNum}`);
    }
    // CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers
    if ((/securityContext/i.test(cleanContent) && /readOnlyRootFilesystem:\s*false/i.test(cleanContent) && !/readOnlyRootFilesystem:\s*true/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/securityContext/i, /readOnlyRootFilesystem:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `container12203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12203,
            type: 'INFRA_DATABASE',
            title: "CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers",
            severity: "HIGH",
            category: "Filesystem Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Container Security configuration',
            reproductionSteps: [
                `Audited Container Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CONTAINER-03.'
            ],
            remediationPrompt: "Mount container root filesystem with readOnlyRootFilesystem: true and use tmpfs for scratch paths.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers at ${file.path}:${lineNum}`);
    }
    // CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing
    const c04Line = isYaml ? yamlLine(lines, /^\s*hostNetwork\s*:\s*true\b/) : -1;
    if (c04Line !== -1) {
        const matchLineIdx = c04Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `container12204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12204,
            type: 'INFRA_DATABASE',
            title: "CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing",
            severity: "CRITICAL",
            category: "Network Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Container Security configuration',
            reproductionSteps: [
                `Audited Container Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CONTAINER-04.'
            ],
            remediationPrompt: "Remove hostNetwork: true from pod specs to preserve virtual network namespace isolation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing at ${file.path}:${lineNum}`);
    }
    // CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container
    if ((/\/var\/run\/docker\.sock/i.test(cleanContent) && !/isolatedDockerDaemon/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/\/var\/run\/docker\.sock/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `container12205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12205,
            type: 'INFRA_DATABASE',
            title: "CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container",
            severity: "CRITICAL",
            category: "Daemon Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Container Security configuration',
            reproductionSteps: [
                `Audited Container Security configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching CONTAINER-05.'
            ],
            remediationPrompt: "Remove /var/run/docker.sock volume mounts from application containers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
