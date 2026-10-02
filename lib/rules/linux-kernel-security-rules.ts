/**
 * Zelsis Master evaluateLinuxKernelSecurityRules Engine
 * KERN-SEC-01 (15701), KERN-SEC-02 (15702), KERN-SEC-04 (15704), KERN-SEC-05 (15705): each fires on an
 * explicit setting that disables the protection and reports that setting's line.
 * Removed as unsound (id never reused): 15703 user namespaces (fired on any sysctl file not setting
 * user.max_user_namespaces=0, a hardening preference that breaks rootless containers).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface LinuxKernelSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
export function evaluateLinuxKernelSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): LinuxKernelSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip non-container and non-infrastructure files
    if (
        lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") ||
        (!/\.(ya?ml|dockerfile)$/i.test(file.path) && !/docker|k8s|pod_spec|container_security/i.test(lowerPath))
    ) {
        return { findings, logs };
    }
    // YAML / shell `#` comment lines are not stripped upstream: blank them (line count preserved).
    const code = cleanContent.split('\n').map(l => (/^\s*#/.test(l) ? '' : l)).join('\n');
    const ts = new Date().toLocaleTimeString();
    // KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads
    const privilegeGrant = /privileged\s*:\s*true|--privileged|--cap-add[=\s]+(?:CAP_)?(?:SYS_ADMIN|ALL)|(?:cap_add|add)\s*:[^\n]*(?:SYS_ADMIN|ALL)|(?:cap_add|add)\s*:\s*\n(?:\s*-\s*\S+\s*\n)*?\s*-\s*["']?(?:CAP_)?(?:SYS_ADMIN|ALL)\b/i.exec(code);
    if (privilegeGrant && !/drop:\s*\[.*CAP_SYS_ADMIN.*\]/i.test(code)) {
        // Multi-line `add:` lists: point at the SYS_ADMIN / ALL entry, not the `add:` key.
        const entry = privilegeGrant[0].search(/(?:CAP_)?(?:SYS_ADMIN|ALL)\b|privileged/i);
        const matchLineIdx = lineAt(code, privilegeGrant.index + Math.max(0, entry));
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `kernsec15701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15701,
            type: 'SECURITY',
            title: "KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads",
            severity: "CRITICAL",
            category: "Capabilities Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'The container runs privileged or is granted CAP_SYS_ADMIN / ALL capabilities, which allows escaping to the host.'
            ],
            remediationPrompt: "Drop all default Linux capabilities and retain strictly the minimal required set (e.g. drop CAP_SYS_ADMIN, CAP_NET_ADMIN).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-02: seccomp explicitly switched off (k8s Unconfined profile / annotation, docker seccomp=unconfined).
    const unconfined = /seccompProfile\s*:\s*(?:\{\s*type\s*:\s*Unconfined|\n\s*type\s*:\s*Unconfined)|seccomp\.security\.alpha\.kubernetes\.io\/[\w./-]+\s*:\s*["']?unconfined|\bseccomp\s*[=:]\s*["']?unconfined\b/i.exec(code);
    if (unconfined) {
        const matchLineIdx = lineAt(code, unconfined.index + Math.max(0, unconfined[0].search(/unconfined/i)));
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `kernsec15702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15702,
            type: 'SECURITY',
            title: "KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons",
            severity: "MEDIUM",
            category: "Syscall Filtering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'The workload opts out of seccomp: every syscall (keyctl, unshare, bpf, ptrace ...) reaches the host kernel.'
            ],
            remediationPrompt: "Use seccompProfile type RuntimeDefault (or a Localhost profile) instead of Unconfined; drop --security-opt seccomp=unconfined.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-04: BPF JIT hardening explicitly set to 0.
    const jitOff = /\bnet\.core\.bpf_jit_harden["']?\s*[=:]\s*["']?0\b/.exec(code);
    if (jitOff) {
        const matchLineIdx = lineAt(code, jitOff.index);
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `kernsec15704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15704,
            type: 'SECURITY',
            title: "KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage",
            severity: "MEDIUM",
            category: "eBPF Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'net.core.bpf_jit_harden is explicitly 0, turning off constant blinding for JIT-compiled BPF programs.'
            ],
            remediationPrompt: "Enable BPF JIT compiler hardening (net.core.bpf_jit_harden = 2) to mitigate Spectre branch target injection attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-05: kernel boot arguments that disable KPTI / all CPU mitigations.
    const ptiOff = /(?:^|[\s"'\[,=])(?:nopti|pti=off|mitigations=off)\b/m.exec(code);
    if (ptiOff) {
        const matchLineIdx = lineAt(code, ptiOff.index + ptiOff[0].search(/nopti|pti=off|mitigations=off/));
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `kernsec15705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15705,
            type: 'SECURITY',
            title: "KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters",
            severity: "HIGH",
            category: "Memory Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'The kernel command line disables page table isolation (nopti / pti=off / mitigations=off), re-opening Meltdown-class kernel memory reads.'
            ],
            remediationPrompt: "Ensure Kernel Page Table Isolation (KPTI) is enforced in kernel boot configuration to prevent Meltdown CPU vulnerabilities.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
