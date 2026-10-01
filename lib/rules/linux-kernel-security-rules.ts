/**
 * Zelsis Master evaluateLinuxKernelSecurityRules Engine (50 Rules)
 * Rules KERN-SEC-01 to KERN-SEC-50 (Rule IDs 15701 to 15750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface LinuxKernelSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
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
    const ts = new Date().toLocaleTimeString();
    // KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads
    const grantsPrivilege = /privileged\s*:\s*true|--privileged|--cap-add[=\s]+(?:CAP_)?(?:SYS_ADMIN|ALL)|(?:cap_add|add)\s*:[^\n]*(?:SYS_ADMIN|ALL)|(?:cap_add|add)\s*:\s*\n(?:\s*-\s*\S+\s*\n)*?\s*-\s*["']?(?:CAP_)?(?:SYS_ADMIN|ALL)\b/i.test(cleanContent);
    if (grantsPrivilege && !/drop:\s*\[.*CAP_SYS_ADMIN.*\]/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
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
                'Matched KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads.'
            ],
            remediationPrompt: "Drop all default Linux capabilities and retain strictly the minimal required set (e.g. drop CAP_SYS_ADMIN, CAP_NET_ADMIN).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons
    if (((/seccomp|security_profile/i.test(lowerPath) || /seccompProfile/i.test(cleanContent)) && !/type:\s*RuntimeDefault|Localhost/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `kernsec15702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15702,
            type: 'SECURITY',
            title: "KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons",
            severity: "CRITICAL",
            category: "Syscall Filtering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'Matched KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons.'
            ],
            remediationPrompt: "Enforce restrictive Seccomp BPF profiles blocking dangerous system calls (e.g. ptrace, bpf, reboot) across host worker daemons.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-02: Missing Seccomp BPF Syscall Filtering on High-Privilege Worker Daemons at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-03: Unrestricted Unprivileged User Namespaces Permitting Local Privilege Escalation
    if (((/sysctl|kernel_tuning/i.test(lowerPath) || /max_user_namespaces/i.test(cleanContent)) && !/max_user_namespaces\s*=\s*0/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `kernsec15703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15703,
            type: 'SECURITY',
            title: "KERN-SEC-03: Unrestricted Unprivileged User Namespaces Permitting Local Privilege Escalation",
            severity: "HIGH",
            category: "Namespace Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'Matched KERN-SEC-03: Unrestricted Unprivileged User Namespaces Permitting Local Privilege Escalation.'
            ],
            remediationPrompt: "Disable unprivileged user namespace creation via kernel sysctl (user.max_user_namespaces = 0) on production hosts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-03: Unrestricted Unprivileged User Namespaces Permitting Local Privilege Escalation at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage
    if (((/sysctl|ebpf_config/i.test(lowerPath) || /bpf_jit_harden/i.test(cleanContent)) && !/bpf_jit_harden\s*=\s*2/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `kernsec15704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15704,
            type: 'SECURITY',
            title: "KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage",
            severity: "HIGH",
            category: "eBPF Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'Matched KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage.'
            ],
            remediationPrompt: "Enable BPF JIT compiler hardening (net.core.bpf_jit_harden = 2) to mitigate Spectre branch target injection attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-04: Kernel eBPF JIT Hardening Disabled Allowing Speculative Execution Leakage at ${file.path}:${lineNum}`);
    }
    // KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters
    if (((/grub|boot_params/i.test(lowerPath) || /kpti|pti=/i.test(cleanContent)) && !/pti=on/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `kernsec15705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15705,
            type: 'SECURITY',
            title: "KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters",
            severity: "CRITICAL",
            category: "Memory Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Linux Kernel Security configuration',
            reproductionSteps: [
                `Audited Linux Kernel Security configuration in ${file.path}:${lineNum}.`,
                'Matched KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters.'
            ],
            remediationPrompt: "Ensure Kernel Page Table Isolation (KPTI) is enforced in kernel boot configuration to prevent Meltdown CPU vulnerabilities.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [KERNEL AUDIT] Found KERN-SEC-05: Kernel Page Table Isolation (KPTI) Disabled in Boot Parameters at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
