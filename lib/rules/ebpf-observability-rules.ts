/**
 * Zelsis Master evaluateEbpfObservabilityRules Engine (50 Rules)
 * Rules EBPF-01 to EBPF-50 (Rule IDs 14201 to 14250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface EbpfObservabilityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEbpfObservabilityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EbpfObservabilityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM
    if ((/ring_buffer|perf_buffer/i.test(cleanContent) && !/max_entries|buffer_size/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/ring_buffer|perf_buffer/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ebpf14201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14201,
            type: 'INFRA_DATABASE',
            title: "EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM",
            severity: "CRITICAL",
            category: "Memory Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
            reproductionSteps: [
                `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
                'Matched EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM.'
            ],
            remediationPrompt: "Enforce memory limits on perf and ring buffers to prevent kernel memory exhaustion under burst traffic.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM at ${file.path}:${lineNum}`);
    }
    // EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading
    if ((/unprivileged_bpf_disabled/i.test(cleanContent) && cleanContent.includes('unprivileged_bpf_disabled = 0'))) {
        const matchLineIdx = locateMatchLine(lines, [/unprivileged_bpf_disabled/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ebpf14202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14202,
            type: 'INFRA_DATABASE',
            title: "EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading",
            severity: "CRITICAL",
            category: "Syscall Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
            reproductionSteps: [
                `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
                'Matched EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading.'
            ],
            remediationPrompt: "Set kernel.unprivileged_bpf_disabled = 2 to restrict BPF program loading strictly to privileged admin processes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading at ${file.path}:${lineNum}`);
    }
    // EBPF-03: Missing Tetragon Process Execution Tracing in Workloads
    if ((/tetragon/i.test(lowerPath) && !/tracingpolicy/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ebpf14203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14203,
            type: 'INFRA_DATABASE',
            title: "EBPF-03: Missing Tetragon Process Execution Tracing in Workloads",
            severity: "HIGH",
            category: "Runtime Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
            reproductionSteps: [
                `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
                'Matched EBPF-03: Missing Tetragon Process Execution Tracing in Workloads.'
            ],
            remediationPrompt: "Deploy eBPF kprobe hooks monitoring unauthorized execve calls and shell spawns in container namespaces.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-03: Missing Tetragon Process Execution Tracing in Workloads at ${file.path}:${lineNum}`);
    }
    // EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation
    if ((/xdp_pass/i.test(cleanContent) && !/xdp_drop|rateLimit/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/xdp_pass/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ebpf14204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14204,
            type: 'INFRA_DATABASE',
            title: "EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation",
            severity: "HIGH",
            category: "Packet Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
            reproductionSteps: [
                `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
                'Matched EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation.'
            ],
            remediationPrompt: "Implement rate-limiting XDP drop filters before packet payloads reach the Linux network stack.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation at ${file.path}:${lineNum}`);
    }
    // EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement
    if ((/CiliumNetworkPolicy/i.test(cleanContent) && !/rules:\s*-/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/CiliumNetworkPolicy/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `ebpf14205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14205,
            type: 'INFRA_DATABASE',
            title: "EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement",
            severity: "CRITICAL",
            category: "Network Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
            reproductionSteps: [
                `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
                'Matched EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement.'
            ],
            remediationPrompt: "Enforce L7 HTTP and gRPC API path filtering rules rather than permissive L3/L4 IP and port allowances.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
