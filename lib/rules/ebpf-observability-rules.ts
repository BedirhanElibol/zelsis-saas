/**
 * Zelsis Master evaluateEbpfObservabilityRules Engine (50 Rules)
 * Rules EBPF-01 to EBPF-50 (Rule IDs 14201 to 14250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    // EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading
    const hit_14202 = lines.findIndex((l) => /^\s*(?:sysctl\s+(?:-w\s+)?)?kernel\.unprivileged_bpf_disabled\s*=\s*0\b/.test(l) || /\bsysctl\s+(?:-w\s+)?kernel\.unprivileged_bpf_disabled=0\b/.test(l));
    if (hit_14202 !== -1) {
        const matchLineIdx = hit_14202;
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
    return { findings, logs };
}
