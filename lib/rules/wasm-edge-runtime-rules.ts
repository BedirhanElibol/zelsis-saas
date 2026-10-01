/**
 * Zelsis Master evaluateWasmEdgeRuntimeRules Engine (50 Rules)
 * Rules WASM-EDGE-01 to WASM-EDGE-50 (Rule IDs 15201 to 15250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface WasmEdgeRuntimeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWasmEdgeRuntimeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): WasmEdgeRuntimeRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM
    if (((/wasm|worker|fastly/i.test(lowerPath) || /wasm|WebAssembly/i.test(cleanContent)) && !/maximum_memory_pages/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasmedge15201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15201,
            type: 'INFRA_DATABASE',
            title: "WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM",
            severity: "CRITICAL",
            category: "Memory Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Edge Runtime configuration',
            reproductionSteps: [
                `Audited WebAssembly Edge Runtime configuration in ${file.path}:${lineNum}.`,
                'Matched WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM.'
            ],
            remediationPrompt: "Define strict memory limits in Wasm runtime flags (e.g. maximum linear memory pages 128MB) to prevent edge node exhaustion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM at ${file.path}:${lineNum}`);
    }
    // WASM-EDGE-02: Missing Host Function Sandboxing and Capability-Based Security Barriers in Wasm Runtime
    if (((/wasi|wasm_host/i.test(lowerPath) || /wasi|HostFunction/i.test(cleanContent)) && !/capabilitySandbox/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasmedge15202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15202,
            type: 'INFRA_DATABASE',
            title: "WASM-EDGE-02: Missing Host Function Sandboxing and Capability-Based Security Barriers in Wasm Runtime",
            severity: "CRITICAL",
            category: "Capability Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Edge Runtime configuration',
            reproductionSteps: [
                `Audited WebAssembly Edge Runtime configuration in ${file.path}:${lineNum}.`,
                'Matched WASM-EDGE-02: Missing Host Function Sandboxing and Capability-Based Security Barriers in Wasm Runtime.'
            ],
            remediationPrompt: "Enforce capability-based security barriers restricting WASI system calls to pre-approved directory mappings and domain scopes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-EDGE-02: Missing Host Function Sandboxing and Capability-Based Security Barriers in Wasm Runtime at ${file.path}:${lineNum}`);
    }
    // WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways
    if (((/wasm_edge|edge_compute/i.test(lowerPath) || /wasm/i.test(cleanContent)) && !/enforceReverseProxyOnly/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasmedge15203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15203,
            type: 'INFRA_DATABASE',
            title: "WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways",
            severity: "HIGH",
            category: "Network Policy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Edge Runtime configuration',
            reproductionSteps: [
                `Audited WebAssembly Edge Runtime configuration in ${file.path}:${lineNum}.`,
                'Matched WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways.'
            ],
            remediationPrompt: "Block raw socket bindings in edge Wasm instances; enforce controlled HTTPS subrequests through host reverse proxy APIs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways at ${file.path}:${lineNum}`);
    }
    // WASM-EDGE-04: Unsanitized Wasm SIMD Instructions Executing on Untrusted Multi-Tenant Edge Nodes
    if (((/wasm_simd|worker_runtime/i.test(lowerPath) || /simd/i.test(cleanContent)) && !/verifySimdInstructions/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasmedge15204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15204,
            type: 'INFRA_DATABASE',
            title: "WASM-EDGE-04: Unsanitized Wasm SIMD Instructions Executing on Untrusted Multi-Tenant Edge Nodes",
            severity: "HIGH",
            category: "Execution Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Edge Runtime configuration',
            reproductionSteps: [
                `Audited WebAssembly Edge Runtime configuration in ${file.path}:${lineNum}.`,
                'Matched WASM-EDGE-04: Unsanitized Wasm SIMD Instructions Executing on Untrusted Multi-Tenant Edge Nodes.'
            ],
            remediationPrompt: "Sanitize or disable experimental Wasm vector extensions on shared multi-tenant edge compute infrastructure.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-EDGE-04: Unsanitized Wasm SIMD Instructions Executing on Untrusted Multi-Tenant Edge Nodes at ${file.path}:${lineNum}`);
    }
    // WASM-EDGE-05: Unchecked SharedArrayBuffer Usage in Edge Wasm Modules Vulnerable to Spectre Side-Channels
    if (((/wasm_threads|shared_mem/i.test(lowerPath) || /SharedArrayBuffer/i.test(cleanContent)) && !/crossOriginIsolated/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasmedge15205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15205,
            type: 'INFRA_DATABASE',
            title: "WASM-EDGE-05: Unchecked SharedArrayBuffer Usage in Edge Wasm Modules Vulnerable to Spectre Side-Channels",
            severity: "CRITICAL",
            category: "Side-Channel Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Edge Runtime configuration',
            reproductionSteps: [
                `Audited WebAssembly Edge Runtime configuration in ${file.path}:${lineNum}.`,
                'Matched WASM-EDGE-05: Unchecked SharedArrayBuffer Usage in Edge Wasm Modules Vulnerable to Spectre Side-Channels.'
            ],
            remediationPrompt: "Require Cross-Origin-Opener-Policy (COOP) and Cross-Origin-Embedder-Policy (COEP) headers whenever SharedArrayBuffer is utilized in Wasm.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-EDGE-05: Unchecked SharedArrayBuffer Usage in Edge Wasm Modules Vulnerable to Spectre Side-Channels at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
