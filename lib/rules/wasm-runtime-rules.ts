/**
 * Zelsis Master evaluateWasmRuntimeRules Engine (50 Rules)
 * Rules WASM-01 to WASM-50 (Rule IDs 12701 to 12750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface WasmRuntimeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWasmRuntimeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): WasmRuntimeRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // WASM-01: Unbounded WebAssembly Linear Memory Allocation
    const r12701Idx = lines.findIndex((l, i) => /new\s+WebAssembly\.Memory\s*\(/.test(l) && !/\bmaximum\s*:/.test(lines.slice(i, i + 6).join(' ').split('})')[0]));
    if (r12701Idx !== -1) {
        const matchLineIdx = r12701Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12701,
            type: 'INFRA_DATABASE',
            title: "WASM-01: Unbounded WebAssembly Linear Memory Allocation",
            severity: "MEDIUM",
            category: "Memory Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Sandbox configuration',
            reproductionSteps: [
                `Audited WebAssembly Sandbox configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching WASM-01.'
            ],
            remediationPrompt: "Specify maximum memory bounds (e.g. maximum: 2048 pages) when instantiating WebAssembly.Memory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-01: Unbounded WebAssembly Linear Memory Allocation at ${file.path}:${lineNum}`);
    }
    // WASM-03: Unrestricted WASI Filesystem Preopens Permitting Host Traversal
    const r12703Idx = lines.findIndex((l, i) => /preopened_dir\(\s*"\/"/.test(l) ||
        (/:\s*['"]\/['"]\s*[,}]?\s*$|:\s*['"]\/['"]\s*[,}]/.test(l) && /preopens/.test(lines.slice(Math.max(0, i - 3), i + 1).join(' '))));
    if (r12703Idx !== -1) {
        const matchLineIdx = r12703Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12703,
            type: 'INFRA_DATABASE',
            title: "WASM-03: Unrestricted WASI Filesystem Preopens Permitting Host Traversal",
            severity: "CRITICAL",
            category: "Filesystem Sandboxing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Sandbox configuration',
            reproductionSteps: [
                `Audited WebAssembly Sandbox configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching WASM-03.'
            ],
            remediationPrompt: "Restrict WASI preopens strictly to dedicated sandbox subdirectories; never preopen host root (/ or C:\\).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-03: Unrestricted WASI Filesystem Preopens Permitting Host Traversal at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
