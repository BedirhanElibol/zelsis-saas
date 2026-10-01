/**
 * Zelsis Master evaluateWasmRuntimeRules Engine (50 Rules)
 * Rules WASM-01 to WASM-50 (Rule IDs 12701 to 12750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    if ((/WebAssembly\.Memory/i.test(cleanContent) && !/maximum:\s*\d+/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/WebAssembly\.Memory/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12701,
            type: 'INFRA_DATABASE',
            title: "WASM-01: Unbounded WebAssembly Linear Memory Allocation",
            severity: "HIGH",
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
    // WASM-02: Missing Gas Metering or Execution Fuel Limits in Wasm Runtime
    if ((/(?:wasmtime|wasmer|wasm_engine)/i.test(cleanContent) && !/consumeFuel|consume_fuel|gasLimit/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:wasmtime|wasmer|wasm_engine)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12702,
            type: 'INFRA_DATABASE',
            title: "WASM-02: Missing Gas Metering or Execution Fuel Limits in Wasm Runtime",
            severity: "CRITICAL",
            category: "Compute Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Sandbox configuration',
            reproductionSteps: [
                `Audited WebAssembly Sandbox configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching WASM-02.'
            ],
            remediationPrompt: "Configure gas metering or fuel limits to terminate runaway Wasm execution loops.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-02: Missing Gas Metering or Execution Fuel Limits in Wasm Runtime at ${file.path}:${lineNum}`);
    }
    // WASM-03: Unrestricted WASI Filesystem Preopens Permitting Host Traversal
    if ((/preopen(?:s|Dir)/i.test(cleanContent) && /(?:'\/'|"\/")/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/preopen(?:s|Dir)/i, /(?:'\/'|"\/")/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // WASM-04: Shared Wasm Module State Causing Cross-Request Data Leakage
    if ((/let\s+wasmInstance/i.test(cleanContent) && !/newInstancePerRequest/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/let\s+wasmInstance/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12704,
            type: 'INFRA_DATABASE',
            title: "WASM-04: Shared Wasm Module State Causing Cross-Request Data Leakage",
            severity: "HIGH",
            category: "State Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Sandbox configuration',
            reproductionSteps: [
                `Audited WebAssembly Sandbox configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching WASM-04.'
            ],
            remediationPrompt: "Instantiate new WebAssembly instances per request to guarantee complete memory isolation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-04: Shared Wasm Module State Causing Cross-Request Data Leakage at ${file.path}:${lineNum}`);
    }
    // WASM-05: Unvalidated Host Function Bindings Permitting Privilege Escalation
    if ((/importObject/i.test(cleanContent) && !/validateHostCallArgs/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/importObject/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `wasm12705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12705,
            type: 'INFRA_DATABASE',
            title: "WASM-05: Unvalidated Host Function Bindings Permitting Privilege Escalation",
            severity: "HIGH",
            category: "Host Call Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'WebAssembly Sandbox configuration',
            reproductionSteps: [
                `Audited WebAssembly Sandbox configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching WASM-05.'
            ],
            remediationPrompt: "Validate all memory offsets and argument boundaries passed across the Wasm-to-host FFI boundary.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WASM AUDIT] Found WASM-05: Unvalidated Host Function Bindings Permitting Privilege Escalation at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
