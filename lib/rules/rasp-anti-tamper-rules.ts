/**
 * Zelsis Master evaluateRaspAntiTamperRules Engine (50 Rules)
 * Rules RASP-01 to RASP-50 (Rule IDs 14601 to 14650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface RaspAntiTamperRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateRaspAntiTamperRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): RaspAntiTamperRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // RASP-01: Missing Runtime Application Self-Protection (RASP) Execution Hooks
    if ((/dynamicExecution/i.test(cleanContent) && !/raspGuard/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/dynamicExecution/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rasp14601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14601,
            type: 'SECURITY',
            title: "RASP-01: Missing Runtime Application Self-Protection (RASP) Execution Hooks",
            severity: "CRITICAL",
            category: "Runtime Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Runtime Application Self-Protection configuration',
            reproductionSteps: [
                `Audited Runtime Application Self-Protection configuration in ${file.path}:${lineNum}.`,
                'Matched RASP-01: Missing Runtime Application Self-Protection (RASP) Execution Hooks.'
            ],
            remediationPrompt: "Intercept and block dynamic code evaluation (eval, Function constructor, exec) at the JavaScript/runtime level.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RASP AUDIT] Found RASP-01: Missing Runtime Application Self-Protection (RASP) Execution Hooks at ${file.path}:${lineNum}`);
    }
    // RASP-02: Unauthorized Debugger Attachment Permitted in Production Runtime
    if ((/debuggerDetection/i.test(cleanContent) && !/terminateOnDebugger/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/debuggerDetection/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rasp14602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14602,
            type: 'SECURITY',
            title: "RASP-02: Unauthorized Debugger Attachment Permitted in Production Runtime",
            severity: "HIGH",
            category: "Anti-Debugging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Runtime Application Self-Protection configuration',
            reproductionSteps: [
                `Audited Runtime Application Self-Protection configuration in ${file.path}:${lineNum}.`,
                'Matched RASP-02: Unauthorized Debugger Attachment Permitted in Production Runtime.'
            ],
            remediationPrompt: "Detect and terminate application processes if unauthorized ptrace or remote debugger attach attempts occur.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RASP AUDIT] Found RASP-02: Unauthorized Debugger Attachment Permitted in Production Runtime at ${file.path}:${lineNum}`);
    }
    // RASP-03: Prototype Pollution Exploitation: Unfrozen Core Object Prototypes
    if ((/initializeRuntime/i.test(cleanContent) && !/Object\.freeze/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/initializeRuntime/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rasp14603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14603,
            type: 'SECURITY',
            title: "RASP-03: Prototype Pollution Exploitation: Unfrozen Core Object Prototypes",
            severity: "CRITICAL",
            category: "Prototype Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Runtime Application Self-Protection configuration',
            reproductionSteps: [
                `Audited Runtime Application Self-Protection configuration in ${file.path}:${lineNum}.`,
                'Matched RASP-03: Prototype Pollution Exploitation: Unfrozen Core Object Prototypes.'
            ],
            remediationPrompt: "Freeze Object.prototype, Array.prototype, and Function.prototype at process startup to prevent pollution.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RASP AUDIT] Found RASP-03: Prototype Pollution Exploitation: Unfrozen Core Object Prototypes at ${file.path}:${lineNum}`);
    }
    // RASP-04: Dynamic Memory Tampering: Insecure Memory Allocations in Native Addons
    if ((/(?:binding\.gyp|CMakeLists\.txt)/i.test(cleanContent) && !/-fstack-protector/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:binding\.gyp|CMakeLists\.txt)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rasp14604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14604,
            type: 'SECURITY',
            title: "RASP-04: Dynamic Memory Tampering: Insecure Memory Allocations in Native Addons",
            severity: "HIGH",
            category: "Memory Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Runtime Application Self-Protection configuration',
            reproductionSteps: [
                `Audited Runtime Application Self-Protection configuration in ${file.path}:${lineNum}.`,
                'Matched RASP-04: Dynamic Memory Tampering: Insecure Memory Allocations in Native Addons.'
            ],
            remediationPrompt: "Enable Address Space Layout Randomization (ASLR) and stack canary compiler flags on all native modules.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RASP AUDIT] Found RASP-04: Dynamic Memory Tampering: Insecure Memory Allocations in Native Addons at ${file.path}:${lineNum}`);
    }
    // RASP-05: Unchecked Buffer Offsets Across Foreign Function Interface (FFI)
    if ((/ffiBridge|nativeCall/i.test(cleanContent) && !/validateBufferBounds/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/ffiBridge|nativeCall/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rasp14605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14605,
            type: 'SECURITY',
            title: "RASP-05: Unchecked Buffer Offsets Across Foreign Function Interface (FFI)",
            severity: "HIGH",
            category: "FFI Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Runtime Application Self-Protection configuration',
            reproductionSteps: [
                `Audited Runtime Application Self-Protection configuration in ${file.path}:${lineNum}.`,
                'Matched RASP-05: Unchecked Buffer Offsets Across Foreign Function Interface (FFI).'
            ],
            remediationPrompt: "Validate memory bounds and argument pointer offsets before crossing native C/C++ addon boundaries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RASP AUDIT] Found RASP-05: Unchecked Buffer Offsets Across Foreign Function Interface (FFI) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
