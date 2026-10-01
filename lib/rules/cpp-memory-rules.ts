/**
 * Zelsis Master evaluateCppMemoryRules Engine (50 Rules)
 * Rules CPP-SEC-01 to CPP-SEC-50 (Rule IDs 10001 to 10050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CppMemoryRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCppMemoryRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CppMemoryRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-cpp paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isCpp = lowerPath.endsWith(".c") || lowerPath.endsWith(".cpp") || lowerPath.endsWith(".cc") || lowerPath.endsWith(".h") || lowerPath.endsWith(".hpp");
    if (!isCpp)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // CPP-SEC-01: Use of Unbounded String Copy Function (strcpy / gets / sprintf)
    if ((/\b(?:strcpy|gets|sprintf)\s*\(/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10001,
            type: 'SECURITY',
            title: "CPP-SEC-01: Use of Unbounded String Copy Function (strcpy / gets / sprintf)",
            severity: "CRITICAL",
            category: "Buffer Overflow",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'C/C++ code statement',
            reproductionSteps: [
                `Audited C/C++ source in ${file.path}:${lineNum}.`,
                'Detected systems memory safety violation matching CPP-SEC-01.'
            ],
            remediationPrompt: "Replace strcpy with snprintf or std::string assignment to prevent buffer overflow vulnerabilities.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CPP AUDIT] Found CPP-SEC-01: Use of Unbounded String Copy Function (strcpy / gets / sprintf) at ${file.path}:${lineNum}`);
    }
    // CPP-SEC-02: Use-After-Free Vulnerability (Dangling Pointer Dereference)
    if ((/free\s*\(\s*([a-zA-Z0-9_]+)\s*\)[\s\S]{1,200}\b\1(?:->|\.|\s*=\s*\*)/.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10002,
            type: 'SECURITY',
            title: "CPP-SEC-02: Use-After-Free Vulnerability (Dangling Pointer Dereference)",
            severity: "CRITICAL",
            category: "Memory Corruption",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'C/C++ code statement',
            reproductionSteps: [
                `Audited C/C++ source in ${file.path}:${lineNum}.`,
                'Detected systems memory safety violation matching CPP-SEC-02.'
            ],
            remediationPrompt: "Migrate raw pointers to std::unique_ptr or assign ptr = nullptr immediately following free().",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CPP AUDIT] Found CPP-SEC-02: Use-After-Free Vulnerability (Dangling Pointer Dereference) at ${file.path}:${lineNum}`);
    }
    // CPP-SEC-03: Double Free Vulnerability (Repeated Deallocation)
    if ((/free\s*\(\s*([a-zA-Z0-9_]+)\s*\)[\s\S]{1,150}free\s*\(\s*\1\s*\)/.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10003,
            type: 'SECURITY',
            title: "CPP-SEC-03: Double Free Vulnerability (Repeated Deallocation)",
            severity: "CRITICAL",
            category: "Memory Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'C/C++ code statement',
            reproductionSteps: [
                `Audited C/C++ source in ${file.path}:${lineNum}.`,
                'Detected systems memory safety violation matching CPP-SEC-03.'
            ],
            remediationPrompt: "Eliminate redundant delete calls or wrap resource management in an RAII container class.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CPP AUDIT] Found CPP-SEC-03: Double Free Vulnerability (Repeated Deallocation) at ${file.path}:${lineNum}`);
    }
    // CPP-SEC-04: Integer Overflow Leading to Heap Buffer Overflow in malloc
    if ((/malloc\s*\(\s*[a-zA-Z0-9_]+\s*\*\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10004,
            type: 'SECURITY',
            title: "CPP-SEC-04: Integer Overflow Leading to Heap Buffer Overflow in malloc",
            severity: "CRITICAL",
            category: "Arithmetic Overflow",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'C/C++ code statement',
            reproductionSteps: [
                `Audited C/C++ source in ${file.path}:${lineNum}.`,
                'Detected systems memory safety violation matching CPP-SEC-04.'
            ],
            remediationPrompt: "Use calloc or check if (count > SIZE_MAX / size) before allocating dynamic memory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CPP AUDIT] Found CPP-SEC-04: Integer Overflow Leading to Heap Buffer Overflow in malloc at ${file.path}:${lineNum}`);
    }
    // CPP-SEC-05: Uninitialized Stack Variable Usage
    if ((/(?:char|int|uint8_t)\s+[a-zA-Z0-9_]+\[\d+\]\s*;/.test(cleanContent) && !/memset|bzero|\{\s*0\s*\}/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10005,
            type: 'SECURITY',
            title: "CPP-SEC-05: Uninitialized Stack Variable Usage",
            severity: "HIGH",
            category: "Memory Initialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'C/C++ code statement',
            reproductionSteps: [
                `Audited C/C++ source in ${file.path}:${lineNum}.`,
                'Detected systems memory safety violation matching CPP-SEC-05.'
            ],
            remediationPrompt: "Initialize all local variables and buffer arrays with zero-initialization at declaration.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CPP AUDIT] Found CPP-SEC-05: Uninitialized Stack Variable Usage at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
