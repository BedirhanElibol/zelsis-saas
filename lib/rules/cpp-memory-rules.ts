/**
 * Zelsis Master evaluateCppMemoryRules Engine
 * CPP-SEC-01..04 (10001-10004). Removed as unsound (id never reused): 10005 any fixed-size stack array
 * declared in a file without memset (declaration is not an uninitialized read).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
    // CPP-SEC-01: Use of Unbounded String Copy Function (strcpy / gets / sprintf)
    if ((/\b(?:strcpy|gets|sprintf)\s*\(/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/\b(?:strcpy|gets|sprintf)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10001,
            type: 'SECURITY',
            title: "CPP-SEC-01: Use of Unbounded String Copy Function (strcpy / gets / sprintf)",
            severity: "HIGH",
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
    // free(p) followed (within ~200 chars, same function) by p-> / p. / *p use, with no reassignment of p in between.
    let useAfterFreeIdx = -1;
    const freed = /\bfree\s*\(\s*(\w+)\s*\)\s*;/g;
    for (let m = freed.exec(cleanContent); m && useAfterFreeIdx === -1; m = freed.exec(cleanContent)) {
        const after = cleanContent.slice(m.index + m[0].length, m.index + m[0].length + 200).split(/\n\}/)[0];
        const use = new RegExp(String.raw`(?:\b${m[1]}\s*(?:->|\.|\[)|\*\s*${m[1]}\b)`).exec(after);
        // A completed reassignment (`p = ...;`) before the use re-points p; `p = p->next` still reads freed memory.
        if (use && !new RegExp(String.raw`\b${m[1]}\s*=[^=][^;]*;`).test(after.slice(0, use.index))) {
            useAfterFreeIdx = lineAt(cleanContent, m.index + m[0].length + use.index);
        }
    }
    if (useAfterFreeIdx !== -1) {
        const matchLineIdx = useAfterFreeIdx;
        const lineNum = matchLineIdx + 1;
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
    // free(p) ... free(p) within the same function, with p never reset (p = NULL) or reassigned in between.
    let doubleFreeIdx = -1;
    const firstFree = /\bfree\s*\(\s*(\w+)\s*\)\s*;/g;
    for (let m = firstFree.exec(cleanContent); m && doubleFreeIdx === -1; m = firstFree.exec(cleanContent)) {
        const after = cleanContent.slice(m.index + m[0].length, m.index + m[0].length + 300).split(/\n\}/)[0];
        const again = new RegExp(String.raw`\bfree\s*\(\s*${m[1]}\s*\)`).exec(after);
        if (again && !new RegExp(String.raw`\b${m[1]}\s*=[^=]`).test(after.slice(0, again.index))) {
            doubleFreeIdx = lineAt(cleanContent, m.index + m[0].length + again.index);
        }
    }
    if (doubleFreeIdx !== -1) {
        const matchLineIdx = doubleFreeIdx;
        const lineNum = matchLineIdx + 1;
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
        const matchLineIdx = locateMatchLine(lines, [/malloc\s*\(\s*[a-zA-Z0-9_]+\s*\*\s*[a-zA-Z0-9_]+\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cppsec10004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10004,
            type: 'SECURITY',
            title: "CPP-SEC-04: Integer Overflow Leading to Heap Buffer Overflow in malloc",
            severity: "MEDIUM",
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
    return { findings, logs };
}
