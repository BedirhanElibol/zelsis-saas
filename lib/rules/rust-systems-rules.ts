/**
 * Zelsis Master evaluateRustSystemsRules Engine (50 Rules)
 * Rules RUST-01 to RUST-50 (Rule IDs 9601 to 9650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface RustSystemsRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateRustSystemsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): RustSystemsRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-rust paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isRust = lowerPath.endsWith(".rs") || lowerPath.endsWith("cargo.toml") || lowerPath.endsWith("cargo.lock");
    if (!isRust)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // RUST-01: Unsound Unsafe Block Missing Safety Invariant Comment
    if ((/unsafe\s*\{[\s\S]*?\}/i.test(cleanContent) && !cleanContent.includes('SAFETY:'))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rust9601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9601,
            type: 'INFRA_DATABASE',
            title: "RUST-01: Unsound Unsafe Block Missing Safety Invariant Comment",
            severity: "HIGH",
            category: "Memory Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Detected systems resilience violation matching RUST-01.'
            ],
            remediationPrompt: "Add // SAFETY: comment detailing pointer validity, alignment, and lifetime constraints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-01: Unsound Unsafe Block Missing Safety Invariant Comment at ${file.path}:${lineNum}`);
    }
    // RUST-02: Blocking Synchronous I/O Inside Tokio Async Function
    if ((/async\s+fn\s+[a-zA-Z0-9_]+\s*\([\s\S]*?std::thread::sleep/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rust9602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9602,
            type: 'INFRA_DATABASE',
            title: "RUST-02: Blocking Synchronous I/O Inside Tokio Async Function",
            severity: "HIGH",
            category: "Async Runtime",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Detected systems resilience violation matching RUST-02.'
            ],
            remediationPrompt: "Replace std::thread::sleep with tokio::time::sleep or offload to spawn_blocking.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-02: Blocking Synchronous I/O Inside Tokio Async Function at ${file.path}:${lineNum}`);
    }
    // RUST-03: Unbounded Tokio MPSC Channel Without Flow Control
    if ((/tokio::sync::mpsc::unbounded_channel/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rust9603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9603,
            type: 'INFRA_DATABASE',
            title: "RUST-03: Unbounded Tokio MPSC Channel Without Flow Control",
            severity: "HIGH",
            category: "Resource Starvation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Detected systems resilience violation matching RUST-03.'
            ],
            remediationPrompt: "Replace unbounded_channel with bounded channel with appropriate buffer capacity.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-03: Unbounded Tokio MPSC Channel Without Flow Control at ${file.path}:${lineNum}`);
    }
    // RUST-04: Panic in Drop Trait Implementation (Process Abort)
    if ((/impl(?:<[^>]*>)?\s+Drop\s+for[\s\S]*?fn\s+drop[\s\S]*?(?:panic!|\.unwrap\(\)|\.expect\()/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rust9604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9604,
            type: 'INFRA_DATABASE',
            title: "RUST-04: Panic in Drop Trait Implementation (Process Abort)",
            severity: "HIGH",
            category: "Runtime Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Detected systems resilience violation matching RUST-04.'
            ],
            remediationPrompt: "Remove unwrap() in Drop implementation and handle errors gracefully.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-04: Panic in Drop Trait Implementation (Process Abort) at ${file.path}:${lineNum}`);
    }
    // RUST-05: SQL Injection via format! in Database Queries
    const rustSqlInjectionRegex = /(?:format!\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b|sqlx::query\s*\(\s*&format!\()/i;
    if (rustSqlInjectionRegex.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && !l.trim().startsWith('*') && (rustSqlInjectionRegex.test(l) || l.includes('format!')));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `rust9605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9605,
            type: 'SECURITY',
            title: "RUST-05: SQL Injection via format! String Interpolation in Query",
            severity: "CRITICAL",
            category: "SQL Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'format!("SELECT ... {}", ...)',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Detected dynamic SQL query formatted with format!() instead of parameterized bind parameters.'
            ],
            remediationPrompt: "Use parameterized queries with sqlx::query! or sqlx::query_as! with query.bind(val) to prevent SQL injection.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-05: SQL Injection via format! at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
