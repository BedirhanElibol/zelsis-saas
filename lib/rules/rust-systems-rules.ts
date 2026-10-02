/**
 * Zelsis Master evaluateRustSystemsRules Engine
 * RUST-01 (9601), RUST-02 (9602), RUST-04 (9604), RUST-05 (9605), each reported on the offending line.
 * Removed as unsound (id never reused): 9603 tokio unbounded_channel (a documented, legitimate primitive;
 * whether backpressure is needed is not visible in code).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface RustSystemsRuleResult {
    findings: Finding[];
    logs: string[];
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
/** Brace-matched `{ ... }` starting at the first `{` at or after `from`. */
function blockFrom(src: string, from: number): { start: number; text: string } | null {
    const open = src.indexOf('{', from);
    if (open === -1) return null;
    let depth = 0;
    for (let i = open; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) return { start: open, text: src.slice(open, i + 1) };
    }
    return null;
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
    if (!lowerPath.endsWith(".rs"))
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    const isCommentLine = (l: string) => /^\s*(?:\/\/|\/\*|\*)/.test(l);
    // RUST-01: an `unsafe { }` block with no `// SAFETY:` comment on it or in the comment lines right above it.
    // (`lines` keeps comments; cleanContent has them stripped, so the comment check reads `lines`.)
    const undocumentedUnsafeIdx = lines.findIndex((l, i) => {
        if (isCommentLine(l) || !/\bunsafe\s*\{/.test(l.replace(/\/\/.*$/, ''))) return false;
        if (/SAFETY:/.test(l)) return false;
        for (let j = i - 1; j >= 0 && j >= i - 4; j--) {
            if (/SAFETY:/.test(lines[j])) return false;
            if (lines[j].trim() !== '' && !isCommentLine(lines[j])) break;
        }
        return true;
    });
    if (undocumentedUnsafeIdx !== -1) {
        const matchLineIdx = undocumentedUnsafeIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `rust9601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9601,
            type: 'INFRA_DATABASE',
            title: "RUST-01: Unsound Unsafe Block Missing Safety Invariant Comment",
            severity: "LOW",
            category: "Memory Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'This unsafe block has no // SAFETY: comment stating the invariants that make it sound (clippy::undocumented_unsafe_blocks).'
            ],
            remediationPrompt: "Add // SAFETY: comment detailing pointer validity, alignment, and lifetime constraints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-01: Unsound Unsafe Block Missing Safety Invariant Comment at ${file.path}:${lineNum}`);
    }
    // RUST-02: std::thread::sleep inside the body of an `async fn` (not inside a spawn_blocking closure):
    // it parks the executor worker thread and stalls every task scheduled on it.
    let blockingSleepIdx = -1;
    const asyncFn = /\basync\s+fn\s+\w+[^{;]*/g;
    for (let m = asyncFn.exec(cleanContent); m && blockingSleepIdx === -1; m = asyncFn.exec(cleanContent)) {
        const body = blockFrom(cleanContent, m.index + m[0].length);
        if (!body) continue;
        const sleep = /\b(?:std::)?thread::sleep\s*\(/.exec(body.text);
        if (sleep && !/spawn_blocking/.test(body.text.slice(0, sleep.index))) blockingSleepIdx = lineAt(cleanContent, body.start + sleep.index);
    }
    if (blockingSleepIdx !== -1) {
        const matchLineIdx = blockingSleepIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `rust9602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9602,
            type: 'INFRA_DATABASE',
            title: "RUST-02: Blocking Synchronous I/O Inside Tokio Async Function",
            severity: "MEDIUM",
            category: "Async Runtime",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'std::thread::sleep blocks the async executor thread instead of yielding.'
            ],
            remediationPrompt: "Replace std::thread::sleep with tokio::time::sleep or offload to spawn_blocking.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-02: Blocking Synchronous I/O Inside Tokio Async Function at ${file.path}:${lineNum}`);
    }
    // RUST-04: panic!/unwrap()/expect() inside the body of Drop::drop (panicking while unwinding aborts).
    let dropPanicIdx = -1;
    const dropImpl = /\bimpl(?:<[^>]*>)?\s+Drop\s+for\b[^{]*/g;
    for (let m = dropImpl.exec(cleanContent); m && dropPanicIdx === -1; m = dropImpl.exec(cleanContent)) {
        const impl = blockFrom(cleanContent, m.index + m[0].length);
        if (!impl) continue;
        const fnDrop = /\bfn\s+drop\s*\(/.exec(impl.text);
        if (!fnDrop) continue;
        const body = blockFrom(impl.text, fnDrop.index);
        if (!body) continue;
        const panic = /\bpanic!\s*\(|\.unwrap\(\)|\.expect\(/.exec(body.text);
        if (panic) dropPanicIdx = lineAt(cleanContent, impl.start + body.start + panic.index);
    }
    if (dropPanicIdx !== -1) {
        const matchLineIdx = dropPanicIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `rust9604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9604,
            type: 'INFRA_DATABASE',
            title: "RUST-04: Panic in Drop Trait Implementation (Process Abort)",
            severity: "MEDIUM",
            category: "Runtime Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Rust source code instruction',
            reproductionSteps: [
                `Audited Rust source in ${file.path}:${lineNum}.`,
                'Drop::drop can panic; a panic while already unwinding aborts the whole process.'
            ],
            remediationPrompt: "Remove unwrap() in Drop implementation and handle errors gracefully.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [RUST AUDIT] Found RUST-04: Panic in Drop Trait Implementation (Process Abort) at ${file.path}:${lineNum}`);
    }
    // RUST-05: SQL Injection via format! in Database Queries
    const rustSqlInjection = /(?:format!\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b|sqlx::query\s*\(\s*&format!\()/i.exec(cleanContent);
    if (rustSqlInjection) {
        const matchLineIdx = lineAt(cleanContent, rustSqlInjection.index);
        const lineNum = matchLineIdx + 1;
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
