/**
 * Zelsis Master evaluateGoMicroservicesRules Engine (50 Rules)
 * Rules GO-01 to GO-50 (Rule IDs 9001 to 9050).
 * Zero artificial sentinels. Real regex patterns with exact line detection.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface GoMicroservicesRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGoMicroservicesRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GoMicroservicesRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-go paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isGo = lowerPath.endsWith(".go") || lowerPath.endsWith("go.mod") || lowerPath.endsWith("go.sum");
    if (!isGo)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // GO-01: Command Injection via Unsanitized exec.Command Input
    const idx_9001 = (() => {
        const tainted = goRequestVars(lines);
        const call = /exec\.Command(?:Context)?\s*\(/;
        return goFindLine(lines, call, (_l, i) => {
            const text = callText(lines, i, call);
            const args = goSplitArgs(text);
            if (/^exec\.CommandContext/.test(text)) args.shift();
            if (args.length >= 3 && /^"(?:sh|bash|\/bin\/sh|\/bin\/bash|cmd|cmd\.exe|powershell)"$/.test(args[0]) && /^"(?:-c|\/c|\/C|-Command)"$/.test(args[1])) {
                const script = args[2];
                if (/^"(?:[^"\\]|\\.)*"$|^`[^`]*`$/.test(script)) return false;
                return /fmt\.Sprintf\s*\(|\+/.test(script) || goTainted(script, tainted);
            }
            return !!args[0] && goTainted(args[0], tainted);
        });
    })();
    if (idx_9001 !== -1) {
        const matchLineIdx = idx_9001;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Command Injection via Unsanitized exec.Command Input";
        findings.push({
            id: `go9001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9001,
            type: 'INFRA_DATABASE',
            title: "GO-01: Command Injection via Unsanitized exec.Command Input",
            severity: "CRITICAL",
            category: "Command Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Passing unsanitized user inputs or invoking shell interpreters (sh -c, bash -c) in exec.Command enables remote code execution."
            ],
            remediationPrompt: "Pass command arguments directly as separate slice arguments to exec.Command instead of invoking a shell interpreter.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-01: Command Injection via Unsanitized exec.Command Input at ${file.path}:${lineNum}`);
    }
    // GO-02: SQL Injection via String Concatenation or fmt.Sprintf
    const reg_9002 = /(?:(?:db|tx)\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(?:fmt\.Sprintf\s*\(|query|[a-zA-Z0-9_]+\s*\+)|fmt\.Sprintf\s*\(\s*['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)/i;
    if (reg_9002.test(cleanContent)) {
        const linePattern = /(?:(?:db|tx)\.(?:Query|QueryRow|Exec)|fmt\.Sprintf\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE))/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "SQL Injection via String Concatenation or fmt.Sprintf";
        findings.push({
            id: `go9002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9002,
            type: 'INFRA_DATABASE',
            title: "GO-02: SQL Injection via String Concatenation or fmt.Sprintf",
            severity: "CRITICAL",
            category: "SQL Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Formatting SQL statements with fmt.Sprintf or string concatenation in db.Query or db.Exec enables SQL injection."
            ],
            remediationPrompt: "Replace fmt.Sprintf in SQL queries with parameterized query placeholders ($1, ?).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-02: SQL Injection via String Concatenation or fmt.Sprintf at ${file.path}:${lineNum}`);
    }
    // GO-03: Missing Response Body Close (Leaking TCP Sockets)
    const idx_9003 = (() => {
        const call = /^\s*(\w+)\s*,\s*\w+\s*:?=\s*(?:http\.(?:Get|Post|PostForm|Head)|[\w.]*(?:[cC]lient|http\.DefaultClient)\.(?:Do|Get|Post|PostForm|Head))\s*\(/;
        for (let i = 0; i < lines.length; i++) {
            const m = call.exec(lines[i]);
            if (!m || !goIsCode(lines[i])) continue;
            const name = m[1];
            if (name === '_') return i;
            const handled = new RegExp(`\\b${name}\\.Body\\.Close\\s*\\(|\\breturn\\b[^\\n]*\\b${name}\\b|\\(\\s*${name}\\s*[,)]`);
            let closed = false;
            for (let j = i + 1; j < Math.min(lines.length, i + 80); j++) {
                if (/^(?:func\s|\})/.test(lines[j])) break;
                if (goIsCode(lines[j]) && handled.test(lines[j])) { closed = true; break; }
            }
            if (!closed) return i;
        }
        return -1;
    })();
    if (idx_9003 !== -1) {
        const matchLineIdx = idx_9003;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Missing Response Body Close (Leaking TCP Sockets)";
        findings.push({
            id: `go9003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9003,
            type: 'INFRA_DATABASE',
            title: "GO-03: Missing Response Body Close (Leaking TCP Sockets)",
            severity: "HIGH",
            category: "Resource Leakage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Calling http.Get or client.Do without defer resp.Body.Close() exhausts operating system socket descriptors."
            ],
            remediationPrompt: "Add defer resp.Body.Close() after successful HTTP request execution.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-03: Missing Response Body Close (Leaking TCP Sockets) at ${file.path}:${lineNum}`);
    }
    // GO-04: Default HTTP Client Without Timeout (http.DefaultClient)
    const reg_9004 = /http\.DefaultClient|http\.Get\s*\(/i;
    if (reg_9004.test(cleanContent)) {
        const linePattern = /http\.DefaultClient|http\.Get/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Default HTTP Client Without Timeout (http.DefaultClient)";
        findings.push({
            id: `go9004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9004,
            type: 'INFRA_DATABASE',
            title: "GO-04: Default HTTP Client Without Timeout (http.DefaultClient)",
            severity: "HIGH",
            category: "Availability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Using http.DefaultClient or http.Get() with zero timeout causes goroutines to hang indefinitely on stalled connections."
            ],
            remediationPrompt: "Replace http.DefaultClient with custom client configured with a 10-second timeout.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-04: Default HTTP Client Without Timeout (http.DefaultClient) at ${file.path}:${lineNum}`);
    }
    // GO-05: Data Race on Shared Map Without Mutex or sync.Map
    const idx_9005 = (() => {
        const maps = new Set<string>();
        for (const l of lines) {
            const made = /(\w+)\s*(?::?=|:)\s*(?:make\s*\(\s*map\[|map\[[^\]]+\][\w.*[\]]+\s*\{)/.exec(l);
            if (made) maps.add(made[1]);
            const declared = /^\s*(?:var\s+)?(\w+)\s+map\[/.exec(l);
            if (declared) maps.add(declared[1]);
        }
        if (maps.size === 0) return -1;
        for (let i = 0; i < lines.length; i++) {
            if (!goIsCode(lines[i]) || !/\bgo\s+func\s*\(/.test(lines[i])) continue;
            const [s, e] = goBlockRange(lines, i);
            const body = lines.slice(s, e + 1);
            if (body.some((l) => /\.(?:Lock|RLock)\s*\(\s*\)/.test(l))) continue;
            for (let j = s; j <= e; j++) {
                const w = /^\s*(?:\w+\.)*(\w+)\[[^\]]+\]\s*(?:=(?!=)|\+\+|--|[-+*/]=)|^\s*delete\s*\(\s*(?:\w+\.)*(\w+)\s*,/.exec(lines[j]);
                const name = w && (w[1] || w[2]);
                if (!name || !maps.has(name)) continue;
                if (body.some((l) => new RegExp(`\\b${name}\\s*:?=\\s*(?:make|map)\\b`).test(l))) continue;
                return j;
            }
        }
        return -1;
    })();
    if (idx_9005 !== -1) {
        const matchLineIdx = idx_9005;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Data Race on Shared Map Without Mutex or sync.Map";
        findings.push({
            id: `go9005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9005,
            type: 'INFRA_DATABASE',
            title: "GO-05: Data Race on Shared Map Without Mutex or sync.Map",
            severity: "CRITICAL",
            category: "Thread Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Reading and writing to standard Go map across multiple goroutines without sync.RWMutex synchronization causes fatal runtime panics."
            ],
            remediationPrompt: "Synchronize concurrent map access using sync.RWMutex.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-05: Data Race on Shared Map Without Mutex or sync.Map at ${file.path}:${lineNum}`);
    }
    // GO-06: Path Traversal via Unvalidated File Access in Go Source
    const idx_9006 = (() => {
        const tainted = goRequestVars(lines);
        const sink = /(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile)|ioutil\.(?:ReadFile|WriteFile)|http\.ServeFile|c\.(?:File|FileAttachment|SendFile|Attachment))\s*\(/;
        return goFindLine(lines, sink, (_l, i) => {
            const text = callText(lines, i, sink);
            const args = goSplitArgs(text);
            const pathArg = /^http\.ServeFile/.test(text) ? args[2] : args[0];
            return !!pathArg && goTainted(pathArg, tainted);
        });
    })();
    if (idx_9006 !== -1) {
        const matchLineIdx = idx_9006;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Path Traversal via Unvalidated File Access in Go Source";
        findings.push({
            id: `go9006-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9006,
            type: 'INFRA_DATABASE',
            title: "GO-06: Path Traversal via Unvalidated File Access in Go Source",
            severity: "HIGH",
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Opening or reading files directly using user request parameters in os.Open or os.ReadFile allows reading sensitive server files."
            ],
            remediationPrompt: "Validate target file paths using filepath.Clean and verify with strings.HasPrefix.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-06: Path Traversal via Unvalidated File Access in Go Source at ${file.path}:${lineNum}`);
    }
    // GO-07: Cross-Site Scripting (XSS) via Unescaped template.HTML
    const reg_9007 = /template\.(?:HTML|JS|CSS|URL)\s*\(\s*(?!['"`])[a-zA-Z0-9_.]+\s*\)/i;
    if (reg_9007.test(cleanContent)) {
        const linePattern = /template\.(?:HTML|JS|CSS|URL)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Cross-Site Scripting (XSS) via Unescaped template.HTML";
        findings.push({
            id: `go9007-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9007,
            type: 'INFRA_DATABASE',
            title: "GO-07: Cross-Site Scripting (XSS) via Unescaped template.HTML",
            severity: "HIGH",
            category: "Cross-Site Scripting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Wrapping unvalidated user strings in template.HTML() bypasses Go html/template contextual auto-escaping, leading to XSS."
            ],
            remediationPrompt: "Remove template.HTML cast on user input and pass data directly to template execution context.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-07: Cross-Site Scripting (XSS) via Unescaped template.HTML at ${file.path}:${lineNum}`);
    }
    // GO-08: Hardcoded Secret or API Key in Go Source Code
    const idx_9008 = goFindLine(lines, /(?:^|\b(?:const|var)\s+)\s*[a-zA-Z_]\w*(?:secret|password|passwd|token|apikey|api_key|privatekey|signingkey)\s*(?:string\s*)?:?=\s*"[^"\s]{12,}"/i, (l) => {
        const v = (/"([^"\s]{12,})"/.exec(l) as RegExpExecArray)[1];
        return /[0-9]/.test(v) && /[A-Za-z]/.test(v) && !/^[A-Za-z]+(?:[-_.:][A-Za-z0-9]+)*$/.test(v) && !/^(?:https?:|\/)/.test(v);
    });
    if (idx_9008 !== -1) {
        const matchLineIdx = idx_9008;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Hardcoded Secret or API Key in Go Source Code";
        findings.push({
            id: `go9008-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9008,
            type: 'INFRA_DATABASE',
            title: "GO-08: Hardcoded Secret or API Key in Go Source Code",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Hardcoded static secrets or API tokens committed in Go source code expose services to unauthorized access."
            ],
            remediationPrompt: "Replace hardcoded secrets with os.Getenv().",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-08: Hardcoded Secret or API Key in Go Source Code at ${file.path}:${lineNum}`);
    }
    // GO-09: Weak Cryptographic Algorithm in Go Source (MD5 / SHA1 / DES)
    const idx_9009 = goFindLine(lines, /(?:des\.(?:NewCipher|NewTripleDESCipher)|rc4\.NewCipher|md5\.(?:New|Sum)|sha1\.(?:New|Sum))\s*\(/, (l, i) =>
        /(?:des\.(?:NewCipher|NewTripleDESCipher)|rc4\.NewCipher)\s*\(/.test(l) || /passw(?:or)?d|\bpwd\b/i.test(lines.slice(Math.max(0, i - 3), i + 4).join('\n')));
    if (idx_9009 !== -1) {
        const matchLineIdx = idx_9009;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Weak Cryptographic Algorithm in Go Source (MD5 / SHA1 / DES)";
        findings.push({
            id: `go9009-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9009,
            type: 'INFRA_DATABASE',
            title: "GO-09: Weak Cryptographic Algorithm in Go Source (MD5 / SHA1 / DES)",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Using crypto/md5, crypto/sha1, or crypto/des for hashing or encryption is cryptographically broken."
            ],
            remediationPrompt: "Replace md5.New() or sha1.New() with sha256.New().",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-09: Weak Cryptographic Algorithm in Go Source (MD5 / SHA1 / DES) at ${file.path}:${lineNum}`);
    }
    // GO-10: Insecure TLS Configuration with InsecureSkipVerify: true
    const reg_9010 = /InsecureSkipVerify\s*:\s*true\b/i;
    if (reg_9010.test(cleanContent)) {
        const linePattern = /InsecureSkipVerify\s*:\s*true/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure TLS Configuration with InsecureSkipVerify: true";
        findings.push({
            id: `go9010-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9010,
            type: 'INFRA_DATABASE',
            title: "GO-10: Insecure TLS Configuration with InsecureSkipVerify: true",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Setting InsecureSkipVerify: true in tls.Config disables server certificate validation, allowing Man-in-the-Middle attacks."
            ],
            remediationPrompt: "Remove InsecureSkipVerify: true or set to false to enforce TLS certificate validation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-10: Insecure TLS Configuration with InsecureSkipVerify: true at ${file.path}:${lineNum}`);
    }
    // GO-11: Critical I/O Error Ignored on Defer Close / Remove Operations
    const reg_9011 = /defer\s+(?:file|f|db|tx)\.Close\s*\(\s*\)/i;
    if (reg_9011.test(cleanContent)) {
        const linePattern = /defer\s+(?:file|f|db|tx)\.Close/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Critical I/O Error Ignored on Defer Close / Remove Operations";
        findings.push({
            id: `go9011-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9011,
            type: 'INFRA_DATABASE',
            title: "GO-11: Critical I/O Error Ignored on Defer Close / Remove Operations",
            severity: "LOW",
            category: "Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Ignoring error return on defer file.Close() or file write operations can hide disk write failures and data corruption."
            ],
            remediationPrompt: "Handle close errors or call file.Sync() before deferring close.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-11: Critical I/O Error Ignored on Defer Close / Remove Operations at ${file.path}:${lineNum}`);
    }
    // GO-12: Goroutine Leak on Unbuffered Channel Send Without Cancellation
    const reg_9012 = /go\s+func\s*\([^)]*\)\s*\{[\s\S]*?[a-zA-Z0-9_]+\s*<-\s*[a-zA-Z0-9_]+[\s\S]*?\}(?!\s*select)/i;
    if (reg_9012.test(cleanContent)) {
        const linePattern = /<-\s*[a-zA-Z0-9_]+/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Goroutine Leak on Unbuffered Channel Send Without Cancellation";
        findings.push({
            id: `go9012-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9012,
            type: 'INFRA_DATABASE',
            title: "GO-12: Goroutine Leak on Unbuffered Channel Send Without Cancellation",
            severity: "HIGH",
            category: "Concurrency Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Sending to unbuffered channels inside goroutines without a select case <-ctx.Done() branch permanently leaks goroutines."
            ],
            remediationPrompt: "Add select block with case <-ctx.Done() when sending to channels in goroutines.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-12: Goroutine Leak on Unbuffered Channel Send Without Cancellation at ${file.path}:${lineNum}`);
    }
    // GO-13: Server-Side Request Forgery (SSRF) via Dynamic HTTP Call
    const idx_9013 = (() => {
        const tainted = goRequestVars(lines);
        const call = /(?:http|[\w.]*[cC]lient)\.(?:Get|Post|PostForm|Head|NewRequest|NewRequestWithContext)\s*\(/;
        return goFindLine(lines, call, (_l, i) => {
            const text = callText(lines, i, call);
            const args = goSplitArgs(text);
            const urlArg = /NewRequestWithContext\s*\(/.test(text) ? args[2] : /NewRequest\s*\(/.test(text) ? args[1] : args[0];
            return !!urlArg && goTainted(urlArg, tainted);
        });
    })();
    if (idx_9013 !== -1) {
        const matchLineIdx = idx_9013;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Server-Side Request Forgery (SSRF) via Dynamic HTTP Call";
        findings.push({
            id: `go9013-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9013,
            type: 'INFRA_DATABASE',
            title: "GO-13: Server-Side Request Forgery (SSRF) via Dynamic HTTP Call",
            severity: "HIGH",
            category: "SSRF",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Making outbound HTTP requests using URLs derived directly from user request parameters enables SSRF."
            ],
            remediationPrompt: "Validate outbound URLs against allowed hosts before initiating http.Get.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-13: Server-Side Request Forgery (SSRF) via Dynamic HTTP Call at ${file.path}:${lineNum}`);
    }
    // GO-14: Unbounded Request Body Read (DoS Memory Exhaustion)
    const idx_9014 = goFindLine(lines, /(?:io|ioutil)\.ReadAll\s*\(\s*(?:r|req|c\.Request)\.Body\s*\)/, (_l, i) =>
        !lines.slice(goFuncStart(lines, i), i).some((x) => /MaxBytesReader\s*\(/.test(x)));
    if (idx_9014 !== -1) {
        const matchLineIdx = idx_9014;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unbounded Request Body Read (DoS Memory Exhaustion)";
        findings.push({
            id: `go9014-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9014,
            type: 'INFRA_DATABASE',
            title: "GO-14: Unbounded Request Body Read (DoS Memory Exhaustion)",
            severity: "HIGH",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Reading HTTP request bodies with io.ReadAll(r.Body) without http.MaxBytesReader allows attackers to exhaust server memory."
            ],
            remediationPrompt: "Wrap r.Body with http.MaxBytesReader before reading all bytes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-14: Unbounded Request Body Read (DoS Memory Exhaustion) at ${file.path}:${lineNum}`);
    }
    // GO-15: Weak Random Number Generator Used in Security Context (math/rand)
    const idx_9015 = (() => {
        const imp = /(?:^|\s)(?:(\w+)\s+)?"math\/rand(?:\/v2)?"/m.exec(cleanContent);
        if (!imp) return -1;
        const alias = imp[1] || 'rand';
        const secretName = /(?:token|password|passwd|secret|otp|nonce|salt|apikey|resetcode|verificationcode)/i;
        const call = new RegExp(`\\b${alias}\\.(?:Int|Intn|IntN|Int31|Int31n|Int63|Int63n|N|Uint32|Uint64|Read|Perm|Float64)\\s*\\(`);
        return goFindLine(lines, call, (l, i) => {
            const lhs = /^\s*(?:var\s+)?([\w.]+)(?:\s*,\s*\w+)?\s*(?::?=|\[)/.exec(l);
            if (lhs && secretName.test(lhs[1])) return true;
            for (let j = i; j >= 0; j--) {
                const fn = /^func\s+(?:\([^)]*\)\s*)?(\w+)/.exec(lines[j]);
                if (fn) return secretName.test(fn[1]);
            }
            return false;
        });
    })();
    if (idx_9015 !== -1) {
        const matchLineIdx = idx_9015;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Weak Random Number Generator Used in Security Context (math/rand)";
        findings.push({
            id: `go9015-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9015,
            type: 'INFRA_DATABASE',
            title: "GO-15: Weak Random Number Generator Used in Security Context (math/rand)",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Using math/rand instead of crypto/rand to generate tokens, passwords, or encryption keys generates predictable values."
            ],
            remediationPrompt: "Replace math/rand with crypto/rand for cryptographic operations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-15: Weak Random Number Generator Used in Security Context (math/rand) at ${file.path}:${lineNum}`);
    }
    // GO-16: Unsafe Pointer Usage (unsafe.Pointer)
    const reg_9016 = /unsafe\.Pointer\s*\(/i;
    if (reg_9016.test(cleanContent)) {
        const linePattern = /unsafe\.Pointer/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unsafe Pointer Usage (unsafe.Pointer)";
        findings.push({
            id: `go9016-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9016,
            type: 'INFRA_DATABASE',
            title: "GO-16: Unsafe Pointer Usage (unsafe.Pointer)",
            severity: "MEDIUM",
            category: "Memory Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Casting memory with unsafe.Pointer bypasses Go type safety and can result in memory corruption or arbitrary memory reads."
            ],
            remediationPrompt: "Refactor code to avoid unsafe.Pointer casts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-16: Unsafe Pointer Usage (unsafe.Pointer) at ${file.path}:${lineNum}`);
    }
    // GO-17: CORS Permissive Wildcard with AllowCredentials in Gin / Echo / Chi
    const idx_9017 = goFindLine(lines, /AllowOrigins\s*:\s*(?:\[\]string\s*\{\s*"\*"\s*\}|"\*")/, (_l, i) =>
        lines.slice(Math.max(0, i - 10), i + 11).some((x) => goIsCode(x) && /AllowCredentials\s*:\s*true\b/.test(x)));
    if (idx_9017 !== -1) {
        const matchLineIdx = idx_9017;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "CORS Permissive Wildcard with AllowCredentials in Gin / Echo / Chi";
        findings.push({
            id: `go9017-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9017,
            type: 'INFRA_DATABASE',
            title: "GO-17: CORS Permissive Wildcard with AllowCredentials in Gin / Echo / Chi",
            severity: "HIGH",
            category: "Cross-Origin Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Configuring AllowOrigins: []string{\"*\"} alongside AllowCredentials: true violates CORS spec and leaks sensitive user sessions."
            ],
            remediationPrompt: "Set explicit origin domains rather than wildcard \"*\" when AllowCredentials is true.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-17: CORS Permissive Wildcard with AllowCredentials in Gin / Echo / Chi at ${file.path}:${lineNum}`);
    }
    // GO-18: Gin Framework Running in Debug Mode in Production
    const idx_9018 = goFindLine(lines, /gin\.SetMode\s*\(\s*(?:gin\.DebugMode|"debug")\s*\)/);
    if (idx_9018 !== -1) {
        const matchLineIdx = idx_9018;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Gin Framework Running in Debug Mode in Production";
        findings.push({
            id: `go9018-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9018,
            type: 'INFRA_DATABASE',
            title: "GO-18: Gin Framework Running in Debug Mode in Production",
            severity: "HIGH",
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Setting gin.SetMode(gin.DebugMode) in production logs detailed route metrics, request headers, and stack traces."
            ],
            remediationPrompt: "Set gin.SetMode(gin.ReleaseMode) for production builds.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-18: Gin Framework Running in Debug Mode in Production at ${file.path}:${lineNum}`);
    }
    // GO-19: Open Redirect via http.Redirect with Unsanitized User Input
    const reg_9019 = /http\.Redirect\s*\(\s*[a-zA-Z0-9_.]+\s*,\s*[a-zA-Z0-9_.]+\s*,\s*r\.URL\.Query\(\)\.Get\(/i;
    if (reg_9019.test(cleanContent)) {
        const linePattern = /http\.Redirect/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Open Redirect via http.Redirect with Unsanitized User Input";
        findings.push({
            id: `go9019-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9019,
            type: 'INFRA_DATABASE',
            title: "GO-19: Open Redirect via http.Redirect with Unsanitized User Input",
            severity: "MEDIUM",
            category: "Open Redirect",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Calling http.Redirect with a URL obtained directly from request query parameters allows phishing redirects."
            ],
            remediationPrompt: "Validate target redirect URL is relative before calling http.Redirect.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-19: Open Redirect via http.Redirect with Unsanitized User Input at ${file.path}:${lineNum}`);
    }
    // GO-20: Missing Read/Write Timeout on http.Server (Slowloris DoS)
    const idx_9020 = (() => {
        for (let i = 0; i < lines.length; i++) {
            if (!goIsCode(lines[i]) || !/&?http\.Server\s*\{/.test(lines[i])) continue;
            const [s, e] = goBlockRange(lines, i);
            if (/Read(?:Header)?Timeout\s*:/.test(lines.slice(s, e + 1).join('\n'))) continue;
            const v = /(\w+)\s*:?=\s*&?http\.Server/.exec(lines[i]);
            if (v && new RegExp(`\\b${v[1]}\\.Read(?:Header)?Timeout\\s*=`).test(cleanContent)) continue;
            return i;
        }
        return -1;
    })();
    if (idx_9020 !== -1) {
        const matchLineIdx = idx_9020;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Missing Read/Write Timeout on http.Server (Slowloris DoS)";
        findings.push({
            id: `go9020-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9020,
            type: 'INFRA_DATABASE',
            title: "GO-20: Missing Read/Write Timeout on http.Server (Slowloris DoS)",
            severity: "HIGH",
            category: "Availability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Spawning an http.Server without ReadTimeout and WriteTimeout leaves the server vulnerable to Slowloris connection starvation."
            ],
            remediationPrompt: "Specify ReadTimeout, WriteTimeout, and IdleTimeout on http.Server structs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-20: Missing Read/Write Timeout on http.Server (Slowloris DoS) at ${file.path}:${lineNum}`);
    }
    // GO-21: Hardcoded Database Connection String with Credentials in Go
    const idx_9021 = goFindLine(lines, /(?:postgres|postgresql|mysql|mariadb|mongodb|redis|amqp)(?:\+\w+)?:\/\/|"\w+:[^@"\s]+@tcp\(/i, (l) => hasDbUrlWithRealPassword(l));
    if (idx_9021 !== -1) {
        const matchLineIdx = idx_9021;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Hardcoded Database Connection String with Credentials in Go";
        findings.push({
            id: `go9021-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9021,
            type: 'INFRA_DATABASE',
            title: "GO-21: Hardcoded Database Connection String with Credentials in Go",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Committed database credentials in connection URIs risk unauthorized database access."
            ],
            remediationPrompt: "Use environment variables to inject database credentials at runtime.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-21: Hardcoded Database Connection String with Credentials in Go at ${file.path}:${lineNum}`);
    }
    // GO-22: Insecure JWT Parsing Without Signature Verification
    const idx_9022 = goFindLine(lines, /\.ParseUnverified\s*\(/);
    if (idx_9022 !== -1) {
        const matchLineIdx = idx_9022;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure JWT Parsing Without Signature Verification";
        findings.push({
            id: `go9022-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9022,
            type: 'INFRA_DATABASE',
            title: "GO-22: Insecure JWT Parsing Without Signature Verification",
            severity: "CRITICAL",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Calling jwt.ParseUnverified or skipping Keyfunc validation accepts forged JWT tokens from untrusted clients."
            ],
            remediationPrompt: "Replace ParseUnverified with jwt.Parse providing a strict key validation function.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-22: Insecure JWT Parsing Without Signature Verification at ${file.path}:${lineNum}`);
    }
    // GO-23: Insecure SSH Host Key Validation (ssh.InsecureIgnoreHostKey)
    const idx_9023 = goFindLine(lines, /ssh\.InsecureIgnoreHostKey\s*\(\s*\)/);
    if (idx_9023 !== -1) {
        const matchLineIdx = idx_9023;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure SSH Host Key Validation (ssh.InsecureIgnoreHostKey)";
        findings.push({
            id: `go9023-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9023,
            type: 'INFRA_DATABASE',
            title: "GO-23: Insecure SSH Host Key Validation (ssh.InsecureIgnoreHostKey)",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Using ssh.InsecureIgnoreHostKey() accepts any remote SSH host key without verification, enabling MitM attacks."
            ],
            remediationPrompt: "Replace InsecureIgnoreHostKey with knownhosts host key callback.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-23: Insecure SSH Host Key Validation (ssh.InsecureIgnoreHostKey) at ${file.path}:${lineNum}`);
    }
    // GO-24: Archive Path Traversal (Zip Slip / Tar Slip in Go)
    const idx_9024 = (() => {
        if (!/"archive\/(?:zip|tar)"/.test(cleanContent)) return -1;
        if (/filepath\.IsLocal\s*\(|strings\.HasPrefix\s*\([^)]*filepath\.Clean|filepath\.Rel\s*\(|strings\.Contains\s*\([^)]*"\.\."|SecureJoin/.test(cleanContent)) return -1;
        return goFindLine(lines, /(?:filepath|path)\.Join\s*\([^)]*\b\w+\.Name\b(?!\s*\()|os\.(?:Create|OpenFile|MkdirAll)\s*\(\s*\w+\.Name\b(?!\s*\()/);
    })();
    if (idx_9024 !== -1) {
        const matchLineIdx = idx_9024;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Archive Path Traversal (Zip Slip / Tar Slip in Go)";
        findings.push({
            id: `go9024-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9024,
            type: 'INFRA_DATABASE',
            title: "GO-24: Archive Path Traversal (Zip Slip / Tar Slip in Go)",
            severity: "HIGH",
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Extracting zip or tar archives directly using file headers containing \"../\" enables overwriting arbitrary files."
            ],
            remediationPrompt: "Validate target file path remains within target extraction directory before creating files.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-24: Archive Path Traversal (Zip Slip / Tar Slip in Go) at ${file.path}:${lineNum}`);
    }
    // GO-25: XML External Entity (XXE) via Insecure Go XML Parser
    const reg_9025 = /decoder\.Entity\s*=[\s\S]*?xml\.NewDecoder/i;
    if (reg_9025.test(cleanContent)) {
        const linePattern = /decoder\.Entity/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "XML External Entity (XXE) via Insecure Go XML Parser";
        findings.push({
            id: `go9025-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9025,
            type: 'INFRA_DATABASE',
            title: "GO-25: XML External Entity (XXE) via Insecure Go XML Parser",
            severity: "HIGH",
            category: "XML Entity Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Parsing untrusted XML documents using xml.Decoder with custom entity resolution enabled can allow XXE file disclosure."
            ],
            remediationPrompt: "Avoid setting Entity table with external resource resolvers on xml.Decoder.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-25: XML External Entity (XXE) via Insecure Go XML Parser at ${file.path}:${lineNum}`);
    }
    // GO-26: Unhandled Goroutine Panic Crashing Process (Missing recover)
    const reg_9026 = /go\s+func\s*\([^)]*\)\s*\{(?!.*recover\s*\(\s*\))/i;
    if (reg_9026.test(cleanContent)) {
        const linePattern = /go\s+func/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unhandled Goroutine Panic Crashing Process (Missing recover)";
        findings.push({
            id: `go9026-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9026,
            type: 'INFRA_DATABASE',
            title: "GO-26: Unhandled Goroutine Panic Crashing Process (Missing recover)",
            severity: "MEDIUM",
            category: "Availability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Spawning background goroutines without defer recover() causes the entire server process to crash on unhandled panics."
            ],
            remediationPrompt: "Add panic recovery handler inside spawned background goroutine.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-26: Unhandled Goroutine Panic Crashing Process (Missing recover) at ${file.path}:${lineNum}`);
    }
    // GO-27: Nil Pointer Dereference on Unchecked Error Return
    const reg_9027 = /([a-zA-Z0-9_]+),\s*err\s*:=\s*[a-zA-Z0-9_.]+\([^)]*\)[\s\S]{1,60}?\1\.[a-zA-Z0-9_]+/i;
    if (reg_9027.test(cleanContent)) {
        const linePattern = /err\s*:=/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Nil Pointer Dereference on Unchecked Error Return";
        findings.push({
            id: `go9027-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9027,
            type: 'INFRA_DATABASE',
            title: "GO-27: Nil Pointer Dereference on Unchecked Error Return",
            severity: "MEDIUM",
            category: "Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Accessing return values without checking if err != nil causes fatal nil pointer dereference panics."
            ],
            remediationPrompt: "Add if err != nil check before dereferencing returned struct pointer.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-27: Nil Pointer Dereference on Unchecked Error Return at ${file.path}:${lineNum}`);
    }
    // GO-28: Missing CSRF Middleware in Web Handlers
    const reg_9028 = /(?:http\.HandleFunc|r\.POST|r\.PUT)\s*\([^{]*\{[\s\S]*?r\.ParseForm\(\)(?!.*csrf)/i;
    if (reg_9028.test(cleanContent)) {
        const linePattern = /r\.ParseForm/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Missing CSRF Middleware in Web Handlers";
        findings.push({
            id: `go9028-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9028,
            type: 'INFRA_DATABASE',
            title: "GO-28: Missing CSRF Middleware in Web Handlers",
            severity: "HIGH",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Serving HTML form state changes without CSRF protection tokens enables cross-site request forgery."
            ],
            remediationPrompt: "Attach CSRF middleware to router endpoints handling form mutations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-28: Missing CSRF Middleware in Web Handlers at ${file.path}:${lineNum}`);
    }
    // GO-29: Sensitive Information Leak via Insecure Log Output in Go
    const idx_9029 = goFindLine(lines, /\blog\.(?:Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf)\s*\(/, (l) => {
        const args = /log\.\w+\s*\((.*)$/.exec(l.replace(/"(?:[^"\\]|\\.)*"|`[^`]*`/g, '""'));
        return !!args && /(?<!len\()(?:^|[^\w.])(?:\w+\.)*\w*(?:password|passwd|secret|token|apikey|api_key)\b(?!\s*\()/i.test(args[1]);
    });
    if (idx_9029 !== -1) {
        const matchLineIdx = idx_9029;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Sensitive Information Leak via Insecure Log Output in Go";
        findings.push({
            id: `go9029-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9029,
            type: 'INFRA_DATABASE',
            title: "GO-29: Sensitive Information Leak via Insecure Log Output in Go",
            severity: "HIGH",
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Logging passwords, auth tokens, or private keys directly to application logs risks credential theft."
            ],
            remediationPrompt: "Redact sensitive credentials from log formatting strings.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-29: Sensitive Information Leak via Insecure Log Output in Go at ${file.path}:${lineNum}`);
    }
    // GO-30: GORM Unscoped Query Disabling Soft-Delete Protection
    const reg_9030 = /(?:db|tx)\.Unscoped\s*\(\s*\)\.(?:Delete|Find|Where)/i;
    if (reg_9030.test(cleanContent)) {
        const linePattern = /\.Unscoped\s*\(\s*\)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "GORM Unscoped Query Disabling Soft-Delete Protection";
        findings.push({
            id: `go9030-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9030,
            type: 'INFRA_DATABASE',
            title: "GO-30: GORM Unscoped Query Disabling Soft-Delete Protection",
            severity: "MEDIUM",
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Calling db.Unscoped() bypasses GORM soft-delete protection, risking accidental permanent record deletion."
            ],
            remediationPrompt: "Remove db.Unscoped() to respect soft-delete DeletedAt timestamps.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-30: GORM Unscoped Query Disabling Soft-Delete Protection at ${file.path}:${lineNum}`);
    }
    // GO-31: Unbounded Goroutine Spawning in HTTP Handler (Worker Pool Missing)
    const reg_9031 = /func\s+[a-zA-Z0-9_]*Handler\s*\([^)]*\)[\s\S]*?go\s+[a-zA-Z0-9_]+\s*\(/i;
    if (reg_9031.test(cleanContent)) {
        const linePattern = /go\s+[a-zA-Z0-9_]+\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unbounded Goroutine Spawning in HTTP Handler (Worker Pool Missing)";
        findings.push({
            id: `go9031-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9031,
            type: 'INFRA_DATABASE',
            title: "GO-31: Unbounded Goroutine Spawning in HTTP Handler (Worker Pool Missing)",
            severity: "HIGH",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Spawning unmetered goroutines for each HTTP request allows attackers to trigger memory exhaustion and OOM crashes."
            ],
            remediationPrompt: "Offload requests to a worker pool with a maximum concurrency limit.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-31: Unbounded Goroutine Spawning in HTTP Handler (Worker Pool Missing) at ${file.path}:${lineNum}`);
    }
    // GO-32: Insecure Cookie Configuration Missing HttpOnly or Secure Flag
    const reg_9032 = /&http\.Cookie\s*\{[\s\S]*?(?:HttpOnly\s*:\s*false|Secure\s*:\s*false)/i;
    if (reg_9032.test(cleanContent)) {
        const linePattern = /&http\.Cookie/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure Cookie Configuration Missing HttpOnly or Secure Flag";
        findings.push({
            id: `go9032-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9032,
            type: 'INFRA_DATABASE',
            title: "GO-32: Insecure Cookie Configuration Missing HttpOnly or Secure Flag",
            severity: "MEDIUM",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Creating HTTP cookies without HttpOnly: true or Secure: true exposes session tokens to script theft and MITM."
            ],
            remediationPrompt: "Set HttpOnly: true and Secure: true on http.Cookie.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-32: Insecure Cookie Configuration Missing HttpOnly or Secure Flag at ${file.path}:${lineNum}`);
    }
    // GO-33: Weak RSA Key Generation (< 2048 Bits) in Go
    const idx_9033 = goFindLine(lines, /rsa\.GenerateKey\s*\([^,]+,\s*(?:512|768|1024|1536)\s*\)/);
    if (idx_9033 !== -1) {
        const matchLineIdx = idx_9033;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Weak RSA Key Generation (< 2048 Bits) in Go";
        findings.push({
            id: `go9033-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9033,
            type: 'INFRA_DATABASE',
            title: "GO-33: Weak RSA Key Generation (< 2048 Bits) in Go",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Generating RSA keys with less than 2048 bits (e.g. 1024 bits) violates modern cryptographic standards."
            ],
            remediationPrompt: "Increase RSA key size parameter to 2048 or higher.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-33: Weak RSA Key Generation (< 2048 Bits) in Go at ${file.path}:${lineNum}`);
    }
    // GO-34: Hardcoded AWS Access Key ID in Go Source
    const idx_9034 = goFindLine(lines, /["'`]AKIA[0-9A-Z]{16}["'`]/, (l) => !/AKIAIOSFODNN7EXAMPLE/.test(l));
    if (idx_9034 !== -1) {
        const matchLineIdx = idx_9034;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Hardcoded AWS Access Key ID in Go Source";
        findings.push({
            id: `go9034-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9034,
            type: 'INFRA_DATABASE',
            title: "GO-34: Hardcoded AWS Access Key ID in Go Source",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Hardcoded AWS credentials committed in Go source files expose cloud infrastructure."
            ],
            remediationPrompt: "Remove hardcoded AWS keys and rely on AWS credential provider chain.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-34: Hardcoded AWS Access Key ID in Go Source at ${file.path}:${lineNum}`);
    }
    // GO-35: Cgo Memory Leak or Missing C.free Call
    const idx_9035 = (() => {
        for (let i = 0; i < lines.length; i++) {
            if (!goIsCode(lines[i])) continue;
            const m = /(\w+)\s*:?=\s*C\.CString\s*\(/.exec(lines[i]);
            if (m) {
                const freed = new RegExp(`C\\.free\\s*\\(\\s*unsafe\\.Pointer\\s*\\(\\s*${m[1]}\\s*\\)`);
                let ok = false;
                for (let j = i; j < lines.length && !/^\}/.test(lines[j]); j++) if (freed.test(lines[j])) { ok = true; break; }
                if (!ok) return i;
            } else if (/C\.\w+\s*\([^)]*C\.CString\s*\(/.test(lines[i])) {
                return i;
            }
        }
        return -1;
    })();
    if (idx_9035 !== -1) {
        const matchLineIdx = idx_9035;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Cgo Memory Leak or Missing C.free Call";
        findings.push({
            id: `go9035-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9035,
            type: 'INFRA_DATABASE',
            title: "GO-35: Cgo Memory Leak or Missing C.free Call",
            severity: "HIGH",
            category: "Memory Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Allocating C memory via C.CString without defer C.free(unsafe.Pointer(cstr)) causes unrecoverable memory leaks."
            ],
            remediationPrompt: "Add defer C.free(unsafe.Pointer(cstr)) after C.CString.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-35: Cgo Memory Leak or Missing C.free Call at ${file.path}:${lineNum}`);
    }
    // GO-36: Missing Rate Limiting on Authentication Handlers in Go
    const reg_9036 = /func\s+[a-zA-Z0-9_]*(?:Login|SignIn|Authenticate|Token)Handler[\s\S]*?(?!rate\.NewLimiter)/i;
    if (reg_9036.test(cleanContent)) {
        const linePattern = /func\s+[a-zA-Z0-9_]*(?:Login|SignIn|Authenticate)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Missing Rate Limiting on Authentication Handlers in Go";
        findings.push({
            id: `go9036-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9036,
            type: 'INFRA_DATABASE',
            title: "GO-36: Missing Rate Limiting on Authentication Handlers in Go",
            severity: "MEDIUM",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Login and token endpoints without rate limiting are susceptible to credential stuffing and brute force attacks."
            ],
            remediationPrompt: "Add rate limiting middleware to authentication route handlers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-36: Missing Rate Limiting on Authentication Handlers in Go at ${file.path}:${lineNum}`);
    }
    // GO-37: Context Leak via Missing defer cancel() Call
    const reg_9037 = /context\.(?:WithCancel|WithTimeout|WithDeadline)\s*\([\s\S]*?(?!defer\s+cancel\s*\(\s*\))/i;
    if (reg_9037.test(cleanContent)) {
        const linePattern = /context\.(?:WithCancel|WithTimeout|WithDeadline)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Context Leak via Missing defer cancel() Call";
        findings.push({
            id: `go9037-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9037,
            type: 'INFRA_DATABASE',
            title: "GO-37: Context Leak via Missing defer cancel() Call",
            severity: "MEDIUM",
            category: "Resource Leakage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Calling context.WithCancel or context.WithTimeout without defer cancel() permanently leaks associated timers and goroutines."
            ],
            remediationPrompt: "Add defer cancel() immediately after context creation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-37: Context Leak via Missing defer cancel() Call at ${file.path}:${lineNum}`);
    }
    // GO-38: Unsafe Dynamic Plugin Loading via plugin.Open()
    const idx_9038 = (() => {
        const tainted = goRequestVars(lines);
        return goFindLine(lines, /plugin\.Open\s*\(/, (_l, i) => {
            const args = goSplitArgs(callText(lines, i, /plugin\.Open\s*\(/));
            return !!args[0] && goTainted(args[0], tainted);
        });
    })();
    if (idx_9038 !== -1) {
        const matchLineIdx = idx_9038;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unsafe Dynamic Plugin Loading via plugin.Open()";
        findings.push({
            id: `go9038-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9038,
            type: 'INFRA_DATABASE',
            title: "GO-38: Unsafe Dynamic Plugin Loading via plugin.Open()",
            severity: "CRITICAL",
            category: "Code Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Loading shared object plugins via plugin.Open() using user-controlled file paths allows arbitrary code execution."
            ],
            remediationPrompt: "Validate plugin paths against a strictly controlled whitelist directory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-38: Unsafe Dynamic Plugin Loading via plugin.Open() at ${file.path}:${lineNum}`);
    }
    // GO-39: Insecure gRPC Connection via grpc.WithInsecure()
    const idx_9039 = goFindLine(lines, /grpc\.WithInsecure\s*\(\s*\)/);
    if (idx_9039 !== -1) {
        const matchLineIdx = idx_9039;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure gRPC Connection via grpc.WithInsecure()";
        findings.push({
            id: `go9039-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9039,
            type: 'INFRA_DATABASE',
            title: "GO-39: Insecure gRPC Connection via grpc.WithInsecure()",
            severity: "HIGH",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: grpc.WithInsecure() disables transport encryption, exposing RPC payloads and credentials to network sniffing."
            ],
            remediationPrompt: "Replace grpc.WithInsecure() with secure TLS transport credentials.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-39: Insecure gRPC Connection via grpc.WithInsecure() at ${file.path}:${lineNum}`);
    }
    // GO-40: Insecure Temporary File Creation via Path Concatenation
    const reg_9040 = /os\.Create\s*\(\s*(?:os\.TempDir\(\)|filepath\.Join\(os\.TempDir)/i;
    if (reg_9040.test(cleanContent)) {
        const linePattern = /os\.Create\s*\(.*TempDir/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure Temporary File Creation via Path Concatenation";
        findings.push({
            id: `go9040-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9040,
            type: 'INFRA_DATABASE',
            title: "GO-40: Insecure Temporary File Creation via Path Concatenation",
            severity: "MEDIUM",
            category: "Race Condition",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Constructing temporary file paths with os.TempDir() + \"/filename\" is vulnerable to symlink race conditions."
            ],
            remediationPrompt: "Replace manual path concatenation with os.CreateTemp.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-40: Insecure Temporary File Creation via Path Concatenation at ${file.path}:${lineNum}`);
    }
    // GO-41: LDAP Injection via Formatted Search Query in Go
    const idx_9041 = /ldap\.NewSearchRequest\s*\(/.test(cleanContent) ? goFindLine(lines, /fmt\.Sprintf\s*\(\s*"[^"]*\(\w+=[^"]*%[sv]/, (l) => !/ldap\.EscapeFilter\s*\(/.test(l)) : -1;
    if (idx_9041 !== -1) {
        const matchLineIdx = idx_9041;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "LDAP Injection via Formatted Search Query in Go";
        findings.push({
            id: `go9041-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9041,
            type: 'INFRA_DATABASE',
            title: "GO-41: LDAP Injection via Formatted Search Query in Go",
            severity: "HIGH",
            category: "LDAP Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Formatting LDAP filter queries with fmt.Sprintf without escaping special characters allows LDAP injection."
            ],
            remediationPrompt: "Escape filter arguments with ldap.EscapeFilter before querying.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-41: LDAP Injection via Formatted Search Query in Go at ${file.path}:${lineNum}`);
    }
    // GO-42: XPath Injection via Unsanitized Query Strings in Go
    const idx_9042 = goFindLine(lines, /(?:xpath\.(?:Compile|MustCompile)|xmlquery\.(?:Find|FindOne|Query|QueryAll)|htmlquery\.(?:Find|FindOne|Query|QueryAll))\s*\([^)]*(?:fmt\.Sprintf\s*\(|"\s*\+)/);
    if (idx_9042 !== -1) {
        const matchLineIdx = idx_9042;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "XPath Injection via Unsanitized Query Strings in Go";
        findings.push({
            id: `go9042-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9042,
            type: 'INFRA_DATABASE',
            title: "GO-42: XPath Injection via Unsanitized Query Strings in Go",
            severity: "HIGH",
            category: "XPath Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Constructing XPath queries using string interpolation with unsanitized user inputs enables XPath injection."
            ],
            remediationPrompt: "Sanitize user inputs before executing dynamic XPath queries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-42: XPath Injection via Unsanitized Query Strings in Go at ${file.path}:${lineNum}`);
    }
    // GO-43: Catastrophic Backtracking Regular Expression in Go Source
    const reg_9043 = /regexp\.(?:MustCompile|Compile)\s*\(\s*`[^`]*\([^)]+[+*]\)[+*]/i;
    if (reg_9043.test(cleanContent)) {
        const linePattern = /regexp\.(?:MustCompile|Compile)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Catastrophic Backtracking Regular Expression in Go Source";
        findings.push({
            id: `go9043-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9043,
            type: 'INFRA_DATABASE',
            title: "GO-43: Catastrophic Backtracking Regular Expression in Go Source",
            severity: "MEDIUM",
            category: "Regular Expression Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Nested quantifiers in regexp patterns evaluate with exponential complexity on crafted inputs."
            ],
            remediationPrompt: "Refactor regexp pattern to eliminate nested quantifier groups.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-43: Catastrophic Backtracking Regular Expression in Go Source at ${file.path}:${lineNum}`);
    }
    // GO-44: HTTP Header Injection / Response Splitting via CRLF
    const reg_9044 = /w\.Header\(\)\.Set\s*\([^,]+,\s*r\.URL\.Query\(\)/i;
    if (reg_9044.test(cleanContent)) {
        const linePattern = /w\.Header\(\)\.Set/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "HTTP Header Injection / Response Splitting via CRLF";
        findings.push({
            id: `go9044-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9044,
            type: 'INFRA_DATABASE',
            title: "GO-44: HTTP Header Injection / Response Splitting via CRLF",
            severity: "MEDIUM",
            category: "Header Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Setting HTTP response headers directly from user inputs without stripping \\r\\n characters allows header injection."
            ],
            remediationPrompt: "Sanitize header values by removing CR and LF characters.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-44: HTTP Header Injection / Response Splitting via CRLF at ${file.path}:${lineNum}`);
    }
    // GO-45: Unsafe Deserialization via Gob Decoder on Untrusted Data
    const idx_9045 = goFindLine(lines, /gob\.NewDecoder\s*\(\s*(?:r|req|c\.Request)\.Body\s*\)/);
    if (idx_9045 !== -1) {
        const matchLineIdx = idx_9045;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unsafe Deserialization via Gob Decoder on Untrusted Data";
        findings.push({
            id: `go9045-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9045,
            type: 'INFRA_DATABASE',
            title: "GO-45: Unsafe Deserialization via Gob Decoder on Untrusted Data",
            severity: "HIGH",
            category: "Insecure Deserialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Decoding gob streams from untrusted network sources into complex registered interface types risks resource exhaustion or panic."
            ],
            remediationPrompt: "Adopt Protocol Buffers or JSON for external data interchange.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-45: Unsafe Deserialization via Gob Decoder on Untrusted Data at ${file.path}:${lineNum}`);
    }
    // GO-46: Deprecated TLS Minimum Version (TLS 1.0 / TLS 1.1)
    const idx_9046 = goFindLine(lines, /MinVersion\s*:\s*tls\.Version(?:TLS1[01]|SSL30)\b/);
    if (idx_9046 !== -1) {
        const matchLineIdx = idx_9046;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Deprecated TLS Minimum Version (TLS 1.0 / TLS 1.1)";
        findings.push({
            id: `go9046-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9046,
            type: 'INFRA_DATABASE',
            title: "GO-46: Deprecated TLS Minimum Version (TLS 1.0 / TLS 1.1)",
            severity: "HIGH",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Configuring tls.Config with MinVersion set to VersionTLS10 or VersionTLS11 exposes connections to obsolete cipher suites."
            ],
            remediationPrompt: "Configure MinVersion: tls.VersionTLS12 or higher in tls.Config.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-46: Deprecated TLS Minimum Version (TLS 1.0 / TLS 1.1) at ${file.path}:${lineNum}`);
    }
    // GO-47: Insecure Redis Connection Without Password Authentication
    const reg_9047 = /&redis\.Options\s*\{[\s\S]*?Password\s*:\s*["']["']/i;
    if (reg_9047.test(cleanContent)) {
        const linePattern = /&redis\.Options/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Insecure Redis Connection Without Password Authentication";
        findings.push({
            id: `go9047-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9047,
            type: 'INFRA_DATABASE',
            title: "GO-47: Insecure Redis Connection Without Password Authentication",
            severity: "HIGH",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Connecting to Redis servers with empty password authentication allows unauthenticated access if port is exposed."
            ],
            remediationPrompt: "Supply a non-empty Password from environment variables in redis.Options.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-47: Insecure Redis Connection Without Password Authentication at ${file.path}:${lineNum}`);
    }
    // GO-48: Missing Authorization Check on Admin Handler in Go
    const reg_9048 = /func\s+[a-zA-Z0-9_]*Admin[a-zA-Z0-9_]*Handler\s*\([^)]*\)[\s\S]*?(?!.*is_admin|.*isAdmin|.*role)/i;
    if (reg_9048.test(cleanContent)) {
        const linePattern = /func\s+[a-zA-Z0-9_]*Admin/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Missing Authorization Check on Admin Handler in Go";
        findings.push({
            id: `go9048-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9048,
            type: 'INFRA_DATABASE',
            title: "GO-48: Missing Authorization Check on Admin Handler in Go",
            severity: "HIGH",
            category: "Broken Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Admin route handlers without session role verification allow standard users to perform privileged administrative actions."
            ],
            remediationPrompt: "Add role validation check or admin middleware to handler.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-48: Missing Authorization Check on Admin Handler in Go at ${file.path}:${lineNum}`);
    }
    // GO-49: Unbuffered Channel Deadlock Risk in Single Goroutine Flow
    const reg_9049 = /ch\s*:=\s*make\(chan\s+[a-zA-Z0-9_]+\)[\s\S]{1,40}?ch\s*<-/i;
    if (reg_9049.test(cleanContent)) {
        const linePattern = /make\(chan/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Unbuffered Channel Deadlock Risk in Single Goroutine Flow";
        findings.push({
            id: `go9049-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9049,
            type: 'INFRA_DATABASE',
            title: "GO-49: Unbuffered Channel Deadlock Risk in Single Goroutine Flow",
            severity: "MEDIUM",
            category: "Concurrency Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Sending to an unbuffered channel in the same goroutine that reads it causes an immediate fatal deadlock."
            ],
            remediationPrompt: "Use buffered channel make(chan T, 1) or spawn a goroutine for channel send.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-49: Unbuffered Channel Deadlock Risk in Single Goroutine Flow at ${file.path}:${lineNum}`);
    }
    // GO-50: Verbose Stack Trace Exposure in HTTP Response (Echo / Fiber)
    const idx_9050 = goFindLine(lines, /(?:\bw\.Write\s*\(|\b(?:c|ctx)\.(?:String|SendString|JSON|AbortWithStatusJSON|IndentedJSON|Data)\s*\(|\.SendString\s*\(|fmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,|http\.Error\s*\(\s*w\s*,)[^;]*debug\.Stack\s*\(\s*\)/);
    if (idx_9050 !== -1) {
        const matchLineIdx = idx_9050;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('//'))?.trim() || "Verbose Stack Trace Exposure in HTTP Response (Echo / Fiber)";
        findings.push({
            id: `go9050-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9050,
            type: 'INFRA_DATABASE',
            title: "GO-50: Verbose Stack Trace Exposure in HTTP Response (Echo / Fiber)",
            severity: "HIGH",
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Go source in ${file.path}:${lineNum}.`,
                "Detected microservice resilience/security violation: Printing runtime stack traces directly into HTTP error responses leaks internal file paths and system details."
            ],
            remediationPrompt: "Return sanitized error messages to HTTP clients; log stack traces to internal loggers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GO AUDIT] Found GO-50: Verbose Stack Trace Exposure in HTTP Response (Echo / Fiber) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}

/** A Go source line that is code (not blank, not a // comment). */
function goIsCode(line: string): boolean {
    const t = line.trim();
    return t !== '' && !t.startsWith('//');
}

/** First code line matching `re` (and `ok`, when given), or -1. */
function goFindLine(lines: string[], re: RegExp, ok?: (line: string, idx: number) => boolean): number {
    return lines.findIndex((l, i) => goIsCode(l) && re.test(l) && (!ok || ok(l, i)));
}

/** Same text with string-literal contents blanked to spaces (length preserved). */
const blankGoStrings = (s: string) =>
    s.replace(/"(?:[^"\\]|\\.)*"|`[^`]*`|'(?:[^'\\]|\\.)*'/g, (m) => m[0] + ' '.repeat(m.length - 2) + m[m.length - 1]);

/** Text of the call matched by `re` on line `idx`, up to its balanced closing parenthesis (max 15 lines). */
function callText(lines: string[], idx: number, re: RegExp): string {
    const m = re.exec(lines[idx]);
    let out = '';
    let depth = 0;
    for (let i = idx; i < Math.min(lines.length, idx + 15); i++) {
        const seg = i === idx && m ? lines[i].slice(m.index) : lines[i];
        const structure = blankGoStrings(seg);
        for (let c = 0; c < seg.length; c++) {
            out += seg[c];
            if (structure[c] === '(') depth++;
            else if (structure[c] === ')' && --depth === 0) return out;
        }
        out += '\n';
    }
    return out;
}

/** Top-level arguments of a call text such as `exec.Command("sh", "-c", x)`. */
function goSplitArgs(text: string): string[] {
    const open = text.indexOf('(');
    if (open === -1) return [];
    const args: string[] = [];
    let depth = 0;
    let cur = '';
    let quote = '';
    for (let i = open + 1; i < text.length; i++) {
        const ch = text[i];
        if (quote) {
            cur += ch;
            if (ch === '\\' && quote !== '`') { cur += text[++i] ?? ''; continue; }
            if (ch === quote) quote = '';
            continue;
        }
        if (ch === '"' || ch === '`' || ch === "'") { quote = ch; cur += ch; continue; }
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        if (ch === ')' || ch === ']' || ch === '}') {
            if (depth === 0) break;
            depth--;
        }
        if (ch === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
        cur += ch;
    }
    if (cur.trim()) args.push(cur.trim());
    return args;
}

/** [start, end] lines of the brace block opened on line `idx`. */
function goBlockRange(lines: string[], idx: number): [number, number] {
    let depth = 0;
    let opened = false;
    for (let i = idx; i < lines.length; i++) {
        for (const ch of blankGoStrings(lines[i])) {
            if (ch === '{') { depth++; opened = true; }
            else if (ch === '}' && opened && --depth === 0) return [idx, i];
        }
    }
    return [idx, lines.length - 1];
}

/** Line index of the `func` declaration enclosing line `idx` (0 when none). */
function goFuncStart(lines: string[], idx: number): number {
    for (let j = idx; j >= 0; j--) if (/^func\s/.test(lines[j])) return j;
    return 0;
}

/** Request accessors of net/http, Gin, Echo, Fiber, chi and gorilla/mux. */
const GO_REQUEST_EXPR = /(?:\br|\breq)\.URL\.Query\(\)\.Get\(|(?:\br|\breq)\.(?:FormValue|PostFormValue)\(|\bc\.(?:Query|DefaultQuery|PostForm|DefaultPostForm|Param|QueryParam|FormValue|Params)\(|chi\.URLParam\(|mux\.Vars\((?:r|req)\)\[/;
/** Calls that turn request input into a safe value (or a lookup keyed by it). */
const GO_SANITIZER = /filepath\.Base\(|strconv\.(?:Atoi|ParseInt|ParseUint|ParseBool|Quote)\(|ldap\.EscapeFilter\(|net\.ParseIP\(|url\.(?:Parse|PathEscape|QueryEscape)\(|uuid\.Parse\(|html\.EscapeString\(|^\s*[\w.]+\[[^\]]+\]\s*$/;

/** True when `expr` reads request input directly or through a request-derived variable. */
function goTainted(expr: string, tainted: Set<string>): boolean {
    const code = blankGoStrings(expr);
    if (GO_SANITIZER.test(code)) return false;
    if (GO_REQUEST_EXPR.test(code)) return true;
    for (const m of code.matchAll(/(?<![\w.])([a-zA-Z_]\w*)\b(?!\s*\()/g)) if (tainted.has(m[1])) return true;
    return false;
}

/** Variables assigned from request input in this file (propagated through plain assignments). */
function goRequestVars(lines: string[]): Set<string> {
    const names = new Set<string>();
    for (let pass = 0; pass < 3; pass++) {
        for (const l of lines) {
            if (!goIsCode(l)) continue;
            const m = /^\s*(?:var\s+)?(\w+)(?:\s*,\s*\w+)?\s*(?:\w+\s*)?:?=\s*(.+)$/.exec(l);
            if (m && m[1] !== '_' && !names.has(m[1]) && goTainted(m[2], names)) names.add(m[1]);
        }
    }
    return names;
}

/** A database / broker URL or MySQL DSN with an inline password that is not a local-dev default or placeholder. */
function hasDbUrlWithRealPassword(line: string): boolean {
    const m = /(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)(?:\+\w+)?:\/\/([^:/\s'"@`]*):([^@/\s'"`]+)@([^/:\s'"`?]+)/i.exec(line)
        || /"(\w+):([^@"\s]+)@tcp\(([^:)]+)/.exec(line);
    if (!m) return false;
    const [, , password, host] = m;
    if (/^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)$/i.test(host)) return false;
    return !/[{}$<>%]|^(?:password|pass|passwd|pwd|secret|changeme|change_?me|example|x{3,}|\*+|user|postgres|root|admin)$/i.test(password);
}
