/**
 * Zelsis Master evaluatePythonEnterpriseRules Engine (50 Rules)
 * Rules PY-SEC-01 to PY-SEC-50 (Rule IDs 8801 to 8850).
 * Zero artificial sentinels. Real regex patterns with exact line detection.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface PythonEnterpriseRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluatePythonEnterpriseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): PythonEnterpriseRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-python paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isPy = lowerPath.endsWith(".py") || lowerPath.endsWith("requirements.txt") || lowerPath.endsWith("pipfile") || lowerPath.endsWith("pyproject.toml");
    if (!isPy)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // PY-SEC-01: Unsafe Pickle Deserialization (Remote Code Execution)
    const reg_8801 = /(?:pickle|cPickle|_pickle)\.(?:loads?|Unpickler)/i;
    if (reg_8801.test(cleanContent)) {
        const linePattern = /(?:pickle|cPickle|_pickle)\.(?:loads?|Unpickler)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Unsafe Pickle Deserialization (Remote Code Execution)";
        findings.push({
            id: `py8801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8801,
            type: 'SECURITY',
            title: "PY-SEC-01: Unsafe Pickle Deserialization (Remote Code Execution)",
            severity: "CRITICAL",
            category: "Insecure Deserialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using pickle.loads(), cPickle, or _pickle on untrusted user payloads enables arbitrary bytecode execution."
            ],
            remediationPrompt: "Replace pickle with safe serialization formats like JSON, MessagePack, or Protocol Buffers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-01: Unsafe Pickle Deserialization (Remote Code Execution) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-02: Insecure PyYAML load() Without SafeLoader
    const reg_8802 = /yaml\.load\s*\([^,)]*\)(?!\s*,\s*Loader\s*=\s*(?:yaml\.)?SafeLoader)/i;
    if (reg_8802.test(cleanContent)) {
        const linePattern = /yaml\.load\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure PyYAML load() Without SafeLoader";
        findings.push({
            id: `py8802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8802,
            type: 'SECURITY',
            title: "PY-SEC-02: Insecure PyYAML load() Without SafeLoader",
            severity: "CRITICAL",
            category: "Insecure Deserialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using yaml.load() without Loader=yaml.SafeLoader enables arbitrary Python object instantiation."
            ],
            remediationPrompt: "Always use yaml.safe_load() or specify Loader=yaml.SafeLoader when parsing YAML documents.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-02: Insecure PyYAML load() Without SafeLoader at ${file.path}:${lineNum}`);
    }
    // PY-SEC-03: Subprocess Execution with shell=True
    // Only a shell command assembled from runtime values (f-string, %, .format, +) is injectable; constant commands are not
    const idx_8803 = (() => {
        const dynamicCmd = /^\s*\(\s*(?:[fF]['"][^'"]*\{|['"][^'"]*['"]\s*(?:%|\.format\s*\(|\+))/;
        const sub = /subprocess\.(?:Popen|run|call|check_output|check_call)\s*\(/;
        const osCall = /(?<![\w.])os\.(?:system|popen)\s*(?=\()/;
        return pyFindLine(lines, /subprocess\.(?:Popen|run|call|check_output|check_call)\s*\(|(?<![\w.])os\.(?:system|popen)\s*\(/, (l, i) => {
            if (sub.test(l)) {
                const call = callText(lines, i, sub);
                return /\bshell\s*=\s*True\b/.test(call) && dynamicCmd.test(call.replace(sub, '('));
            }
            const m = osCall.exec(l);
            return !!m && dynamicCmd.test(l.slice(m.index + m[0].length));
        });
    })();
    if (idx_8803 !== -1) {
        const matchLineIdx = idx_8803;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Subprocess Execution with shell=True";
        findings.push({
            id: `py8803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8803,
            type: 'SECURITY',
            title: "PY-SEC-03: Subprocess Execution with shell=True",
            severity: "HIGH",
            category: "Command Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Invoking subprocess.Popen, run, or call with shell=True and unsanitized string formatting allows command injection."
            ],
            remediationPrompt: "Pass command arguments as a list of strings and set shell=False to prevent shell command injection.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-03: Subprocess Execution with shell=True at ${file.path}:${lineNum}`);
    }
    // PY-SEC-04: Python SQL Injection via String Interpolation (f-string / format / %)
    // f-string SQL passed straight to execute()/text() with a value interpolated after WHERE/SET/VALUES/LIKE/=/IN (identifier-only interpolation is left alone)
    const idx_8804 = pyFindLine(lines, /(?:\.execute(?:many)?|(?<![\w.])text|sa\.text|sqlalchemy\.text)\s*\(\s*[fF](?:"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*(?:\bWHERE\b|\bSET\b|\bVALUES\b|\bLIKE\b|=|\bIN\s*\()[^"]*\{[^"]*"|'[^']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^']*(?:\bWHERE\b|\bSET\b|\bVALUES\b|\bLIKE\b|=|\bIN\s*\()[^']*\{[^']*')/i);
    if (idx_8804 !== -1) {
        const matchLineIdx = idx_8804;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Python SQL Injection via String Interpolation (f-string / format / %)";
        findings.push({
            id: `py8804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8804,
            type: 'SECURITY',
            title: "PY-SEC-04: Python SQL Injection via String Interpolation (f-string / format / %)",
            severity: "HIGH",
            category: "SQL Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Constructing SQL queries using f-strings, % formatting, or .format() enables SQL injection."
            ],
            remediationPrompt: "Bind query parameters using parameterized queries with placeholder binding (:id, %s, ?).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-04: Python SQL Injection via String Interpolation (f-string / format / %) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-05: Django / Flask DEBUG Mode Enabled in Production Settings
    // Module-level DEBUG = True in a Django settings module that is not a dev/local/test variant
    // (Flask app.run(debug=True) is the dev server only and is not flagged)
    const isDjangoSettings = /(?:^|\/|_)settings(?:\/[\w-]+)?\.py$|(?:^|\/)(?:prod|production)(?:_settings)?\.py$/.test(lowerPath) && !isDevSettingsPath(lowerPath);
    const idx_8805 = isDjangoSettings ? pyFindLine(lines, /^\s*DEBUG\s*=\s*True\b/) : -1;
    if (idx_8805 !== -1) {
        const matchLineIdx = idx_8805;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django / Flask DEBUG Mode Enabled in Production Settings";
        findings.push({
            id: `py8805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8805,
            type: 'SECURITY',
            title: "PY-SEC-05: Django / Flask DEBUG Mode Enabled in Production Settings",
            severity: "MEDIUM",
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Configuring DEBUG = True or app.run(debug=True) in production settings exposes stack traces and environment secrets."
            ],
            remediationPrompt: "Ensure DEBUG is set to False in production and configured via environment variables.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-05: Django / Flask DEBUG Mode Enabled in Production Settings at ${file.path}:${lineNum}`);
    }
    // PY-SEC-06: FastAPI Permissive CORS with Allow-Credentials
    const idx_8806 = pyFindLine(lines, /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/, (_l, i) => lines.slice(Math.max(0, i - 8), i + 9).some((x) => pyIsCode(x) && /allow_credentials\s*=\s*True\b/.test(x)));
    if (idx_8806 !== -1) {
        const matchLineIdx = idx_8806;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "FastAPI Permissive CORS with Allow-Credentials";
        findings.push({
            id: `py8806-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8806,
            type: 'SECURITY',
            title: "PY-SEC-06: FastAPI Permissive CORS with Allow-Credentials",
            severity: "HIGH",
            category: "Cross-Origin Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: FastAPI CORSMiddleware configured with allow_origins=[\"*\"] alongside allow_credentials=True violates CORS spec."
            ],
            remediationPrompt: "Specify explicit origin domains when allow_credentials is True; wildcard is prohibited by CORS spec.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-06: FastAPI Permissive CORS with Allow-Credentials at ${file.path}:${lineNum}`);
    }
    // PY-SEC-07: Blocking Synchronous I/O Inside FastAPI async def Handler
    const idx_8807 = (() => {
        const blocking = /(?<![\w.])(?:time\.sleep|requests\.(?:get|post|put|patch|delete|head|request))\s*\(/;
        for (let i = 0; i < lines.length; i++) {
            if (!/^\s*async\s+def\s+\w+/.test(lines[i])) continue;
            const [from, to] = pyBlockRange(lines, i);
            for (let j = from; j <= to; j++) if (pyIsCode(lines[j]) && blocking.test(lines[j])) return j;
        }
        return -1;
    })();
    if (idx_8807 !== -1) {
        const matchLineIdx = idx_8807;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Blocking Synchronous I/O Inside FastAPI async def Handler";
        findings.push({
            id: `py8807-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8807,
            type: 'SECURITY',
            title: "PY-SEC-07: Blocking Synchronous I/O Inside FastAPI async def Handler",
            severity: "MEDIUM",
            category: "Event Loop Starvation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Executing time.sleep(), requests.get(), or blocking database calls inside async def handlers freezes the event loop."
            ],
            remediationPrompt: "Use non-blocking async libraries (httpx, asyncio.sleep, asyncpg) or use regular def handlers for threadpool offload.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-07: Blocking Synchronous I/O Inside FastAPI async def Handler at ${file.path}:${lineNum}`);
    }
    // PY-SEC-08: Insecure Celery Task Serializer (Pickle Serialization)
    const idx_8808 = pyFindLine(lines, /(?:task_serializer|result_serializer|accept_content)['"]?\s*[=:]\s*(?:[\[(][^\])]*)?['"](?:pickle|application\/x-python-serialize)['"]/i);
    if (idx_8808 !== -1) {
        const matchLineIdx = idx_8808;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Celery Task Serializer (Pickle Serialization)";
        findings.push({
            id: `py8808-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8808,
            type: 'SECURITY',
            title: "PY-SEC-08: Insecure Celery Task Serializer (Pickle Serialization)",
            severity: "CRITICAL",
            category: "Task Queue Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Celery configured with task_serializer = \"pickle\" or accept_content = [\"pickle\"] allows arbitrary code execution via broker."
            ],
            remediationPrompt: "Configure Celery to accept strictly JSON serialization (task_serializer = \"json\").",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-08: Insecure Celery Task Serializer (Pickle Serialization) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-09: Hardcoded Secret Key in Flask / Django Settings
    // Settings-level signing secret assigned a real-looking literal (placeholders and dev/test settings are skipped)
    const idx_8809 = isDevSettingsPath(lowerPath) ? -1 : pyFindLine(lines, /^\s*(?:SECRET_KEY|JWT_SECRET(?:_KEY)?)\s*(?::\s*str\s*)?=\s*['"]([^'"\s]{16,})['"]\s*$/, (l) => {
        const value = /=\s*['"]([^'"\s]{16,})['"]/.exec(l)![1];
        return !/change|replace|example|your|dummy|placeholder|xxx|\{|\$|<|test|sample/i.test(value);
    });
    if (idx_8809 !== -1) {
        const matchLineIdx = idx_8809;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Hardcoded Secret Key in Flask / Django Settings";
        findings.push({
            id: `py8809-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8809,
            type: 'SECURITY',
            title: "PY-SEC-09: Hardcoded Secret Key in Flask / Django Settings",
            severity: "HIGH",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Static SECRET_KEY string committed in settings.py or app.config[\"SECRET_KEY\"] allows session tampering and forgery."
            ],
            remediationPrompt: "Load SECRET_KEY from environment variables and fail fast if missing in production.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-09: Hardcoded Secret Key in Flask / Django Settings at ${file.path}:${lineNum}`);
    }
    // PY-SEC-10: Unrestricted Jinja2 Server-Side Template Injection (SSTI)
    const idx_8810 = (() => {
        const tainted = pyRequestVars(lines);
        const jinjaTemplate = /from\s+jinja2\s+import\s+[^\n]*\bTemplate\b/.test(cleanContent);
        const call = jinjaTemplate
            ? /(?:render_template_string|jinja2\.Template|(?<![\w.])Template|\.from_string)\s*\(\s*(.*)/
            : /(?:render_template_string|jinja2\.Template|\.from_string)\s*\(\s*(.*)/;
        return pyFindLine(lines, call, (l) => {
            const arg = (call.exec(l) as RegExpExecArray)[1];
            if (/^(?:[rRbB]?[fF]|[fF][rR])['"]/.test(arg) || /^request\./.test(arg)) return true;
            if (/^(?:'[^']*'|"[^"]*")\s*(?:\+|%|\.format\s*\()/.test(arg)) return true;
            const id = /^(\w+)\s*(?:[,)+%]|$)/.exec(arg);
            return !!id && tainted.has(id[1]);
        });
    })();
    if (idx_8810 !== -1) {
        const matchLineIdx = idx_8810;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Unrestricted Jinja2 Server-Side Template Injection (SSTI)";
        findings.push({
            id: `py8810-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8810,
            type: 'SECURITY',
            title: "PY-SEC-10: Unrestricted Jinja2 Server-Side Template Injection (SSTI)",
            severity: "CRITICAL",
            category: "Template Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Rendering Jinja2 templates directly from user input strings using jinja2.Template(user_str).render() enables RCE."
            ],
            remediationPrompt: "Never render raw user strings as templates; pass user input strictly as template context variables.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-10: Unrestricted Jinja2 Server-Side Template Injection (SSTI) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-11: Dynamic Code Execution via eval() or exec()
    const reg_8811 = /(?<![.\w])(?:eval|exec|compile)\s*\(\s*(?!'[^']*'|"[^"]*")[a-zA-Z0-9_]+/;
    if (reg_8811.test(cleanContent)) {
        const linePattern = /(?<![.\w])(?:eval|exec|compile)\s*\(/;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Dynamic Code Execution via eval() or exec()";
        findings.push({
            id: `py8811-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8811,
            type: 'SECURITY',
            title: "PY-SEC-11: Dynamic Code Execution via eval() or exec()",
            severity: "CRITICAL",
            category: "Code Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Dynamic execution of Python code strings using eval() or exec() with untrusted user input."
            ],
            remediationPrompt: "Avoid eval() and exec(). Use ast.literal_eval() for safe literal evaluation or parse structured schemas.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-11: Dynamic Code Execution via eval() or exec() at ${file.path}:${lineNum}`);
    }
    // PY-SEC-12: Weak Cryptographic Hash Algorithm (MD5 / SHA-1)
    // MD5/SHA-1 is fine for cache keys and ETags; only hashing a password with it is flagged
    const idx_8812 = pyFindLine(lines, /hashlib\.(?:md5|sha1)\s*\([^)]*\b(?:password|passwd|pwd)\b/i, (l) => !/usedforsecurity\s*=\s*False/.test(l));
    if (idx_8812 !== -1) {
        const matchLineIdx = idx_8812;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Weak Cryptographic Hash Algorithm (MD5 / SHA-1)";
        findings.push({
            id: `py8812-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8812,
            type: 'SECURITY',
            title: "PY-SEC-12: Weak Cryptographic Hash Algorithm (MD5 / SHA-1)",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using hashlib.md5() or hashlib.sha1() for security digests or password hashing is cryptographically vulnerable."
            ],
            remediationPrompt: "Use hashlib.sha256(), hashlib.sha512(), or bcrypt/argon2 for password hashing.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-12: Weak Cryptographic Hash Algorithm (MD5 / SHA-1) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-13: Insecure Temporary File Creation via tempfile.mktemp()
    const idx_8813 = pyFindLine(lines, /tempfile\.mktemp\s*\(/);
    if (idx_8813 !== -1) {
        const matchLineIdx = idx_8813;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Temporary File Creation via tempfile.mktemp()";
        findings.push({
            id: `py8813-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8813,
            type: 'SECURITY',
            title: "PY-SEC-13: Insecure Temporary File Creation via tempfile.mktemp()",
            severity: "MEDIUM",
            category: "Race Condition",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: tempfile.mktemp() is deprecated and vulnerable to race condition symlink attacks between name creation and file opening."
            ],
            remediationPrompt: "Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() which create and open files atomically.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-13: Insecure Temporary File Creation via tempfile.mktemp() at ${file.path}:${lineNum}`);
    }
    // PY-SEC-14: Server-Side Request Forgery (SSRF) via Dynamic URL Fetch
    const reg_8814 = /(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(\s*(?:request\.(?:args|GET|POST|values|json)|url|target_url)/i;
    if (reg_8814.test(cleanContent)) {
        const linePattern = /(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Server-Side Request Forgery (SSRF) via Dynamic URL Fetch";
        findings.push({
            id: `py8814-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8814,
            type: 'SECURITY',
            title: "PY-SEC-14: Server-Side Request Forgery (SSRF) via Dynamic URL Fetch",
            severity: "HIGH",
            category: "SSRF",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Passing unvalidated user query parameters directly into requests.get(), httpx.get(), or urllib.request.urlopen()."
            ],
            remediationPrompt: "Validate requested URLs against an allowlist of permitted hostnames and disallow private RFC 1918 IPs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-14: Server-Side Request Forgery (SSRF) via Dynamic URL Fetch at ${file.path}:${lineNum}`);
    }
    // PY-SEC-15: Insecure XML Parser Vulnerable to XML External Entity (XXE)
    const idx_8815 = pyFindLine(lines, /XMLParser\s*\([^)]*resolve_entities\s*=\s*True|setFeature\s*\(\s*(?:[\w.]*\.)?feature_external_ges\s*,\s*(?:True|1)\s*\)/);
    if (idx_8815 !== -1) {
        const matchLineIdx = idx_8815;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure XML Parser Vulnerable to XML External Entity (XXE)";
        findings.push({
            id: `py8815-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8815,
            type: 'SECURITY',
            title: "PY-SEC-15: Insecure XML Parser Vulnerable to XML External Entity (XXE)",
            severity: "HIGH",
            category: "XML Entity Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using standard xml.etree.ElementTree or minidom on untrusted XML without entity expansion protection enables XXE."
            ],
            remediationPrompt: "Use defusedxml library (defusedxml.ElementTree) to parse untrusted XML safely.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-15: Insecure XML Parser Vulnerable to XML External Entity (XXE) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-16: Path Traversal via Unsanitized File Access
    const idx_8816 = (() => {
        const tainted = pyRequestVars(lines);
        const sink = /(?<![\w.])(?:open|send_file|io\.open|codecs\.open|aiofiles\.open)\s*\(\s*(.*)/;
        return pyFindLine(lines, sink, (l) => {
            if (/secure_filename|safe_join/.test(l)) return false;
            const pathArg = (sink.exec(l) as RegExpExecArray)[1].split(/,\s*(?:mode\s*=\s*)?['"][rwabxt+]{1,3}['"]/)[0];
            if (/request\.(?:args|GET|POST|values|json|form|query_params)\b/.test(pathArg)) return true;
            return [...pathArg.matchAll(/(?<![\w.'"])([a-zA-Z_]\w*)\b(?!\s*\()/g)].some((m) => tainted.has(m[1]));
        });
    })();
    if (idx_8816 !== -1) {
        const matchLineIdx = idx_8816;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Path Traversal via Unsanitized File Access";
        findings.push({
            id: `py8816-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8816,
            type: 'SECURITY',
            title: "PY-SEC-16: Path Traversal via Unsanitized File Access",
            severity: "HIGH",
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Opening files or serving paths directly concatenated with user request parameters without path resolution checks."
            ],
            remediationPrompt: "Sanitize file paths with os.path.abspath and verify the resolved path is within the designated base directory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-16: Path Traversal via Unsanitized File Access at ${file.path}:${lineNum}`);
    }
    // PY-SEC-17: CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False)
    // Webhook / callback views that authenticate the sender (signature, HMAC, token) legitimately skip CSRF; test configs too
    const idx_8817 = isDevSettingsPath(lowerPath) ? -1 : pyFindLine(lines, /^\s*@csrf_exempt\b|^\s*WTF_CSRF_ENABLED\s*=\s*False\b|app\.config\s*\[\s*['"]WTF_CSRF_ENABLED['"]\s*\]\s*=\s*False\b/, (l, i) => {
        if (/WTF_CSRF_ENABLED/.test(l)) return !/\bTest|TESTING/.test(lines.slice(Math.max(0, i - 20), i).join('\n'));
        let def = i + 1;
        while (def < lines.length && /^\s*@/.test(lines[def])) def++;
        if (def >= lines.length || !/^\s*(?:async\s+)?def\s+\w+|^\s*class\s+\w+/.test(lines[def])) return false;
        if (/webhook|hook|callback|ipn|notify|notification|stripe|paypal|github|slack|twilio/i.test(lines[def])) return false;
        const [from, to] = pyBlockRange(lines, def);
        return !/signature|hmac|construct_event|verify|authorization|api_key|token/i.test(lines.slice(from, to + 1).join('\n'));
    });
    if (idx_8817 !== -1) {
        const matchLineIdx = idx_8817;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False)";
        findings.push({
            id: `py8817-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8817,
            type: 'SECURITY',
            title: "PY-SEC-17: CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False)",
            severity: "MEDIUM",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Disabling CSRF middleware globally or decorating state-mutating views with @csrf_exempt exposes users to CSRF."
            ],
            remediationPrompt: "Enforce CSRF tokens on all state-mutating HTTP methods (POST, PUT, DELETE, PATCH).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-17: CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-18: SSL / TLS Certificate Verification Disabled (verify=False)
    const idx_8818 = pyFindLine(lines, /(?:requests|httpx|session|client|self\.session|self\.client)\.(?:get|post|put|patch|delete|head|request|Client|AsyncClient)\s*\([^)]*\bverify\s*=\s*False|\b(?:session|client|s)\.verify\s*=\s*False\b|ssl\._create_unverified_context\s*\(|verify_mode\s*=\s*ssl\.CERT_NONE/);
    if (idx_8818 !== -1) {
        const matchLineIdx = idx_8818;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "SSL / TLS Certificate Verification Disabled (verify=False)";
        findings.push({
            id: `py8818-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8818,
            type: 'SECURITY',
            title: "PY-SEC-18: SSL / TLS Certificate Verification Disabled (verify=False)",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting verify=False in requests or urllib calls disables TLS certificate validation, enabling Man-in-the-Middle attacks."
            ],
            remediationPrompt: "Keep SSL certificate verification enabled (verify=True) or specify custom CA bundle path.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-18: SSL / TLS Certificate Verification Disabled (verify=False) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-19: Insecure Deserialization via shelve or marshal Modules
    const idx_8819 = pyFindLine(lines, /(?<![\w.])marshal\.loads?\s*\(/);
    if (idx_8819 !== -1) {
        const matchLineIdx = idx_8819;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Deserialization via shelve or marshal Modules";
        findings.push({
            id: `py8819-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8819,
            type: 'SECURITY',
            title: "PY-SEC-19: Insecure Deserialization via shelve or marshal Modules",
            severity: "HIGH",
            category: "Insecure Deserialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using marshal or shelve modules to parse external data allows arbitrary code execution or memory corruption."
            ],
            remediationPrompt: "Use JSON, Protocol Buffers, or CBOR for serializing data between untrusted boundaries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-19: Insecure Deserialization via shelve or marshal Modules at ${file.path}:${lineNum}`);
    }
    // PY-SEC-20: Hardcoded Database Connection String with Credentials
    const idx_8820 = pyFindLine(lines, /(?:postgres|postgresql|mysql|mariadb|mongodb|redis|amqp)(?:\+\w+)?:\/\//i, (l) => hasDbUrlWithRealPassword(l));
    if (idx_8820 !== -1) {
        const matchLineIdx = idx_8820;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Hardcoded Database Connection String with Credentials";
        findings.push({
            id: `py8820-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8820,
            type: 'SECURITY',
            title: "PY-SEC-20: Hardcoded Database Connection String with Credentials",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Hardcoded database credentials in connection URIs committed to source code risk database compromise."
            ],
            remediationPrompt: "Inject database connection strings via DATABASE_URL environment variables in production.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-20: Hardcoded Database Connection String with Credentials at ${file.path}:${lineNum}`);
    }
    // PY-SEC-21: Paramiko SSH Host Key Auto-Add Policy (AutoAddPolicy)
    const idx_8821 = pyFindLine(lines, /set_missing_host_key_policy\s*\(\s*(?:paramiko\.(?:client\.)?)?(?:AutoAddPolicy|WarningPolicy)\b|paramiko\.AutoAddPolicy\s*\(/);
    if (idx_8821 !== -1) {
        const matchLineIdx = idx_8821;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Paramiko SSH Host Key Auto-Add Policy (AutoAddPolicy)";
        findings.push({
            id: `py8821-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8821,
            type: 'SECURITY',
            title: "PY-SEC-21: Paramiko SSH Host Key Auto-Add Policy (AutoAddPolicy)",
            severity: "HIGH",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using paramiko.AutoAddPolicy() automatically trusts any remote SSH host key without verification, risking MitM."
            ],
            remediationPrompt: "Use paramiko.RejectPolicy() and maintain a validated known_hosts file.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-21: Paramiko SSH Host Key Auto-Add Policy (AutoAddPolicy) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-22: Flask / Django Session Cookie Missing Secure or HttpOnly Flags
    // HttpOnly off is wrong anywhere; Secure off is expected in local/dev settings (plain-http localhost), so those are skipped
    const idx_8822 = isDevSettingsPath(lowerPath) ? -1 : pyFindLine(lines, /^\s*SESSION_COOKIE_(?:HTTPONLY|SECURE)\s*=\s*False\b|['"]SESSION_COOKIE_(?:HTTPONLY|SECURE)['"]\s*\]\s*=\s*False\b/);
    if (idx_8822 !== -1) {
        const matchLineIdx = idx_8822;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Flask / Django Session Cookie Missing Secure or HttpOnly Flags";
        findings.push({
            id: `py8822-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8822,
            type: 'SECURITY',
            title: "PY-SEC-22: Flask / Django Session Cookie Missing Secure or HttpOnly Flags",
            severity: "MEDIUM",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Configuring session cookies without HttpOnly or Secure flags exposes cookies to XSS theft and cleartext sniffing."
            ],
            remediationPrompt: "Set SESSION_COOKIE_HTTPONLY = True and SESSION_COOKIE_SECURE = True in production.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-22: Flask / Django Session Cookie Missing Secure or HttpOnly Flags at ${file.path}:${lineNum}`);
    }
    // PY-SEC-24: Use of Assert Statement for Security or Authorization Checks
    // Only asserts that ARE the authorization decision (admin/staff/permission/role checks); `assert x is not None` type narrowing is left alone
    const idx_8824 = pyFindLine(lines, /^\s*assert\s+(?:not\s+)?[\w.]*(?:\.(?:is_admin|is_superuser|is_staff)\b|\.has_perms?\s*\(|\bis_admin\b|\.role\s*(?:==|in)\s|\bhas_permission\s*\()/);
    if (idx_8824 !== -1) {
        const matchLineIdx = idx_8824;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Use of Assert Statement for Security or Authorization Checks";
        findings.push({
            id: `py8824-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8824,
            type: 'SECURITY',
            title: "PY-SEC-24: Use of Assert Statement for Security or Authorization Checks",
            severity: "MEDIUM",
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using assert statements for authorization or data validation is bypassed when Python is run with optimizations (-O / -OO)."
            ],
            remediationPrompt: "Replace assert statements with explicit if not condition: raise PermissionDenied() checks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-24: Use of Assert Statement for Security or Authorization Checks at ${file.path}:${lineNum}`);
    }
    // PY-SEC-25: Flask Weak Default Secret Key
    const idx_8825 = pyFindLine(lines, /(?:app\.secret_key|app\.config\s*\[\s*['"]SECRET_KEY['"]\s*\])\s*=\s*['"][^'"]{1,32}['"]/);
    if (idx_8825 !== -1) {
        const matchLineIdx = idx_8825;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Flask Weak Default Secret Key";
        findings.push({
            id: `py8825-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8825,
            type: 'SECURITY',
            title: "PY-SEC-25: Flask Weak Default Secret Key",
            severity: "HIGH",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Assigning a weak or trivial secret key string to app.secret_key enables session token forgery."
            ],
            remediationPrompt: "Use secrets.token_hex(32) to generate cryptographically strong random secret keys loaded from environment.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-25: Flask Weak Default Secret Key at ${file.path}:${lineNum}`);
    }
    // PY-SEC-26: Cryptographically Weak PRNG Used for Security Tokens
    const idx_8826 = (() => {
        const secretName = /(?:token|password|passwd|secret|otp|nonce|salt|api_key|apikey|reset_code|verification_code|pin_code)/i;
        const weak = /(?<![\w.])random\.(?:random|choice|choices|randint|randrange|getrandbits|sample)\s*\(/;
        const direct = pyFindLine(lines, new RegExp(`^\\s*[\\w.]*${secretName.source}\\s*(?::\\s*\\w+\\s*)?=(?!=)`, 'i'), (l) => weak.test(l));
        if (direct !== -1) return direct;
        for (let i = 0; i < lines.length; i++) {
            const m = /^\s*def\s+(\w+)\s*\(/.exec(lines[i]);
            if (!m || !secretName.test(m[1])) continue;
            const [from, to] = pyBlockRange(lines, i);
            for (let j = from; j <= to; j++) if (pyIsCode(lines[j]) && weak.test(lines[j])) return j;
        }
        return -1;
    })();
    if (idx_8826 !== -1) {
        const matchLineIdx = idx_8826;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Cryptographically Weak PRNG Used for Security Tokens";
        findings.push({
            id: `py8826-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8826,
            type: 'SECURITY',
            title: "PY-SEC-26: Cryptographically Weak PRNG Used for Security Tokens",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using the standard random module (Mersenne Twister) to generate passwords, session tokens, or reset keys is insecure."
            ],
            remediationPrompt: "Use the secrets module (secrets.token_urlsafe or secrets.token_hex) for cryptographically secure generation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-26: Cryptographically Weak PRNG Used for Security Tokens at ${file.path}:${lineNum}`);
    }
    // PY-SEC-27: Django ALLOWED_HOSTS Configured with Wildcard (*)
    const idx_8827 = /(?:^|\/)(?:dev|development|local|test|testing)(?:_settings)?\.py$|settings_(?:dev|local)\.py$/.test(lowerPath) ? -1 : pyFindLine(lines, /^ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/);
    if (idx_8827 !== -1) {
        const matchLineIdx = idx_8827;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django ALLOWED_HOSTS Configured with Wildcard (*)";
        findings.push({
            id: `py8827-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8827,
            type: 'SECURITY',
            title: "PY-SEC-27: Django ALLOWED_HOSTS Configured with Wildcard (*)",
            severity: "HIGH",
            category: "Host Header Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting ALLOWED_HOSTS = [\"*\"] in Django allows Host Header poisoning, password reset poisoning, and cache poisoning."
            ],
            remediationPrompt: "Specify fully qualified production domain names in ALLOWED_HOSTS without wildcards.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-27: Django ALLOWED_HOSTS Configured with Wildcard (*) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-28: Hardcoded AWS Access Key ID in Python Source
    const idx_8828 = pyFindLine(lines, /['"]AKIA[0-9A-Z]{16}['"]/, (l) => !/AKIAIOSFODNN7EXAMPLE/.test(l));
    if (idx_8828 !== -1) {
        const matchLineIdx = idx_8828;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Hardcoded AWS Access Key ID in Python Source";
        findings.push({
            id: `py8828-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8828,
            type: 'SECURITY',
            title: "PY-SEC-28: Hardcoded AWS Access Key ID in Python Source",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Hardcoded AWS IAM access key ID committed in source code exposes cloud infrastructure to takeover."
            ],
            remediationPrompt: "Use IAM roles or AWS environment variables (AWS_ACCESS_KEY_ID) instead of hardcoding credentials.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-28: Hardcoded AWS Access Key ID in Python Source at ${file.path}:${lineNum}`);
    }
    // PY-SEC-29: Unvalidated Open Redirect via Dynamic Request URL
    const idx_8829 = pyFindLine(lines, /(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*(?:url\s*=\s*)?request\.(?:args|GET|values|query_params)(?:\[['"](?:next|url|redirect_to|return_to|redirect)['"]\]|\.get\s*\(\s*['"](?:next|url|redirect_to|return_to|redirect)['"])/i);
    if (idx_8829 !== -1) {
        const matchLineIdx = idx_8829;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Unvalidated Open Redirect via Dynamic Request URL";
        findings.push({
            id: `py8829-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8829,
            type: 'SECURITY',
            title: "PY-SEC-29: Unvalidated Open Redirect via Dynamic Request URL",
            severity: "MEDIUM",
            category: "Open Redirect",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Redirecting users directly to target URLs provided in query parameters without domain validation allows phishing."
            ],
            remediationPrompt: "Validate destination URLs against relative paths (starting with /) or an allowlist of approved domains.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-29: Unvalidated Open Redirect via Dynamic Request URL at ${file.path}:${lineNum}`);
    }
    // PY-SEC-30: Raw SQL Query with % or .format() String Formatting
    const idx_8830 = pyFindLine(lines, /\.execute(?:many)?\s*\(\s*['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*(?:%\s*[\w(]|\.format\s*\()/i);
    if (idx_8830 !== -1) {
        const matchLineIdx = idx_8830;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Raw SQL Query with % or .format() String Formatting";
        findings.push({
            id: `py8830-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8830,
            type: 'SECURITY',
            title: "PY-SEC-30: Raw SQL Query with % or .format() String Formatting",
            severity: "CRITICAL",
            category: "SQL Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Formatting raw SQL queries using % or str.format() creates SQL injection vulnerabilities."
            ],
            remediationPrompt: "Use DB-API parameterized queries (execute(query, (params,))) to bind parameters safely.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-30: Raw SQL Query with % or .format() String Formatting at ${file.path}:${lineNum}`);
    }
    // PY-SEC-31: Django Mass Assignment via Unfiltered Request Data Unpacking
    const idx_8831 = pyFindLine(lines, /\.objects\.(?:create|get_or_create|update_or_create|filter\([^)]*\)\.update)\s*\(\s*\*\*request\.(?:data|POST|GET)\b/);
    if (idx_8831 !== -1) {
        const matchLineIdx = idx_8831;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django Mass Assignment via Unfiltered Request Data Unpacking";
        findings.push({
            id: `py8831-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8831,
            type: 'SECURITY',
            title: "PY-SEC-31: Django Mass Assignment via Unfiltered Request Data Unpacking",
            severity: "HIGH",
            category: "Mass Assignment",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Unpacking unfiltered request.POST or request.data into Model.objects.create(**request.data) allows privilege escalation."
            ],
            remediationPrompt: "Use Django ModelForm with explicit fields list or serializers with validated fields.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-31: Django Mass Assignment via Unfiltered Request Data Unpacking at ${file.path}:${lineNum}`);
    }
    // PY-SEC-32: Insecure LDAP Search Filter String Interpolation
    const idx_8832 = (() => {
        if (!/^\s*(?:import\s+ldap3?\b|from\s+ldap3?(?:\.\w+)*\s+import\b)/m.test(cleanContent)) return -1;
        const escaped = new Set<string>();
        for (const l of lines) {
            const m = /^\s*(\w+)\s*=\s*(?:[\w.]*\.)?escape_filter_chars\s*\(/.exec(l);
            if (m) escaped.add(m[1]);
        }
        const filter = /[fF]['"][^'"]*\(\w+[~<>]?=[^'"{]*\{\s*(?!(?:[\w.]*\.)?escape_filter_chars\s*\()([\w.]+)|['"][^'"]*\(\w+=[^'"]*%s[^'"]*['"]\s*%|['"][^'"]*\(\w+=['"]\s*\+/;
        return pyFindLine(lines, filter, (l) => {
            const m = filter.exec(l) as RegExpExecArray;
            return !(m[1] && escaped.has(m[1]));
        });
    })();
    if (idx_8832 !== -1) {
        const matchLineIdx = idx_8832;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure LDAP Search Filter String Interpolation";
        findings.push({
            id: `py8832-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8832,
            type: 'SECURITY',
            title: "PY-SEC-32: Insecure LDAP Search Filter String Interpolation",
            severity: "HIGH",
            category: "LDAP Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Constructing LDAP search filters via string concatenation or f-strings without ldap.filter.escape_filter_chars."
            ],
            remediationPrompt: "Sanitize user inputs in LDAP queries using ldap.filter.escape_filter_chars().",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-32: Insecure LDAP Search Filter String Interpolation at ${file.path}:${lineNum}`);
    }
    // PY-SEC-33: Catastrophic Backtracking Regular Expression (ReDoS)
    // Nested quantifier over a single token, e.g. (a+)+, ([a-z]+)*, (\w+)+, (.*)*: the classic exponential-backtracking shape
    const idx_8833 = pyFindLine(lines, /re\.(?:compile|match|search|fullmatch|findall|sub)\s*\(\s*r?['"][^'"]*\((?:\?:)?(?:\[[^\]]+\]|\\[wdsWDS]|\.|[A-Za-z0-9])[+*]\)[+*{]/);
    if (idx_8833 !== -1) {
        const matchLineIdx = idx_8833;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Catastrophic Backtracking Regular Expression (ReDoS)";
        findings.push({
            id: `py8833-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8833,
            type: 'SECURITY',
            title: "PY-SEC-33: Catastrophic Backtracking Regular Expression (ReDoS)",
            severity: "MEDIUM",
            category: "Regular Expression Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Compiling regex patterns with nested quantifiers (e.g., (a+)+) causes exponential evaluation time on crafted inputs."
            ],
            remediationPrompt: "Refactor regex patterns to avoid nested repetition or use re2/linear-time regex engines.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-33: Catastrophic Backtracking Regular Expression (ReDoS) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-34: Hardcoded Private Key in Python Source Code
    const idx_8834 = pyFindLine(lines, /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, (_l, i) => /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/=]{40,}/.test(lines.slice(i, i + 3).join('\n')));
    if (idx_8834 !== -1) {
        const matchLineIdx = idx_8834;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Hardcoded Private Key in Python Source Code";
        findings.push({
            id: `py8834-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8834,
            type: 'SECURITY',
            title: "PY-SEC-34: Hardcoded Private Key in Python Source Code",
            severity: "CRITICAL",
            category: "Hardcoded Secrets",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Committed RSA, EC, or OpenSSH private key PEM blocks in source code expose server cryptography."
            ],
            remediationPrompt: "Store private keys in hardware security modules (HSM) or secure secret managers (AWS Secrets Manager, Vault).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-34: Hardcoded Private Key in Python Source Code at ${file.path}:${lineNum}`);
    }
    // PY-SEC-35: Broad Exception Handling Swallowing Critical Errors (except: pass)
    // Bare `except:` that silently passes also swallows KeyboardInterrupt / SystemExit; `except Exception: pass` (best-effort cleanup) is left alone
    const idx_8835 = pyFindLine(lines, /^\s*except\s*:\s*(?:pass\b|$)/, (l, i) => /:\s*pass\b/.test(l) || /^\s*pass\s*$/.test(lines.slice(i + 1).find((x) => x.trim() !== '') ?? ''));
    if (idx_8835 !== -1) {
        const matchLineIdx = idx_8835;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Broad Exception Handling Swallowing Critical Errors (except: pass)";
        findings.push({
            id: `py8835-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8835,
            type: 'SECURITY',
            title: "PY-SEC-35: Broad Exception Handling Swallowing Critical Errors (except: pass)",
            severity: "LOW",
            category: "Error Handling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Catching all exceptions silently with except: pass or except Exception: pass masks security and integrity failures."
            ],
            remediationPrompt: "Catch specific exception types and log errors appropriately with logger.exception().",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-35: Broad Exception Handling Swallowing Critical Errors (except: pass) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-36: Django SECURE_HSTS_SECONDS Not Configured or Disabled
    // Explicitly disabling HSTS outside dev/local/test settings
    const idx_8836 = isDevSettingsPath(lowerPath) ? -1 : pyFindLine(lines, /^\s*SECURE_HSTS_SECONDS\s*=\s*0\s*$/);
    if (idx_8836 !== -1) {
        const matchLineIdx = idx_8836;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django SECURE_HSTS_SECONDS Not Configured or Disabled";
        findings.push({
            id: `py8836-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8836,
            type: 'SECURITY',
            title: "PY-SEC-36: Django SECURE_HSTS_SECONDS Not Configured or Disabled",
            severity: "MEDIUM",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting SECURE_HSTS_SECONDS = 0 or omitting HSTS in production settings leaves clients vulnerable to SSL stripping."
            ],
            remediationPrompt: "Set SECURE_HSTS_SECONDS to at least 31536000 (1 year) and enable SECURE_HSTS_INCLUDE_SUBDOMAINS.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-36: Django SECURE_HSTS_SECONDS Not Configured or Disabled at ${file.path}:${lineNum}`);
    }
    // PY-SEC-38: Insecure FTPLib Usage Without TLS (Plaintext FTP)
    const idx_8838 = pyFindLine(lines, /from\s+ftplib\s+import\s+[^\n]*\bFTP\b/.test(cleanContent) ? /(?:ftplib\.|(?<![\w.]))FTP\s*\(/ : /ftplib\.FTP\s*\(/);
    if (idx_8838 !== -1) {
        const matchLineIdx = idx_8838;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure FTPLib Usage Without TLS (Plaintext FTP)";
        findings.push({
            id: `py8838-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8838,
            type: 'SECURITY',
            title: "PY-SEC-38: Insecure FTPLib Usage Without TLS (Plaintext FTP)",
            severity: "MEDIUM",
            category: "Cleartext Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using ftplib.FTP transmits credentials and file contents unencrypted over the network."
            ],
            remediationPrompt: "Use ftplib.FTP_TLS or SFTP (paramiko) for encrypted file transfers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-38: Insecure FTPLib Usage Without TLS (Plaintext FTP) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-39: Insecure Telnetlib Usage (Cleartext Management Protocol)
    const idx_8839 = pyFindLine(lines, /from\s+telnetlib\s+import\s+[^\n]*\bTelnet\b/.test(cleanContent) ? /(?:telnetlib\.|(?<![\w.]))Telnet\s*\(/ : /telnetlib\.Telnet\s*\(/);
    if (idx_8839 !== -1) {
        const matchLineIdx = idx_8839;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Telnetlib Usage (Cleartext Management Protocol)";
        findings.push({
            id: `py8839-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8839,
            type: 'SECURITY',
            title: "PY-SEC-39: Insecure Telnetlib Usage (Cleartext Management Protocol)",
            severity: "MEDIUM",
            category: "Cleartext Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: telnetlib transmits all command inputs, passwords, and server output in plaintext."
            ],
            remediationPrompt: "Use SSH (paramiko or asyncssh) for remote administrative shell access.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-39: Insecure Telnetlib Usage (Cleartext Management Protocol) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-40: Unsafe PyTorch Model Loading via torch.load Without weights_only
    const idx_8840 = pyFindLine(lines, /(?<![\w.])torch\.load\s*\(/, (_l, i) => !/weights_only\s*=\s*True/.test(callText(lines, i, /torch\.load\s*\(/)));
    if (idx_8840 !== -1) {
        const matchLineIdx = idx_8840;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Unsafe PyTorch Model Loading via torch.load Without weights_only";
        findings.push({
            id: `py8840-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8840,
            type: 'SECURITY',
            title: "PY-SEC-40: Unsafe PyTorch Model Loading via torch.load Without weights_only",
            severity: "HIGH",
            category: "Insecure Deserialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: torch.load() defaults to pickle deserialization, allowing arbitrary code execution when loading untrusted model checkpoints."
            ],
            remediationPrompt: "Pass weights_only=True to torch.load() or use safetensors format.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-40: Unsafe PyTorch Model Loading via torch.load Without weights_only at ${file.path}:${lineNum}`);
    }
    // PY-SEC-41: Insecure TarFile Extraction Vulnerable to Arbitrary File Overwrite
    const idx_8841 = (() => {
        const tars = new Set<string>();
        for (const l of lines) {
            const assigned = /(\w+)\s*=\s*tarfile\.open\s*\(/.exec(l);
            if (assigned) tars.add(assigned[1]);
            const ctx = /tarfile\.open\s*\(.*\)\s+as\s+(\w+)\s*:/.exec(l);
            if (ctx) tars.add(ctx[1]);
        }
        const call = /(?:tarfile\.open\s*\([^)]*\)|\b(\w+))\.extractall\s*\(/;
        return pyFindLine(lines, call, (l, i) => {
            const m = call.exec(l) as RegExpExecArray;
            if (m[1] && !tars.has(m[1])) return false;
            return !/\bfilter\s*=/.test(callText(lines, i, /\.extractall\s*\(/));
        });
    })();
    if (idx_8841 !== -1) {
        const matchLineIdx = idx_8841;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure TarFile Extraction Vulnerable to Arbitrary File Overwrite";
        findings.push({
            id: `py8841-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8841,
            type: 'SECURITY',
            title: "PY-SEC-41: Insecure TarFile Extraction Vulnerable to Arbitrary File Overwrite",
            severity: "HIGH",
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: tarfile.extractall() without destination path validation allows malicious tar archives to overwrite system files."
            ],
            remediationPrompt: "Use filter=\"data\" (Python 3.12+) or validate that member names resolve within the target directory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-41: Insecure TarFile Extraction Vulnerable to Arbitrary File Overwrite at ${file.path}:${lineNum}`);
    }
    // PY-SEC-42: Insecure ZipFile Extraction Vulnerable to Zip Slip
    const idx_8842 = /\bzipfile\b|ZipFile/.test(cleanContent) ? pyFindLine(lines, /(?<![\w.])open\s*\(\s*(?:os\.path\.join\s*\([^)]*\b\w+\.filename\s*\)|[fF]['"][^'"]*\{\w+\.filename\}[^'"]*['"])\s*,\s*['"]wb?['"]/) : -1;
    if (idx_8842 !== -1) {
        const matchLineIdx = idx_8842;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure ZipFile Extraction Vulnerable to Zip Slip";
        findings.push({
            id: `py8842-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8842,
            type: 'SECURITY',
            title: "PY-SEC-42: Insecure ZipFile Extraction Vulnerable to Zip Slip",
            severity: "HIGH",
            category: "Path Traversal",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: ZipFile.extractall() extracting archive members containing directory traversal sequences (../) risks Zip Slip."
            ],
            remediationPrompt: "Inspect zipinfo.filename to ensure target extraction paths reside within the designated directory.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-42: Insecure ZipFile Extraction Vulnerable to Zip Slip at ${file.path}:${lineNum}`);
    }
    // PY-SEC-43: Insecure Cipher Mode (ECB Mode in PyCryptodome / Cryptography)
    const idx_8843 = pyFindLine(lines, /(?:AES|DES|DES3|Blowfish|ARC2|CAST)\.MODE_ECB\b|modes\.ECB\s*\(/);
    if (idx_8843 !== -1) {
        const matchLineIdx = idx_8843;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Cipher Mode (ECB Mode in PyCryptodome / Cryptography)";
        findings.push({
            id: `py8843-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8843,
            type: 'SECURITY',
            title: "PY-SEC-43: Insecure Cipher Mode (ECB Mode in PyCryptodome / Cryptography)",
            severity: "HIGH",
            category: "Broken Cryptography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Using ECB mode (Electronic Codebook) does not provide semantic security and leaks plaintext patterns."
            ],
            remediationPrompt: "Use authenticated encryption modes such as AES-GCM (AES.MODE_GCM) or ChaCha20-Poly1305.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-43: Insecure Cipher Mode (ECB Mode in PyCryptodome / Cryptography) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-44: JWT Signature Verification Disabled in PyJWT
    const idx_8844 = (() => {
        const direct = pyFindLine(lines, /jwt\.decode\s*\([^)]*(?:\bverify\s*=\s*False|['"]verify_signature['"]\s*:\s*False)/);
        if (direct !== -1) return direct;
        return pyFindLine(lines, /['"]verify_signature['"]\s*:\s*False/, (_l, i) => /jwt\.decode\s*\(/.test(lines.slice(Math.max(0, i - 4), i + 1).join('\n')));
    })();
    if (idx_8844 !== -1) {
        const matchLineIdx = idx_8844;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "JWT Signature Verification Disabled in PyJWT";
        findings.push({
            id: `py8844-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8844,
            type: 'SECURITY',
            title: "PY-SEC-44: JWT Signature Verification Disabled in PyJWT",
            severity: "CRITICAL",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Calling jwt.decode() with verify_signature=False or options={\"verify_signature\": False} trusts forged tokens."
            ],
            remediationPrompt: "Always verify JWT signatures with a trusted secret or public key and enforce expiration checks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-44: JWT Signature Verification Disabled in PyJWT at ${file.path}:${lineNum}`);
    }
    // PY-SEC-45: Missing Request Timeout on Python Requests / HTTPX Calls
    // `requests` has no default timeout (httpx does), so a module-level requests call without timeout= can hang forever
    const reqCall_8845 = /(?<![\w.])requests\.(?:get|post|put|delete|patch|head|request)\s*\(/;
    const idx_8845 = pyFindLine(lines, reqCall_8845, (_l, i) => !/\btimeout\s*=|\*\*\w+/.test(callText(lines, i, reqCall_8845)));
    if (idx_8845 !== -1) {
        const matchLineIdx = idx_8845;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Missing Request Timeout on Python Requests / HTTPX Calls";
        findings.push({
            id: `py8845-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8845,
            type: 'SECURITY',
            title: "PY-SEC-45: Missing Request Timeout on Python Requests / HTTPX Calls",
            severity: "LOW",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Invoking requests.get() or requests.post() without an explicit timeout parameter allows hanging connections to exhaust worker threads."
            ],
            remediationPrompt: "Always specify an explicit timeout (e.g., timeout=10) on outbound HTTP requests.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-45: Missing Request Timeout on Python Requests / HTTPX Calls at ${file.path}:${lineNum}`);
    }
    // PY-SEC-46: Unrestricted File Upload Without Extension or Content Validation
    const idx_8846 = /request\.files\b/.test(cleanContent) ? pyFindLine(lines, /\.save\s*\(\s*(?:os\.path\.join\s*\([^)]*?\b\w+\.filename\b|[fF]['"][^'"]*\{\w+\.filename\}|\w+\.filename\s*\))/, (l) => !/secure_filename/.test(l)) : -1;
    if (idx_8846 !== -1) {
        const matchLineIdx = idx_8846;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Unrestricted File Upload Without Extension or Content Validation";
        findings.push({
            id: `py8846-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8846,
            type: 'SECURITY',
            title: "PY-SEC-46: Unrestricted File Upload Without Extension or Content Validation",
            severity: "HIGH",
            category: "Unrestricted Upload",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Saving uploaded files directly via file.save() without checking file extensions or MIME types allows arbitrary executable uploads."
            ],
            remediationPrompt: "Validate file extensions against an allowlist and use secure_filename() before saving.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-46: Unrestricted File Upload Without Extension or Content Validation at ${file.path}:${lineNum}`);
    }
    // PY-SEC-49: Django SESSION_COOKIE_AGE Overly Permissive (> 30 Days)
    // Literal age above 30 days (2,592,000 s)
    const idx_8849 = pyFindLine(lines, /^\s*SESSION_COOKIE_AGE\s*=\s*(\d[\d_]*)\s*$/, (l) => Number(/=\s*(\d[\d_]*)/.exec(l)![1].replace(/_/g, '')) > 2592000);
    if (idx_8849 !== -1) {
        const matchLineIdx = idx_8849;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django SESSION_COOKIE_AGE Overly Permissive (> 30 Days)";
        findings.push({
            id: `py8849-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8849,
            type: 'SECURITY',
            title: "PY-SEC-49: Django SESSION_COOKIE_AGE Overly Permissive (> 30 Days)",
            severity: "LOW",
            category: "Broken Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting SESSION_COOKIE_AGE to values exceeding 30 days keeps sessions active indefinitely, increasing exposure window."
            ],
            remediationPrompt: "Set SESSION_COOKIE_AGE to a reasonable duration (e.g., 1209600 for 14 days) and implement session invalidation on logout.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-49: Django SESSION_COOKIE_AGE Overly Permissive (> 30 Days) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-50: Insecure Multiprocessing Manager Without Authentication Key
    const idx_8850 = pyFindLine(lines, /\w*Manager\s*\(.*\bauthkey\s*=\s*b?(?:''|"")/, () => /multiprocessing/.test(cleanContent));
    if (idx_8850 !== -1) {
        const matchLineIdx = idx_8850;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Multiprocessing Manager Without Authentication Key";
        findings.push({
            id: `py8850-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8850,
            type: 'SECURITY',
            title: "PY-SEC-50: Insecure Multiprocessing Manager Without Authentication Key",
            severity: "HIGH",
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Exposing multiprocessing.managers.BaseManager across network sockets without an authkey allows unauthenticated RCE."
            ],
            remediationPrompt: "Always configure a cryptographically strong authkey when sharing multiprocessing managers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-50: Insecure Multiprocessing Manager Without Authentication Key at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}

/** Settings / config modules meant for local development or tests (dev-only values are expected there). */
function isDevSettingsPath(lowerPath: string): boolean {
    return /(?:^|\/|_)(?:dev|develop|development|local|test|tests|testing|ci)(?:_settings|_config)?\.py$|settings_(?:dev|local|test)\.py$|(?:^|\/)(?:examples?|docs?|samples?)\//.test(lowerPath);
}

/** A Python source line that is code (not blank, not a # comment). */
function pyIsCode(line: string): boolean {
    const t = line.trim();
    return t !== '' && !t.startsWith('#');
}

/** First code line matching `re` (and `ok`, when given), or -1. */
function pyFindLine(lines: string[], re: RegExp, ok?: (line: string, idx: number) => boolean): number {
    return lines.findIndex((l, i) => pyIsCode(l) && re.test(l) && (!ok || ok(l, i)));
}

/** Body line range [from, to] of the def / with / class block whose header starts at `start` (indentation based). */
function pyBlockRange(lines: string[], start: number): [number, number] {
    const indent = (s: string) => s.length - s.trimStart().length;
    let headerEnd = start;
    while (headerEnd < lines.length - 1 && !/:\s*(?:#.*)?$/.test(lines[headerEnd].trimEnd())) headerEnd++;
    const base = indent(lines[start]);
    let end = headerEnd;
    for (let i = headerEnd + 1; i < lines.length; i++) {
        if (lines[i].trim() === '') continue;
        if (indent(lines[i]) <= base) break;
        end = i;
    }
    return [headerEnd + 1, end];
}

/** Names assigned straight from a Flask / Django / Starlette request accessor in this file. */
function pyRequestVars(lines: string[]): Set<string> {
    const names = new Set<string>();
    for (const l of lines) {
        const m = /^\s*(\w+)\s*(?::\s*[\w[\], |]+)?=\s*(?:await\s+)?request\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|query_params|path_params|get_json|body)\b/.exec(l);
        if (m) names.add(m[1]);
    }
    return names;
}

/** Text of the call matched by `re` on line `idx`, up to its balanced closing parenthesis (max 12 lines). */
function callText(lines: string[], idx: number, re: RegExp): string {
    const m = re.exec(lines[idx]);
    let out = '';
    let depth = 0;
    for (let i = idx; i < Math.min(lines.length, idx + 12); i++) {
        const seg = i === idx && m ? lines[i].slice(m.index) : lines[i];
        for (const ch of seg) {
            out += ch;
            if (ch === '(') depth++;
            else if (ch === ')' && --depth === 0) return out;
        }
        out += '\n';
    }
    return out;
}

/** A database / broker URL with an inline password that is not a local-dev default or placeholder. */
function hasDbUrlWithRealPassword(line: string): boolean {
    const m = /(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)(?:\+\w+)?:\/\/([^:/\s'"@]*):([^@/\s'"]+)@([^/:\s'"?]+)/i.exec(line);
    if (!m) return false;
    const [, , password, host] = m;
    if (/^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)$/i.test(host)) return false;
    return !/[{}$<>%]|^(?:password|pass|passwd|pwd|secret|changeme|change_?me|example|x{3,}|\*+|user|postgres|root|admin)$/i.test(password);
}
