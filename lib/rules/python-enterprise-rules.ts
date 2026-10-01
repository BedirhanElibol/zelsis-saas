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
    const reg_8803 = /(?:subprocess\.(?:Popen|run|call|check_output|check_call)\s*\([\s\S]*?shell\s*=\s*True|os\.(?:system|popen)\s*\()/i;
    if (reg_8803.test(cleanContent)) {
        const linePattern = /(?:subprocess\.(?:Popen|run|call|check_output|check_call)|shell\s*=\s*True|os\.(?:system|popen))/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Subprocess Execution with shell=True";
        findings.push({
            id: `py8803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8803,
            type: 'SECURITY',
            title: "PY-SEC-03: Subprocess Execution with shell=True",
            severity: "CRITICAL",
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
    const reg_8804 = /(?:(?:cursor|conn|db|session)\.execute\s*\(\s*(?:f['"]|['"][^'"]*%\s*\(|['"][^'"]*\.format\()|text\s*\(\s*f['"]|f["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']*(?:\{|%))/i;
    if (reg_8804.test(cleanContent)) {
        const linePattern = /(?:execute|text|SELECT|INSERT|UPDATE|DELETE)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Python SQL Injection via String Interpolation (f-string / format / %)";
        findings.push({
            id: `py8804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8804,
            type: 'SECURITY',
            title: "PY-SEC-04: Python SQL Injection via String Interpolation (f-string / format / %)",
            severity: "CRITICAL",
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
    const reg_8805 = /(?:(?:^|\s)DEBUG\s*=\s*True\b|app\.run\s*\([^)]*debug\s*=\s*True)/m;
    if (reg_8805.test(cleanContent)) {
        const linePattern = /(?:DEBUG\s*=\s*True|debug\s*=\s*True)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django / Flask DEBUG Mode Enabled in Production Settings";
        findings.push({
            id: `py8805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8805,
            type: 'SECURITY',
            title: "PY-SEC-05: Django / Flask DEBUG Mode Enabled in Production Settings",
            severity: "HIGH",
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
    const reg_8806 = /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][\s\S]*?allow_credentials\s*=\s*True/i;
    if (reg_8806.test(cleanContent)) {
        const linePattern = /allow_origins|allow_credentials/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8807 = /async\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*\)[\s\S]*?(?:time\.sleep\s*\(|requests\.(?:get|post|put|delete)\s*\()/i;
    if (reg_8807.test(cleanContent)) {
        const linePattern = /(?:time\.sleep|requests\.(?:get|post|put|delete))/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Blocking Synchronous I/O Inside FastAPI async def Handler";
        findings.push({
            id: `py8807-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8807,
            type: 'SECURITY',
            title: "PY-SEC-07: Blocking Synchronous I/O Inside FastAPI async def Handler",
            severity: "HIGH",
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
    const reg_8808 = /(?:task_serializer|accept_content|result_serializer)\s*=\s*(?:\[\s*)?['"]pickle['"]/i;
    if (reg_8808.test(cleanContent)) {
        const linePattern = /(?:task_serializer|accept_content|result_serializer)\s*=\s*(?:\[\s*)?['"]pickle['"]/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8809 = /(?:SECRET_KEY|JWT_SECRET|API_KEY)\s*=\s*['"][a-zA-Z0-9!@#$%^&*()_+=-]{8,}['"]/i;
    if (reg_8809.test(cleanContent)) {
        const linePattern = /(?:SECRET_KEY|JWT_SECRET|API_KEY)\s*=\s*['"][a-zA-Z0-9!@#$%^&*()_+=-]{8,}['"]/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Hardcoded Secret Key in Flask / Django Settings";
        findings.push({
            id: `py8809-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8809,
            type: 'SECURITY',
            title: "PY-SEC-09: Hardcoded Secret Key in Flask / Django Settings",
            severity: "CRITICAL",
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
    const reg_8810 = /(?:jinja2\.Template\s*\([^)]*\)\.render|render_template_string\s*\()/i;
    if (reg_8810.test(cleanContent)) {
        const linePattern = /(?:jinja2\.Template|render_template_string)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8811 = /\b(?:eval|exec|compile)\s*\(\s*(?!'[^']*'|"[^"]*")[a-zA-Z0-9_]+/i;
    if (reg_8811.test(cleanContent)) {
        const linePattern = /\b(?:eval|exec|compile)\s*\(/i;
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
    const reg_8812 = /hashlib\.(?:md5|sha1)\s*\(/i;
    if (reg_8812.test(cleanContent)) {
        const linePattern = /hashlib\.(?:md5|sha1)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8813 = /tempfile\.mktemp\s*\(/i;
    if (reg_8813.test(cleanContent)) {
        const linePattern = /tempfile\.mktemp\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Temporary File Creation via tempfile.mktemp()";
        findings.push({
            id: `py8813-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8813,
            type: 'SECURITY',
            title: "PY-SEC-13: Insecure Temporary File Creation via tempfile.mktemp()",
            severity: "HIGH",
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
    const reg_8815 = /(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xmlrpclib|lxml\.etree)\.(?:parse|fromstring)\s*\(/i;
    if (reg_8815.test(cleanContent)) {
        const linePattern = /(?:ElementTree|minidom|xmlrpclib|lxml\.etree)\.(?:parse|fromstring)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8816 = /(?:open|send_file|send_from_directory)\s*\(\s*(?:os\.path\.join\([^)]*request\.|request\.(?:args|GET|POST|values|json)|f['"][^'"]*\{request\.)/i;
    if (reg_8816.test(cleanContent)) {
        const linePattern = /(?:open|send_file|send_from_directory)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8817 = /@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False\b/i;
    if (reg_8817.test(cleanContent)) {
        const linePattern = /@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False)";
        findings.push({
            id: `py8817-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8817,
            type: 'SECURITY',
            title: "PY-SEC-17: CSRF Protection Disabled (@csrf_exempt / WTF_CSRF_ENABLED = False)",
            severity: "HIGH",
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
    const reg_8818 = /(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\([^)]*verify\s*=\s*False|ssl\._create_unverified_context\s*\(/i;
    if (reg_8818.test(cleanContent)) {
        const linePattern = /verify\s*=\s*False|_create_unverified_context/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8819 = /(?:shelve\.open|marshal\.loads?)\s*\(/i;
    if (reg_8819.test(cleanContent)) {
        const linePattern = /(?:shelve\.open|marshal\.loads?)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8820 = /(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9!@#$%^&*()_+=-]+@[a-zA-Z0-9.-]+/i;
    if (reg_8820.test(cleanContent)) {
        const linePattern = /(?:postgres|postgresql|mysql|mongodb|redis):\/\//i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8821 = /paramiko\.AutoAddPolicy\s*\(/i;
    if (reg_8821.test(cleanContent)) {
        const linePattern = /paramiko\.AutoAddPolicy/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8822 = /SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False/i;
    if (reg_8822.test(cleanContent)) {
        const linePattern = /SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SECURE/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    // PY-SEC-23: Insecure Server Binding to All Network Interfaces (0.0.0.0)
    const reg_8823 = /(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]/i;
    if (reg_8823.test(cleanContent)) {
        const linePattern = /(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Server Binding to All Network Interfaces (0.0.0.0)";
        findings.push({
            id: `py8823-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8823,
            type: 'SECURITY',
            title: "PY-SEC-23: Insecure Server Binding to All Network Interfaces (0.0.0.0)",
            severity: "MEDIUM",
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Binding debug servers or internal admin listeners to 0.0.0.0 exposes internal ports to external network interfaces."
            ],
            remediationPrompt: "Bind local development servers to 127.0.0.1 or configure a reverse proxy for external exposure.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-23: Insecure Server Binding to All Network Interfaces (0.0.0.0) at ${file.path}:${lineNum}`);
    }
    // PY-SEC-24: Use of Assert Statement for Security or Authorization Checks
    const reg_8824 = /assert\s+(?:user\.|role\.|is_admin|token|auth|permission|request\.)/i;
    if (reg_8824.test(cleanContent)) {
        const linePattern = /assert\s+(?:user\.|role\.|is_admin|token|auth|permission)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Use of Assert Statement for Security or Authorization Checks";
        findings.push({
            id: `py8824-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8824,
            type: 'SECURITY',
            title: "PY-SEC-24: Use of Assert Statement for Security or Authorization Checks",
            severity: "HIGH",
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
    const reg_8825 = /app\.secret_key\s*=\s*['"][^'"]{1,32}['"]/i;
    if (reg_8825.test(cleanContent)) {
        const linePattern = /app\.secret_key\s*=/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8826 = /(?:token|password|secret|auth|nonce|salt)\s*=[\s\S]*?random\.(?:random|choice|randint|randrange|choices)\s*\(/i;
    if (reg_8826.test(cleanContent)) {
        const linePattern = /random\.(?:random|choice|randint|randrange|choices)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8827 = /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/i;
    if (reg_8827.test(cleanContent)) {
        const linePattern = /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8828 = /['"]AKIA[0-9A-Z]{16}['"]/i;
    if (reg_8828.test(cleanContent)) {
        const linePattern = /AKIA[0-9A-Z]{16}/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8829 = /(?:redirect|HttpResponseRedirect)\s*\(\s*request\.(?:args|GET|values|json)\[['"](?:next|url|redirect_to)['"]\]/i;
    if (reg_8829.test(cleanContent)) {
        const linePattern = /(?:redirect|HttpResponseRedirect)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8830 = /\.execute\s*\(\s*['"][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*['"]\s*%\s*[a-zA-Z0-9_]+/i;
    if (reg_8830.test(cleanContent)) {
        const linePattern = /\.execute\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8831 = /\.objects\.(?:create|filter\([^)]*\)\.update)\s*\(\s*\*\*request\.(?:data|POST)/i;
    if (reg_8831.test(cleanContent)) {
        const linePattern = /\.objects\.(?:create|update)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8832 = /(?:ldap|ldap3)\.search\s*\([^)]*f['"][^"']*\([a-zA-Z0-9_]+=\{/i;
    if (reg_8832.test(cleanContent)) {
        const linePattern = /ldap(?:3)?\.search/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8833 = /re\.compile\s*\(\s*['"][^'"]*\([^)]+[+*]\)[+*]/i;
    if (reg_8833.test(cleanContent)) {
        const linePattern = /re\.compile/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8834 = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i;
    if (reg_8834.test(cleanContent)) {
        const linePattern = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8835 = /except(?:\s+Exception)?\s*:\s*(?:pass|continue)\b/i;
    if (reg_8835.test(cleanContent)) {
        const linePattern = /except(?:\s+Exception)?\s*:\s*(?:pass|continue)/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Broad Exception Handling Swallowing Critical Errors (except: pass)";
        findings.push({
            id: `py8835-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8835,
            type: 'SECURITY',
            title: "PY-SEC-35: Broad Exception Handling Swallowing Critical Errors (except: pass)",
            severity: "MEDIUM",
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
    const reg_8836 = /SECURE_HSTS_SECONDS\s*=\s*0\b/i;
    if (reg_8836.test(cleanContent)) {
        const linePattern = /SECURE_HSTS_SECONDS\s*=\s*0/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    // PY-SEC-37: Django SECURE_SSL_REDIRECT Disabled in Production
    const reg_8837 = /SECURE_SSL_REDIRECT\s*=\s*False\b/i;
    if (reg_8837.test(cleanContent)) {
        const linePattern = /SECURE_SSL_REDIRECT\s*=\s*False/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Django SECURE_SSL_REDIRECT Disabled in Production";
        findings.push({
            id: `py8837-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8837,
            type: 'SECURITY',
            title: "PY-SEC-37: Django SECURE_SSL_REDIRECT Disabled in Production",
            severity: "MEDIUM",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting SECURE_SSL_REDIRECT = False allows unencrypted HTTP connections to access application endpoints."
            ],
            remediationPrompt: "Set SECURE_SSL_REDIRECT = True in production settings.py.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-37: Django SECURE_SSL_REDIRECT Disabled in Production at ${file.path}:${lineNum}`);
    }
    // PY-SEC-38: Insecure FTPLib Usage Without TLS (Plaintext FTP)
    const reg_8838 = /ftplib\.FTP\s*\(/i;
    if (reg_8838.test(cleanContent)) {
        const linePattern = /ftplib\.FTP\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure FTPLib Usage Without TLS (Plaintext FTP)";
        findings.push({
            id: `py8838-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8838,
            type: 'SECURITY',
            title: "PY-SEC-38: Insecure FTPLib Usage Without TLS (Plaintext FTP)",
            severity: "HIGH",
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
    const reg_8839 = /telnetlib\.Telnet\s*\(/i;
    if (reg_8839.test(cleanContent)) {
        const linePattern = /telnetlib\.Telnet/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Telnetlib Usage (Cleartext Management Protocol)";
        findings.push({
            id: `py8839-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8839,
            type: 'SECURITY',
            title: "PY-SEC-39: Insecure Telnetlib Usage (Cleartext Management Protocol)",
            severity: "CRITICAL",
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
    const reg_8840 = /torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)[^)]*\)/i;
    if (reg_8840.test(cleanContent)) {
        const linePattern = /torch\.load\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8841 = /\.extractall\s*\([^)]*(?!filter\s*=)[^)]*\)/i;
    if (reg_8841.test(cleanContent)) {
        const linePattern = /\.extractall\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8842 = /zipfile\.ZipFile\([^)]*\)\.extractall\s*\(/i;
    if (reg_8842.test(cleanContent)) {
        const linePattern = /zipfile\.ZipFile/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8843 = /(?:AES|DES)\.MODE_ECB\b/i;
    if (reg_8843.test(cleanContent)) {
        const linePattern = /MODE_ECB/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8844 = /jwt\.decode\s*\([^)]*['"]verify_signature['"]\s*:\s*False/i;
    if (reg_8844.test(cleanContent)) {
        const linePattern = /verify_signature/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8845 = /requests\.(?:get|post|put|delete|patch)\s*\([^)]*(?!timeout\s*=)[^)]*\)/i;
    if (reg_8845.test(cleanContent)) {
        const linePattern = /requests\.(?:get|post|put|delete|patch)\s*\(/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Missing Request Timeout on Python Requests / HTTPX Calls";
        findings.push({
            id: `py8845-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8845,
            type: 'SECURITY',
            title: "PY-SEC-45: Missing Request Timeout on Python Requests / HTTPX Calls",
            severity: "MEDIUM",
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
    const reg_8846 = /request\.files\[['"][^'"]*['"]\]\.save\s*\(/i;
    if (reg_8846.test(cleanContent)) {
        const linePattern = /request\.files/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    // PY-SEC-47: Insecure Socket Binding with SO_REUSEADDR on Multi-User Host
    const reg_8847 = /setsockopt\s*\([^)]*SO_REUSEADDR\s*,\s*1\s*\)/i;
    if (reg_8847.test(cleanContent)) {
        const linePattern = /SO_REUSEADDR/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "Insecure Socket Binding with SO_REUSEADDR on Multi-User Host";
        findings.push({
            id: `py8847-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8847,
            type: 'SECURITY',
            title: "PY-SEC-47: Insecure Socket Binding with SO_REUSEADDR on Multi-User Host",
            severity: "LOW",
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: Setting SO_REUSEADDR on listening sockets in shared environments can allow port hijacking by other local users."
            ],
            remediationPrompt: "Avoid SO_REUSEADDR on multi-user systems or use SO_REUSEPORT with strict UID verification.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-47: Insecure Socket Binding with SO_REUSEADDR on Multi-User Host at ${file.path}:${lineNum}`);
    }
    // PY-SEC-48: GraphQL Query Depth Limit Unconfigured in Strawberry / Graphene
    const reg_8848 = /(?:strawberry|graphene)\.Schema\s*\([^)]*query\s*=[^)]*\)/i;
    if (reg_8848.test(cleanContent)) {
        const linePattern = /(?:strawberry|graphene)\.Schema/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const rawSnippet = matchLineIdx !== -1 ? lines[matchLineIdx].trim() : lines.find(l => !l.trim().startsWith('#'))?.trim() || "GraphQL Query Depth Limit Unconfigured in Strawberry / Graphene";
        findings.push({
            id: `py8848-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8848,
            type: 'SECURITY',
            title: "PY-SEC-48: GraphQL Query Depth Limit Unconfigured in Strawberry / Graphene",
            severity: "MEDIUM",
            category: "Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: rawSnippet,
            reproductionSteps: [
                `Audited Python source in ${file.path}:${lineNum}.`,
                "Detected security violation: GraphQL endpoints without query depth or complexity limits are vulnerable to deeply nested DoS queries."
            ],
            remediationPrompt: "Configure query depth and complexity limits on GraphQL schema executors.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [PYTHON AUDIT] Found PY-SEC-48: GraphQL Query Depth Limit Unconfigured in Strawberry / Graphene at ${file.path}:${lineNum}`);
    }
    // PY-SEC-49: Django SESSION_COOKIE_AGE Overly Permissive (> 30 Days)
    const reg_8849 = /SESSION_COOKIE_AGE\s*=\s*(?:[3-9]\d{7,}|\d{8,})/i;
    if (reg_8849.test(cleanContent)) {
        const linePattern = /SESSION_COOKIE_AGE/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
    const reg_8850 = /BaseManager\s*\([^)]*authkey\s*=\s*(?:None|b?['"]['"])/i;
    if (reg_8850.test(cleanContent)) {
        const linePattern = /BaseManager/i;
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && !l.trim().startsWith('"""') && linePattern.test(l));
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
