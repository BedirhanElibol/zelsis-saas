/**
 * Polyglot Backend & Database Security Rules Engine (PHP, Java, C# / .NET, Ruby, NoSQL, Firebase)
 * Fulfills audit findings F-44, F-45, F-25, F-37:
 * Addresses missing multi-language coverage across enterprise web and cloud backends.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface PolyglotBackendRuleResult {
    findings: Finding[];
    logs: string[];
}
/** PHP request input: superglobals, Laravel Request / request() helper, Cookie facade. */
const PHP_REQUEST_SOURCE = /\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|get|query|post|cookie|getContent|all|header)\s*\(|\$request->\w+\b(?!\s*\()|\brequest\s*\(\s*['")]|Request::(?:input|get|query|cookie)\s*\(|Cookie::get\s*\(/;
function extractSnippet(lines: string[], lineNum: number): string {
    const targetIdx = Math.max(0, lineNum - 1);
    const start = Math.max(0, targetIdx - 2);
    const end = Math.min(lines.length, targetIdx + 3);
    return lines.slice(start, end).join('\n');
}
export function evaluatePolyglotBackendRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): PolyglotBackendRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and node_modules
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // =========================================================================
    // 1. PHP SECURITY RULES (*.php, *.phtml, *.inc)
    // =========================================================================
    const isPhp = lowerPath.endsWith('.php') || lowerPath.endsWith('.phtml') || lowerPath.endsWith('.inc');
    if (isPhp) {
        // PHP-01: SQL Injection via unparameterized input concatenation
        const phpSqliRegex = /(?:mysql_query|mysqli_query|\$pdo->query|\$pdo->exec|\$db->query)\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\.|\$[a-zA-Z0-9_]+\s*\.|\s*"\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*\$_(?:GET|POST|REQUEST|COOKIE))/i;
        const phpConcatSql = /\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\][\s\S]*?(?:SELECT|INSERT|UPDATE|DELETE)/i;
        if (phpSqliRegex.test(cleanContent) || (phpConcatSql.test(cleanContent) && /(?:query|exec)\s*\(/i.test(cleanContent))) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && (phpSqliRegex.test(l) || /\$_(?:GET|POST|REQUEST)/.test(l)));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `php-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18001,
                type: 'SECURITY',
                title: 'PHP-SEC-01: SQL Injection via Unparameterized Query Concatenation',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'mysqli_query($conn, "SELECT ... " . $_GET["id"])',
                reproductionSteps: [
                    `Scanned PHP source file at ${file.path}:${lineNum}.`,
                    'Detected database query formatted with raw HTTP user parameters ($_GET/$_POST/$_REQUEST) without PDO prepared statements or parameterized binding.'
                ],
                remediationPrompt: 'Use PDO prepared statements with parameter binding: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute([":id" => $id]);',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: SQL Injection in ${file.path}:${lineNum}`);
        }
        // PHP-02: Local File Inclusion (LFI / Path Traversal)
        const phpLfiRegex = /(?:include|require|include_once|require_once)\s*\(?\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$[a-zA-Z0-9_]+\s*\.)/i;
        if (phpLfiRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && phpLfiRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `php-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18002,
                type: 'SECURITY',
                title: 'PHP-SEC-02: Local File Inclusion (LFI) via Dynamic include/require',
                severity: 'CRITICAL',
                category: 'Path Traversal',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'include($_GET["page"] . ".php")',
                reproductionSteps: [
                    `Scanned PHP file inclusion logic at ${file.path}:${lineNum}.`,
                    'Detected dynamic file inclusion using unvalidated user input, enabling arbitrary local file inclusion (LFI) and remote code execution.'
                ],
                remediationPrompt: 'Whitelist allowable file paths through a strict array lookup or avoid dynamic file inclusion completely.',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: Local File Inclusion in ${file.path}:${lineNum}`);
        }
        // PHP-03: Command Injection via shell execution
        // Global shell functions only (not $pdo->exec / Foo::system), with request input or an unescaped
        // variable concatenated / interpolated into the command string.
        const phpCmdRegex = /(?<![\w>:$])(?:exec|shell_exec|system|passthru|proc_open|popen)\s*\(\s*(.*)/i;
        const phpCmdTainted = (arg: string) => !/escapeshell(?:arg|cmd)\s*\(/i.test(arg) &&
            (PHP_REQUEST_SOURCE.test(arg) || /^(?:"[^"]*"|'[^']*')\s*\.\s*\$\w+|^\$\w+\s*\.|^"[^"]*\$\w+/.test(arg));
        const phpCmdIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && !l.trim().startsWith('*') && phpCmdRegex.test(l) && phpCmdTainted((phpCmdRegex.exec(l) as RegExpExecArray)[1]));
        if (phpCmdIdx !== -1) {
            const matchLineIdx = phpCmdIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `php-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18003,
                type: 'SECURITY',
                title: 'PHP-SEC-03: OS Command Injection via shell_exec / system',
                severity: 'CRITICAL',
                category: 'Command Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'shell_exec($_GET["cmd"])',
                reproductionSteps: [
                    `Scanned system execution handlers in ${file.path}:${lineNum}.`,
                    'Detected shell execution functions invoked with unsanitized HTTP input parameters.'
                ],
                remediationPrompt: 'Avoid system shell execution. If necessary, escape arguments with escapeshellarg() or escapeshellcmd().',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: Command Injection in ${file.path}:${lineNum}`);
        }
        // PHP-04: Insecure Deserialization via unserialize()
        // Only request-controlled input (directly or via a variable assigned from it), and not when
        // object instantiation is disabled with ['allowed_classes' => false].
        const phpUnserializeRegex = /(?<![\w>:$])unserialize\s*\(\s*(.*)/i;
        const phpRequestVars = new Set<string>();
        for (let pass = 0; pass < 2; pass++) {
            for (const l of lines) {
                const m = /^\s*\$(\w+)\s*=\s*(.*)/.exec(l);
                if (m && (PHP_REQUEST_SOURCE.test(m[2]) || [...m[2].matchAll(/\$(\w+)/g)].some((v) => phpRequestVars.has(v[1])))) phpRequestVars.add(m[1]);
            }
        }
        const phpUnserializeIdx = lines.findIndex(l => {
            if (l.trim().startsWith('//') || l.trim().startsWith('#') || l.trim().startsWith('*') || !phpUnserializeRegex.test(l)) return false;
            const arg = (phpUnserializeRegex.exec(l) as RegExpExecArray)[1];
            if (/allowed_classes['"]\s*=>\s*false/i.test(arg)) return false;
            return PHP_REQUEST_SOURCE.test(arg) || [...arg.matchAll(/\$(\w+)/g)].some((v) => phpRequestVars.has(v[1]));
        });
        if (phpUnserializeIdx !== -1) {
            const matchLineIdx = phpUnserializeIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `php-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18004,
                type: 'SECURITY',
                title: 'PHP-SEC-04: Insecure PHP Object Deserialization via unserialize()',
                severity: 'CRITICAL',
                category: 'Insecure Deserialization',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'unserialize($_POST["data"])',
                reproductionSteps: [
                    `Scanned object deserialization calls in ${file.path}:${lineNum}.`,
                    'Detected native PHP unserialize() invoked on user-controlled inputs, allowing Object Injection and Remote Code Execution via POP chains.'
                ],
                remediationPrompt: 'Use json_decode() for data interchange. If unserialize() is required, pass allowed_classes => false option.',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [PHP AUDIT] CRITICAL: PHP Insecure Deserialization in ${file.path}:${lineNum}`);
        }
        // PHP-05: Reflected Cross-Site Scripting (XSS)
        const phpXssRegex = /(?:echo|print)\s+(?:\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\]|\$[a-zA-Z0-9_]+)/i;
        if (phpXssRegex.test(cleanContent) && !/htmlspecialchars|htmlentities|strip_tags/i.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('#') && phpXssRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `php-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18005,
                type: 'SECURITY',
                title: 'PHP-SEC-05: Reflected Cross-Site Scripting (XSS) via Direct Echo',
                severity: 'HIGH',
                category: 'Cross-Site Scripting',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'echo $_GET["name"]',
                reproductionSteps: [
                    `Scanned output rendering statements in ${file.path}:${lineNum}.`,
                    'Detected unencoded user request parameters echoed directly to output buffer without htmlspecialchars sanitization.'
                ],
                remediationPrompt: 'Sanitize output before rendering: echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
                status: 'OPEN',
                owner: 'Frontend/Backend Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [PHP AUDIT] HIGH: Reflected XSS in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 2. JAVA SECURITY RULES (*.java, *.jsp)
    // =========================================================================
    const isJava = lowerPath.endsWith('.java') || lowerPath.endsWith('.jsp');
    if (isJava) {
        // JAVA-01: Java SQL Injection via string concatenation
        const javaSqliRegex = /(?:executeQuery|executeUpdate|jdbcTemplate\.query|createQuery|createNativeQuery)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i;
        if (javaSqliRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && javaSqliRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `java-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18011,
                type: 'SECURITY',
                title: 'JAVA-SEC-01: SQL Injection via String Concatenation in Statement Execution',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'stmt.executeQuery("SELECT * FROM users WHERE id = " + id)',
                reproductionSteps: [
                    `Scanned Java database query at ${file.path}:${lineNum}.`,
                    'Detected JDBC Statement or JPA query constructed using string concatenation instead of PreparedStatement with parameterized query binding.'
                ],
                remediationPrompt: 'Use PreparedStatement with positional parameter markers (?): PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setString(1, id);',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [JAVA AUDIT] CRITICAL: Java SQL Injection in ${file.path}:${lineNum}`);
        }
        // JAVA-02: Hardcoded Secrets & Passwords in Source
        const javaHardcodedSecretRegex = /(?:String|char\[\])\s+(?:password|secretKey|apiKey|api_secret|auth_token)\s*=\s*["'][^"']{6,}["']/i;
        if (javaHardcodedSecretRegex.test(cleanContent) && !lowerPath.includes('test')) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && javaHardcodedSecretRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `java-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18012,
                type: 'SECURITY',
                title: 'JAVA-SEC-02: Hardcoded Password or Secret Key in Java Source Code',
                severity: 'HIGH',
                category: 'Hardcoded Secret',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'String password = "..."',
                reproductionSteps: [
                    `Scanned Java source in ${file.path}:${lineNum}.`,
                    'Detected plaintext password or authentication credential committed directly into source code.'
                ],
                remediationPrompt: 'Externalize credentials using environment variables (System.getenv("DB_PASSWORD")) or a secrets vault.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [JAVA AUDIT] HIGH: Hardcoded Credentials in ${file.path}:${lineNum}`);
        }
        // JAVA-03: Insecure Deserialization via ObjectInputStream
        const javaDeserializationRegex = /new\s+ObjectInputStream\b[\s\S]*?\.readObject\(\)/i;
        if (javaDeserializationRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && l.includes('readObject'));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `java-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18013,
                type: 'SECURITY',
                title: 'JAVA-SEC-03: Unrestricted Java Deserialization via ObjectInputStream.readObject',
                severity: 'CRITICAL',
                category: 'Insecure Deserialization',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'ois.readObject()',
                reproductionSteps: [
                    `Scanned serialization handlers in ${file.path}:${lineNum}.`,
                    'Detected ObjectInputStream.readObject() deserializing untrusted binary streams without class filter verification, enabling remote code execution via gadget chains.'
                ],
                remediationPrompt: 'Implement ObjectInputFilter or replace Java native serialization with safe data interchange formats such as JSON or Protocol Buffers.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [JAVA AUDIT] CRITICAL: Java Insecure Deserialization in ${file.path}:${lineNum}`);
        }
        // JAVA-04: Log4j / JNDI Lookup Injection
        const log4jJndiRegex = /\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nis|http)/i;
        if (log4jJndiRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => log4jJndiRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `java-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18014,
                type: 'SECURITY',
                title: 'JAVA-SEC-04: Log4Shell / JNDI Remote Code Execution Pattern (CVE-2021-44228)',
                severity: 'CRITICAL',
                category: 'Remote Code Execution',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || '${jndi:ldap://...}',
                reproductionSteps: [
                    `Scanned Java code at ${file.path}:${lineNum}.`,
                    'Detected Log4j JNDI lookup string pattern susceptible to arbitrary remote code execution via LDAP/RMI directory services.'
                ],
                remediationPrompt: 'Upgrade Log4j to >= 2.17.1 and set formatMsgNoLookups=true or sanitize logger inputs.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [JAVA AUDIT] CRITICAL: Log4Shell Pattern in ${file.path}:${lineNum}`);
        }
        // JAVA-05: Broken / Deprecated Cryptographic Ciphers & Hashes
        // Broken ciphers / ECB (plain "AES" defaults to ECB) always; MD5 / SHA-1 digests only next to
        // password handling, since checksums, ETags and cache keys use them legitimately.
        const javaWeakCipherRegex = /Cipher\.getInstance\s*\(\s*["'](?:(?:DES|RC4|ARCFOUR|RC2|Blowfish|DESede)(?:\/[^"']*)?|AES|[^"']*\/ECB\/[^"']*)["']\s*\)/i;
        const javaWeakDigestRegex = /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)/i;
        const javaWeakCryptoIdx = lines.findIndex((l, i) => !l.trim().startsWith('//') && !l.trim().startsWith('*') &&
            (javaWeakCipherRegex.test(l) || (javaWeakDigestRegex.test(l) && /passw(?:or)?d|\bpwd\b/i.test(lines.slice(Math.max(0, i - 3), i + 4).join('\n')))));
        if (javaWeakCryptoIdx !== -1) {
            const matchLineIdx = javaWeakCryptoIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `java-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18015,
                type: 'SECURITY',
                title: 'JAVA-SEC-05: Cryptographically Weak Cipher or Hash in Java (DES / RC4 / MD5 / ECB)',
                severity: 'HIGH',
                category: 'Cryptographic Weakness',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'Cipher.getInstance("DES")',
                reproductionSteps: [
                    `Scanned cryptographic providers in ${file.path}:${lineNum}.`,
                    'Detected broken symmetric cipher (DES/RC4/ECB) or collision-vulnerable hash (MD5/SHA-1).'
                ],
                remediationPrompt: 'Use AES-GCM (Cipher.getInstance("AES/GCM/NoPadding")) and SHA-256 for secure hashing.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [JAVA AUDIT] HIGH: Weak Java Cryptography in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 3. C# / .NET SECURITY RULES (*.cs, *.cshtml, *.vb)
    // =========================================================================
    const isCSharp = lowerPath.endsWith('.cs') || lowerPath.endsWith('.cshtml') || lowerPath.endsWith('.vb');
    if (isCSharp) {
        // CS-01: C# SQL Injection via string interpolation or concatenation
        const csSqliRegex = /(?:new\s+SqlCommand|Database\.SqlQueryRaw|FromSqlRaw)\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+|\$["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{)/i;
        if (csSqliRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && csSqliRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `cs-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18021,
                type: 'SECURITY',
                title: 'CS-SEC-01: C# SQL Injection via SqlCommand Interpolation / Concatenation',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'new SqlCommand($"SELECT * FROM Users WHERE Id = {id}")',
                reproductionSteps: [
                    `Scanned C# database command at ${file.path}:${lineNum}.`,
                    'Detected dynamic SQL construction via string interpolation ($"...") or concatenation without SqlParameter parameterization.'
                ],
                remediationPrompt: 'Use parameterized SqlCommand with parameters: cmd.Parameters.AddWithValue("@id", id) or Entity Framework FromSqlInterpolated.',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [C# AUDIT] CRITICAL: C# SQL Injection in ${file.path}:${lineNum}`);
        }
        // CS-02: Weak Cryptographic Algorithms (MD5, SHA1, DES)
        // Broken ciphers always; MD5 / SHA1 only next to password handling (checksums and ETags are fine).
        const csWeakCipherRegex = /(?:DESCryptoServiceProvider|RC2CryptoServiceProvider|TripleDESCryptoServiceProvider|\bDES\.Create|\bRC2\.Create)\s*\(/;
        const csWeakHashRegex = /(?:\bMD5\.(?:Create|HashData)|\bSHA1\.(?:Create|HashData)|MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed)\s*\(/;
        const csWeakCryptoIdx = lines.findIndex((l, i) => !l.trim().startsWith('//') && !l.trim().startsWith('*') &&
            (csWeakCipherRegex.test(l) || (csWeakHashRegex.test(l) && /passw(?:or)?d|\bpwd\b/i.test(lines.slice(Math.max(0, i - 3), i + 4).join('\n')))));
        if (csWeakCryptoIdx !== -1) {
            const matchLineIdx = csWeakCryptoIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `cs-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18022,
                type: 'SECURITY',
                title: 'CS-SEC-02: Cryptographically Broken Hash / Cipher Algorithm (MD5 / SHA1 / DES)',
                severity: 'HIGH',
                category: 'Cryptographic Weakness',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'MD5.Create()',
                reproductionSteps: [
                    `Scanned cryptographic primitives at ${file.path}:${lineNum}.`,
                    'Detected deprecated, collision-vulnerable cryptographic algorithm (MD5/SHA1/DES).'
                ],
                remediationPrompt: 'Upgrade to collision-resistant hash functions: SHA256.Create() or SHA512.Create(), and Aes.Create() for symmetric encryption.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [C# AUDIT] HIGH: Weak Cryptography in ${file.path}:${lineNum}`);
        }
        // CS-03: Insecure Deserialization via BinaryFormatter
        const csBinaryFormatterRegex = /new\s+BinaryFormatter\s*\(\s*\)[\s\S]*?\.Deserialize\s*\(/i;
        if (csBinaryFormatterRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && l.includes('Deserialize'));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `cs-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18023,
                type: 'SECURITY',
                title: 'CS-SEC-03: Insecure .NET Deserialization via BinaryFormatter (RCE Hazard)',
                severity: 'CRITICAL',
                category: 'Insecure Deserialization',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'formatter.Deserialize(stream)',
                reproductionSteps: [
                    `Scanned deserializer initialization at ${file.path}:${lineNum}.`,
                    'Detected BinaryFormatter.Deserialize() which is inherently unsafe in .NET and leads to arbitrary remote code execution.'
                ],
                remediationPrompt: 'Migrate to System.Text.Json or Protobuf-net. BinaryFormatter is obsolete and disallowed in modern .NET.',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [C# AUDIT] CRITICAL: BinaryFormatter Deserialization in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 4. RUBY / RAILS SECURITY RULES (*.rb, *.erb, *.rake)
    // =========================================================================
    const isRuby = lowerPath.endsWith('.rb') || lowerPath.endsWith('.erb') || lowerPath.endsWith('.rake');
    if (isRuby) {
        // RUBY-01: Ruby ActiveRecord SQL Injection
        // A value interpolated into the SQL fragment (after =, <, >, LIKE, IN) or params interpolated anywhere.
        // `where("#{table_name}.id = ?", id)` (identifier interpolation with a bound value) stays quiet.
        const rubySqliRegex = /(?:\bfind_by_sql|\bcount_by_sql|\.(?:where|not|order|reorder|having|pluck|joins|group|select|from|find_by|exists\?|delete_all|update_all|lock))\s*\(?\s*"[^"]*?(?:(?:=|<>|!=|<|>|\bLIKE|\bIN)\s*\(?\s*'?%?#\{|#\{params\[)/i;
        const rubySqliIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubySqliRegex.test(l));
        if (rubySqliIdx !== -1) {
            const matchLineIdx = rubySqliIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `ruby-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18031,
                type: 'SECURITY',
                title: 'RUBY-SEC-01: Ruby on Rails SQL Injection in ActiveRecord Query Interpolation',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'User.where("name = #{params[:name]}")',
                reproductionSteps: [
                    `Scanned ActiveRecord queries at ${file.path}:${lineNum}.`,
                    'Detected direct Ruby string interpolation (#{}) inside ActiveRecord query fragments, bypassing SQL escaping.'
                ],
                remediationPrompt: 'Use parameterized array syntax: User.where("name = ?", params[:name]) or hash conditions: User.where(name: params[:name]).',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [RUBY AUDIT] CRITICAL: Ruby SQL Injection in ${file.path}:${lineNum}`);
        }
        // RUBY-02: Ruby Mass Assignment via params.permit!
        const rubyMassAssignmentRegex = /params(?:\[[^\]]+\]|\.[a-zA-Z0-9_]+(?:\([^)]*\))?)*\.permit!(?:\s|\(|$|;)/i;
        if (rubyMassAssignmentRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubyMassAssignmentRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `ruby-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18032,
                type: 'SECURITY',
                title: 'RUBY-SEC-02: Insecure Mass Assignment via params.permit!',
                severity: 'HIGH',
                category: 'Mass Assignment',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'params.require(:user).permit!',
                reproductionSteps: [
                    `Scanned controller action in ${file.path}:${lineNum}.`,
                    'Detected params.permit! which completely disables Strong Parameters, allowing attackers to overwrite protected model attributes.'
                ],
                remediationPrompt: 'Explicitly whitelist required model attributes: params.require(:user).permit(:username, :email).',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [RUBY AUDIT] HIGH: Ruby Mass Assignment in ${file.path}:${lineNum}`);
        }
        // RUBY-03: Ruby Remote Code Execution via eval
        const rubyEvalRegex = /(?:eval|Kernel\.eval)\s*\(\s*(?:params\[|#\{params\[)/i;
        const rubyEvalIdx = lines.findIndex(l => !l.trim().startsWith('#') && rubyEvalRegex.test(l));
        if (rubyEvalIdx !== -1) {
            const matchLineIdx = rubyEvalIdx;
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `ruby-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18033,
                type: 'SECURITY',
                title: 'RUBY-SEC-03: Remote Code Execution via eval with Unsanitized Parameters',
                severity: 'CRITICAL',
                category: 'Remote Code Execution',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'eval(params[:cmd])',
                reproductionSteps: [
                    `Scanned dynamic evaluation handlers at ${file.path}:${lineNum}.`,
                    'Detected eval() invoked directly with untrusted request parameters.'
                ],
                remediationPrompt: 'Remove dynamic code evaluation. Use static condition trees or safe dispatchers.',
                status: 'OPEN',
                owner: 'Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [RUBY AUDIT] CRITICAL: Ruby Remote Code Execution in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 5. NOSQL, MONGODB & FIREBASE SECURITY RULES
    // =========================================================================
    // MongoDB $where evaluation injection (*.js, *.ts, *.mjs)
    const isJsTs = lowerPath.endsWith('.js') || lowerPath.endsWith('.ts') || lowerPath.endsWith('.mjs') || lowerPath.endsWith('.cjs');
    if (isJsTs) {
        const mongoWhereRegex = /(?:\$where\s*:\s*["'][^"']*|\.find\s*\(\s*\{\s*["']?\$where["']?\s*:)/i;
        if (mongoWhereRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && mongoWhereRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `nosql-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18041,
                type: 'SECURITY',
                title: 'NOSQL-SEC-01: MongoDB $where Arbitrary JavaScript Evaluation Injection',
                severity: 'CRITICAL',
                category: 'NoSQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'db.users.find({ $where: "this.name == \'" + name + "\'" })',
                reproductionSteps: [
                    `Scanned MongoDB query expression at ${file.path}:${lineNum}.`,
                    'Detected MongoDB $where operator executing arbitrary JavaScript on the database engine. Attackers can execute arbitrary server-side code or cause Denial of Service.'
                ],
                remediationPrompt: 'Replace $where queries with standard MongoDB query operators ($eq, $in, $regex). Disable JavaScript execution on MongoDB daemon with --noscripting.',
                status: 'OPEN',
                owner: 'Database & Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [NOSQL AUDIT] CRITICAL: MongoDB $where Injection in ${file.path}:${lineNum}`);
        }
        // Node.js MySQL / Postgres string concatenation SQLi
        const nodeSqlConcatRegex = /(?:connection|pool|db|client)\.query\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i;
        if (nodeSqlConcatRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && nodeSqlConcatRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `sql-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18042,
                type: 'SECURITY',
                title: 'NODE-SQL-01: Node.js Database Query Formatted via String Concatenation',
                severity: 'CRITICAL',
                category: 'SQL Injection',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'connection.query("SELECT * FROM users WHERE id = " + req.query.id)',
                reproductionSteps: [
                    `Scanned database query call at ${file.path}:${lineNum}.`,
                    'Detected SQL statement constructed with direct string concatenation (+) without parameterized query values (?).'
                ],
                remediationPrompt: 'Use parameterized queries: connection.query("SELECT * FROM users WHERE id = ?", [req.query.id], callback);',
                status: 'OPEN',
                owner: 'Backend Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [SQL AUDIT] CRITICAL: Node SQL Concatenation in ${file.path}:${lineNum}`);
        }
    }
    // Firebase Firestore / Realtime DB Security Rules (*.rules, firebase.json)
    const isFirebaseRules = lowerPath.endsWith('.rules') || lowerPath.includes('firestore') || lowerPath.includes('firebase');
    if (isFirebaseRules) {
        const firebaseAllowAllRegex = /allow\s+(?:read\s*,\s*write|write\s*,\s*read|write|read)\s*:\s*if\s+true\s*;/i;
        if (firebaseAllowAllRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && firebaseAllowAllRegex.test(l));
            const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
            const snippet = extractSnippet(lines, lineNum);
            findings.push({
                id: `firebase-${Date.now()}-${findingCounter.count++}`,
                ruleId: 18043,
                type: 'SECURITY',
                title: 'FIREBASE-SEC-01: Insecure Firebase Security Rules (Unauthenticated Public Read/Write)',
                severity: 'CRITICAL',
                category: 'Access Control',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || 'allow read, write: if true;',
                reproductionSteps: [
                    `Scanned Firebase security rules at ${file.path}:${lineNum}.`,
                    'Detected permissive "allow read, write: if true;" rule granting public, unauthenticated read/write access to database collections.'
                ],
                remediationPrompt: 'Restrict access to authenticated users: allow read, write: if request.auth != null && request.auth.uid == userId;',
                status: 'OPEN',
                owner: 'Cloud Security Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] 🔒 [FIREBASE AUDIT] CRITICAL: Permissive Firebase Rule in ${file.path}:${lineNum}`);
        }
    }
    return { findings, logs };
}
