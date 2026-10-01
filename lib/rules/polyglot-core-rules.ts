/**
 * Core injection and data-handling flaws across languages (CORE-01..08, Rule IDs 24101-24108).
 * One rule per vulnerability class, with per-language sinks, so every stack gets the OWASP basics.
 * Rules flag dynamic values (interpolation / concatenation with non-constant identifiers); constants are ignored.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface PolyglotCoreRuleResult {
  findings: Finding[];
  logs: string[];
}

type Lang = 'java' | 'kotlin' | 'ruby' | 'erb' | 'php' | 'python' | 'csharp' | 'razor' | 'go' | 'jsp' | 'template' | null;

function languageOf(path: string): Lang {
  const p = path.toLowerCase();
  if (p.endsWith('.java')) return 'java';
  if (p.endsWith('.kt')) return 'kotlin';
  if (p.endsWith('.rb')) return 'ruby';
  if (p.endsWith('.erb')) return 'erb';
  if (p.endsWith('.php')) return 'php';
  if (p.endsWith('.py')) return 'python';
  if (p.endsWith('.cs')) return 'csharp';
  if (p.endsWith('.cshtml') || p.endsWith('.razor')) return 'razor';
  if (p.endsWith('.go')) return 'go';
  if (p.endsWith('.jsp')) return 'jsp';
  if (/\.(?:html|jinja2?|j2|twig)$/.test(p)) return 'template';
  return null;
}

const SQL = String.raw`(?:SELECT\s+[\w*]|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)`;
/** A non-constant identifier (lowercase start or member access), i.e. not FOO_BAR / Foo.class. */
const DYN = String.raw`(?:[a-z_][\w]*(?:\.[\w]+|\[[^\]]*\]|\([^)]*\))*)`;

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const firstLine = (lines: string[], re: RegExp) => lines.findIndex((l) => re.test(l) && !/^\s*(?:\/\/|#|\*|--)/.test(l));

/** Joins Java/C#/Python string continuations so a query built over several lines is seen as one statement. */
const joinStatements = (content: string) => content.replace(/(["'])\s*\n\s*\+/g, '$1 +').replace(/\+\s*\n\s*/g, '+ ').replace(/=\s*\n\s*(["'(])/g, '= $1');

export function evaluatePolyglotCoreRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): PolyglotCoreRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const lang = languageOf(file.path);
  if (!lang || /node_modules\/|vendor\//i.test(file.path)) return { findings, logs };
  const withoutHashComments = lang === 'ruby' || lang === 'python' || lang === 'erb'
    ? cleanContent.replace(/^\s*#.*$/gm, '').replace(/<%#[\s\S]*?%>/g, '')
    : cleanContent;
  // Framework-quoted identifiers are not user input
  const content = joinStatements(withoutHashComments)
    .replace(/#\{\s*(?:self\.class\.)?(?:quoted_table_name|table_name|connection\.quote\w*\([^}]*\)|sanitize_sql\w*\([^}]*\)|quote_column_name\([^}]*\))\s*\}/g, 'IDENT');
  const isDevTooling = /(?:^|\/)(?:scripts?|bin|tools|tasks|lib\/tasks|management\/commands)\/|(?:^|\/)(?:Rakefile|manage\.py|setup\.py|fabfile\.py|noxfile\.py)$/i.test(file.path);
  const hits: Hit[] = [];
  const add = (h: Omit<Hit, 'lineIdx'>, lineRe: RegExp) => {
    const idx = firstLine(lines, lineRe);
    hits.push({ ...h, lineIdx: idx === -1 ? 0 : idx });
  };

  // CORE-01: SQL built from dynamic values
  const sqlByLang: Partial<Record<Exclude<Lang, null>, RegExp[]>> = {
    java: [new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*"\s*\+\s*` + DYN, 'i')],
    kotlin: [new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*\$\{?` + DYN, 'i')],
    csharp: [new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*"\s*\+\s*` + DYN, 'i'), new RegExp(String.raw`\$@?"[^"\n]*` + SQL + String.raw`[^"\n]*\{` + DYN, 'i')],
    ruby: [/\.(?:where|order|group|having|joins|select|from|pluck|find_by_sql|exists\?|update_all|delete_all|execute|exec_query)\s*\(?\s*"[^"\n]*#\{(?!\s*[A-Z_]+\s*\})/i, new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*#\{`, 'i')],
    php: [new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*\$[a-z_]\w*`, 'i'), new RegExp(String.raw`["'][^"'\n]*` + SQL + String.raw`[^"'\n]*["']\s*\.\s*\$`, 'i')],
    // Quote-matched literals (SQL often contains the other quote), allowing implicitly concatenated adjacent literals
    python: [
      new RegExp(String.raw`f"[^"\n]*` + SQL + String.raw`[^"\n]*\{|f'[^'\n]*` + SQL + String.raw`[^'\n]*\{`, 'i'),
      new RegExp(String.raw`(?:"[^"\n]*` + SQL + String.raw`[^"\n]*"|'[^'\n]*` + SQL + String.raw`[^'\n]*')(?:\s*(?:"[^"\n]*"|'[^'\n]*'))*\s*\)?\s*(?:%\s*[({\w]|\.format\s*\(|\+\s*` + DYN + ')', 'i')
    ],
    go: [new RegExp(String.raw`fmt\.Sprintf\(\s*"[^"\n]*` + SQL + String.raw`[^"\n]*%[sv]`, 'i'), new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*"\s*\+\s*` + DYN, 'i')]
  };
  const sqlPatterns = sqlByLang[lang as keyof typeof sqlByLang] ?? [];
  const sqlHit = sqlPatterns.find((re) => re.test(content));
  if (sqlHit) {
    add({
      ruleId: 24101, code: 'CORE-01', severity: 'CRITICAL',
      title: 'SQL Injection: Query Built From Dynamic Values',
      why: 'The SQL text is assembled with string concatenation / interpolation, so a crafted value can change the query (read, modify or delete data).',
      fix: 'Use parameterized queries / bind variables (PreparedStatement, ActiveRecord placeholders, PDO prepare, cursor.execute(sql, params), SqlParameter).'
    }, sqlPatterns.find((re) => lines.some((l) => re.test(l))) ?? new RegExp(SQL, 'i'));
  }

  // CORE-02: OS command built from dynamic values
  const cmdByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    ruby: /(?:\bsystem|\bexec|\bspawn|IO\.popen|Open3\.\w+|%x)\s*[\(\{]?\s*["`][^"`\n]*#\{|`[^`\n]*#\{/,
    php: /\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:["'][^"'\n]*["']\s*\.\s*\$|"[^"\n]*\$\w|\$\w)/i,
    python: /\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\((?=[^)]*(?:\+|%|\.format\(|f["']))|shell\s*=\s*True/,
    java: /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+\s*[a-z_]/,
    kotlin: /(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*\$\{?[a-z_]/,
    csharp: /Process\.Start\s*\([^)]*(?:\+\s*[a-z_]|\$")/,
    go: /exec\.Command(?:Context)?\s*\([^)]*"(?:sh|bash|cmd)"\s*,\s*"-c"\s*,\s*[^)"]*(?:\+|fmt\.Sprintf)/
  };
  const cmd = cmdByLang[lang as keyof typeof cmdByLang];
  if (cmd && !isDevTooling && cmd.test(content)) {
    add({
      ruleId: 24102, code: 'CORE-02', severity: 'CRITICAL',
      title: 'OS Command Injection: Shell Command Built From Dynamic Values',
      why: 'A shell command string includes a variable, so input containing ; | && or $() runs extra commands on the server.',
      fix: 'Avoid the shell: pass an argument array (Open3.capture2(cmd, arg), subprocess.run([...]), ProcessBuilder(list), escapeshellarg) and validate input against an allowlist.'
    }, cmd);
  }

  // CORE-03: deserialization of untrusted data
  const deserByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    ruby: /\bMarshal\.(?:load|restore)\s*\(|\bYAML\.(?:unsafe_load|load)\s*\((?![^)]*permitted_classes)|\bOj\.load\s*\((?![^)]*mode:\s*:strict)/,
    java: /\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|\bnew\s+XMLDecoder\s*\(|\bXStream\b[^;]*\.fromXML\s*\(/,
    kotlin: /\bObjectInputStream\s*\(|\.readObject\s*\(\s*\)/,
    python: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\bjsonpickle\.decode\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)|\byaml\.unsafe_load\s*\(/,
    php: /\bunserialize\s*\(\s*\$/,
    csharp: /\bBinaryFormatter\b|\bLosFormatter\b|\bNetDataContractSerializer\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)/
  };
  const deser = deserByLang[lang as keyof typeof deserByLang];
  if (deser && deser.test(content)) {
    add({
      ruleId: 24103, code: 'CORE-03', severity: 'CRITICAL',
      title: 'Insecure Deserialization of Untrusted Data',
      why: 'Native object deserializers (Marshal, pickle, ObjectInputStream, BinaryFormatter, unsafe YAML) can instantiate attacker-chosen classes and run code.',
      fix: 'Exchange data as JSON validated by a schema; for YAML use safe_load / SafeLoader; never deserialize native objects from requests, cookies or uploads.'
    }, deser);
  }

  // CORE-04: XML parsers with external entities enabled
  const xxeByLang: Partial<Record<Exclude<Lang, null>, () => boolean>> = {
    java: () => /(?:XMLInputFactory|DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory|TransformerFactory)\.new(?:Instance|Factory|DefaultInstance)\s*\(|createXMLReader\s*\(/.test(content) &&
      !/disallow-doctype-decl|external-general-entities|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|ACCESS_EXTERNAL_DTD|setExpandEntityReferences\s*\(\s*false|FEATURE_SECURE_PROCESSING/.test(content),
    php: () => /LIBXML_NOENT|libxml_disable_entity_loader\s*\(\s*false|LIBXML_DTDLOAD/.test(content),
    csharp: () => /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver|ProhibitDtd\s*=\s*false/.test(content),
    python: () => /resolve_entities\s*=\s*True|XMLParser\s*\([^)]*load_dtd\s*=\s*True|xml\.sax\.make_parser|feature_external_ges\s*,\s*True/.test(content)
  };
  const xxe = xxeByLang[lang as keyof typeof xxeByLang];
  if (xxe && xxe()) {
    add({
      ruleId: 24104, code: 'CORE-04', severity: 'HIGH',
      title: 'XML External Entity (XXE) Processing Enabled',
      why: 'The XML parser resolves DTDs / external entities, so an uploaded document can read local files or reach internal services.',
      fix: 'Disable DOCTYPE and external entities on the parser (disallow-doctype-decl, IS_SUPPORTING_EXTERNAL_ENTITIES=false, DtdProcessing.Prohibit, resolve_entities=False / defusedxml).'
    }, /XMLInputFactory|DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory|TransformerFactory|LIBXML_NOENT|libxml_disable_entity_loader|DtdProcessing|XmlUrlResolver|resolve_entities|make_parser/);
  }

  // CORE-05: output escaping bypassed with user-controlled data
  const xssByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    // html_safe / raw are routine for trusted markup; flag them when applied to request or user-controlled data
    erb: /<%=\s*raw\s*\(?\s*(?:params|@?(?:current_)?user\.|request\.)|<%=[^%]*(?:params|(?:current_)?user\.\w+|request\.)[^%]*\.html_safe\b|<%==\s*(?:params|@?(?:current_)?user\.|request\.)/,
    ruby: /(?:params|(?:current_)?user\.\w+|request\.)[^\n]*\.html_safe\b|#\{\s*params[^}]*\}[^\n"]*"\s*\.html_safe\b|\braw\s*\(\s*params/,
    // echo of request data, or request data concatenated into an HTML string literal
    php: /\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b|['"][^'"\n]*<[a-z][^'"\n]*['"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
    // autoescape=False in Python code is a global template-engine setting (unlike {% autoescape off %} blocks in plain-text emails)
    python: /\bautoescape\s*=\s*False|\bmark_safe\s*\((?=[^)]*request)|Markup\s*\((?=[^)]*request)/,
    template: /\{\{\s*request\.[^}]*\|\s*(?:safe|raw)\s*\}\}/i,
    jsp: /<%=\s*request\.getParameter|\$\{param\.[^}]+\}/,
    razor: /@Html\.Raw\s*\(\s*(?:Request|Context\.Request|ViewBag\.\w*(?:Input|Query|Search))/,
    java: /th:utext=/
  };
  const xss = xssByLang[lang as keyof typeof xssByLang];
  if (xss && !/\.text\.erb$/i.test(file.path) && xss.test(content)) {
    add({
      ruleId: 24105, code: 'CORE-05', severity: 'HIGH',
      title: 'Cross-Site Scripting (XSS): Output Escaping Bypassed',
      why: 'Data is written into HTML without the framework’s automatic escaping (html_safe/raw, |safe, autoescape off, Html.Raw, echo of request data), so injected <script> runs in other users’ browsers.',
      fix: 'Keep auto-escaping on; escape at output (htmlspecialchars, h(), {{ }} without |safe) and sanitize rich text with an allowlist sanitizer.'
    }, xss);
  }

  // CORE-06: dynamic file include (PHP)
  // The included variable is request-derived here, or never assigned in this file (set elsewhere, e.g. from $_GET)
  const includedVar = lang === 'php' ? content.match(/\b(?:include|require)(?:_once)?\s*\(?\s*\$([a-z_]\w*)\s*\)?\s*;/i)?.[1] : undefined;
  if (includedVar && (new RegExp(String.raw`\$` + includedVar + String.raw`\s*=\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)`).test(content) ||
      !new RegExp(String.raw`\$` + includedVar + String.raw`\s*=`).test(content))) {
    add({
      ruleId: 24106, code: 'CORE-06', severity: 'CRITICAL',
      title: 'File Inclusion: include/require With a Request-Controlled Path',
      why: 'The included path comes from request data, enabling local file disclosure (../../etc/passwd) or remote code inclusion.',
      fix: 'Map the request value to a fixed allowlist of templates; never pass request data to include/require.'
    }, /\b(?:include|require)(?:_once)?\s*\(?\s*\$/i);
  }

  // CORE-07: unrestricted file upload (PHP)
  if (lang === 'php' && /move_uploaded_file\s*\(/.test(content) &&
      !/pathinfo\s*\(|getimagesize\s*\(|finfo_|mime_content_type|\['type'\]|in_array\s*\([^)]*(?:ext|extension|mime)|preg_match\s*\([^)]*\\\.\((?:jpe?g|png|gif)/i.test(content)) {
    add({
      ruleId: 24107, code: 'CORE-07', severity: 'HIGH',
      title: 'Unrestricted File Upload',
      why: 'Uploaded files are stored without checking type or extension, so a .php file can be uploaded and executed from the web root.',
      fix: 'Validate extension and MIME type against an allowlist, rename files, and store uploads outside the web root.'
    }, /move_uploaded_file\s*\(/);
  }

  // CORE-08: MD5 / SHA-1 for passwords
  const weakHashByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    python: /\b(?:hashlib\.)?(?:md5|sha1)\s*\(/,
    php: /\b(?:md5|sha1)\s*\(\s*\$\w*(?:pass|pwd)/i,
    java: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/i,
    kotlin: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/i,
    ruby: /Digest::(?:MD5|SHA1)\.(?:hexdigest|digest)\s*\(/,
    csharp: /\b(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5|SHA1)CryptoServiceProvider/
  };
  const weakHash = weakHashByLang[lang as keyof typeof weakHashByLang];
  const weakPasswordHash = weakHash ? lines.findIndex((l) => weakHash.test(l) && /pass(?:word|wd)?|pwd|credential/i.test(l)) : -1;
  if (weakHash && weakPasswordHash !== -1) {
    add({
      ruleId: 24108, code: 'CORE-08', severity: 'HIGH',
      title: 'Weak Password Hashing (MD5 / SHA-1)',
      why: 'MD5 and SHA-1 are fast, unsalted-by-default hashes; leaked password hashes are cracked in minutes with GPUs or rainbow tables.',
      fix: 'Hash passwords with bcrypt, scrypt or Argon2 (has_secure_password, password_hash, PBKDF2 / Argon2 libraries).'
    }, weakHash);
    hits[hits.length - 1].lineIdx = weakPasswordHash;
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `core${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'Injection & Data Handling',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [CORE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
