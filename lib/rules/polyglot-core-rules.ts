/**
 * Core injection and data-handling flaws across languages (CORE-01..08, Rule IDs 24101-24108).
 * One rule per vulnerability class, with per-language sinks, so every stack gets the OWASP basics.
 * Rules flag dynamic values (interpolation / concatenation with non-constant identifiers); constants are ignored.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { javaDeserializationIsSafe } from './shared/java-deserialization';

export interface PolyglotCoreRuleResult {
  findings: Finding[];
  logs: string[];
}

type Lang = 'java' | 'kotlin' | 'ruby' | 'erb' | 'php' | 'python' | 'csharp' | 'razor' | 'go' | 'jsp' | 'template' | 'swift' | 'dart' | 'rust' | null;

function languageOf(path: string): Lang {
  const p = path.toLowerCase();
  if (p.endsWith('.java')) return 'java';
  if (p.endsWith('.kt')) return 'kotlin';
  if (p.endsWith('.swift')) return 'swift';
  if (p.endsWith('.dart')) return 'dart';
  if (p.endsWith('.rs')) return 'rust';
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

// SELECT needs a FROM in the same literal: UI text such as "Select at most {n} tickets" is not a query
// ... and SELECT right after a word of prose ("options for Select FormField from") is a sentence, not a query
const SQL = String.raw`(?:(?<!<)(?<!\b(?:for|to|the|a|and|or|please|then|we|you|can|could|cannot|not|must|should|will)\s)\bSELECT\s+(?!value\s*=)[\w*][^"'\n]*?\bFROM\b|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)`;
/**
 * A value spliced into the SQL rather than structure: inside SQL quotes ('{x}', '#{x}', '$x', '%s',
 * '" + x + "'), or right after a comparison / LIKE / IN ( (= {x}, = " + x). DB-API %s without quotes is a bind
 * parameter, so it does not count.
 */
const SQL_VALUE_POSITION = new RegExp([
  // '{x}', '%{x}%' (LIKE), '$x', '%s', '%(name)s'
  String.raw`'%?\s*(?:\{[^}]+\}|#\{[^}]+\}|\$\{[^}]+\}|\$[a-z_]\w*|%s|%\(\w+\)s)`,
  String.raw`'%?["\x60]\s*[+.]\s*\$?[a-z_]`,
  String.raw`(?:=|<>|!=|<=?|>=?|\bLIKE|\bIN\s*\()\s*(?:\{[^}]+\}|#\{[^}]+\}|\$\{[^}]+\}|\$[a-z_]\w*|["\x60]\s*[+.]\s*\$?[a-z_])`,
].join('|'), 'i');

/** The file reads outside input: request bodies, params, cookies, headers, uploads, sockets, stdin. */
const UNTRUSTED_INPUT = /\b(?:request|req)\.(?:body|data|args|form|values|files|json|params|query|cookies|headers|get_data|stream|raw_post|POST|GET|COOKIES|FILES)\b|\bparams\[|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request->|\bcookies\[|request_body|\brecv\s*\(|sys\.stdin|\bSTDIN\b|getInputStream\s*\(|HttpServletRequest|@RequestBody|\bupload/i;

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
  // Framework-quoted identifiers and Python {MAX_IDS} / {_TABLE} module constants are not user input
  const pyConstants = (t: string) => (lang === 'python' ? t.replace(/\{_?[A-Z][A-Z0-9_]*\}/g, 'IDENT') : t);
  const normalize = (t: string) => t
    .replace(/#\{\s*(?:self\.class\.)?(?:quoted_table_name|table_name|connection\.quote\w*\([^}]*\)|sanitize_sql\w*\([^}]*\)|quote_column_name\([^}]*\))\s*\}/g, 'IDENT')
    // Ruby: SQL the ORM generated (#{scope.to_sql}), quote(), Model.table_name and CONSTANTS are not input
    .replace(/#\{\s*(?:[\w.:()]+\.to_sql|(?:\w+\.)*quote\w*\([^}]*\)|[\w:]+\.table_name|(?:[A-Z]\w*::)*[A-Z][A-Z0-9_]*)\s*\}/g, 'IDENT')
    // Numbers cannot change a query: #{limit.to_i}, #{user.id}, #{title.size}, #{Integer(x)}, {int(x)}
    .replace(/(?:#\{|\{)\s*(?:(?:::)?@?[\w.:]+\.(?:to_i|to_f|id|pid|size|count|length)|Integer\([^)]*\)|Float\([^)]*\)|int\([^)]*\)|float\([^)]*\)|len\([^)]*\))\s*\}/g, 'IDENT')
    // A fragment the code assembled on its own ({where}, {sql}, {marks}, #{conditions}, {', '.join(updates)},
    // {family_clause()}): where any user value enters is where that fragment is built, not this line
    .replace(/(?:#\{|\{)\s*(?:['"][^'"]*['"]\s*\.join\(\s*)?(?:\w+_)?(?:where|clause|clauses|sql|subquery|filters?|conditions?|marks|placeholders|cols|columns|fields|updates|set_clause|order_by|base_query|inner)(?:_\w+)?(?:\(\))?\s*\)?\s*\}/gi, 'IDENT')
    // Python placeholder lists: {','.join('?' * len(ids))}, {", ".join(["%s"] * n)}
    .replace(/\{\s*['"][,\s]*['"]\s*\.join\(\s*(?:\[\s*)?['"](?:\?|%s|:\w+)['"]\s*\]?\s*\*[^}]*\)\s*\}/g, 'IDENT')
    // PHP: a table name concatenated after FROM / INTO / UPDATE / JOIN ('... FROM ' . $table, $this->table())
    .replace(/\b(FROM|INTO|UPDATE|JOIN|TABLE)\s*(['"])\s*\.\s*\$[\w>-]+(?:\([^)]*\))?/gi, '$1 IDENT$2')
    // A table name interpolated after FROM / INTO / UPDATE / JOIN / TABLE cannot be a bind parameter and is
    // almost always the app's own constant ("SELECT COUNT(*) FROM $TABLE"); values in WHERE / VALUES still count.
    .replace(/\b(FROM|INTO|UPDATE|JOIN|TABLE)(\s+[`"']?)(?:\$\{\s*\w+\s*\}|\$\w+|\\\(\s*\w+\s*\)|#\{\s*\w+\s*\}|\{\w+\})/gi, '$1$2IDENT')
    // A dynamic SET clause built from column names is safe when the query uses bind placeholders
    // (%s, ?, $1, :name) and passes a parameters argument. Values in quotes or unparameterized queries still count.
    .replace(/\bSET(\s+)(?:\{[a-zA-Z_]\w*\}|\$\{[a-zA-Z_]\w*\})(?=[^\n]*(?:%s|\?|\$\d|:\w+)[^"'\n]*["']\s*,\s*[\w([{])/gi, 'SET$1IDENT');
  const content = normalize(joinStatements(pyConstants(withoutHashComments)));
  // Lines get the same treatment, so a finding points at the statement that is still dynamic, not at the first
  // query of the file that merely looks like one
  const normLines = lines.map((l) => normalize(pyConstants(l)));
  const isDevTooling = /(?:^|\/)(?:scripts?|bin|tools|tasks|lib\/tasks|management\/commands|console\/commands|dev)\/|(?:^|\/)(?:Rakefile|manage\.py|setup\.py|fabfile\.py|noxfile\.py|install\.php|build\.php)$/i.test(file.path);
  const hits: Hit[] = [];
  const add = (h: Omit<Hit, 'lineIdx'>, lineRe: RegExp) => {
    const norm = firstLine(normLines, lineRe);
    const idx = norm !== -1 ? norm : firstLine(lines, lineRe);
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
    go: [new RegExp(String.raw`fmt\.Sprintf\(\s*"[^"\n]*` + SQL + String.raw`[^"\n]*%[sv]`, 'i'), new RegExp(String.raw`"[^"\n]*` + SQL + String.raw`[^"\n]*"\s*\+\s*` + DYN, 'i')],
    // Swift "\(name)" interpolation; Dart '$name' / '${user.id}'. The literal must start with the SQL verb:
    // log and error messages ("Error creating delete from list query: \(error)") also contain SQL words.
    swift: [new RegExp(String.raw`"\s*` + SQL + String.raw`[^"\n]*\\\(\s*` + DYN, 'i'), new RegExp(String.raw`"\s*` + SQL + String.raw`[^"\n]*"\s*\+\s*` + DYN, 'i')],
    dart: [new RegExp(String.raw`(?:"\s*` + SQL + String.raw`[^"\n]*|'\s*` + SQL + String.raw`[^'\n]*)\$\{?` + DYN, 'i'), new RegExp(String.raw`(?:"\s*` + SQL + String.raw`[^"\n]*"|'\s*` + SQL + String.raw`[^'\n]*')\s*\+\s*` + DYN, 'i')]
  };
  const sqlPatterns = sqlByLang[lang as keyof typeof sqlByLang] ?? [];
  // Migrations and maintenance scripts run SQL on the app's own data, not on request input
  const notRequestPath = isDevTooling || /(?:^|\/)(?:db\/(?:post_)?migrate|migrations?|alembic\/versions|\.semgrep)\//i.test(file.path);
  const sqlHit = notRequestPath ? undefined : sqlPatterns.find((re) => re.test(content));
  if (sqlHit) {
    add({
      ruleId: 24101, code: 'CORE-01', severity: 'CRITICAL',
      title: 'SQL Injection: Query Built From Dynamic Values',
      why: 'The SQL text is assembled with string concatenation / interpolation, so a crafted value can change the query (read, modify or delete data).',
      fix: 'Use parameterized queries / bind variables (PreparedStatement, ActiveRecord placeholders, PDO prepare, cursor.execute(sql, params), SqlParameter).'
    }, sqlPatterns.find((re) => normLines.some((l) => re.test(l))) ?? sqlPatterns.find((re) => lines.some((l) => re.test(l))) ?? new RegExp(SQL, 'i'));
    // Only a value placed into the SQL can carry an injection; structure the code assembles itself (column lists,
    // table names, guards, unions) is advice: blocking a release on it would mostly block safe code.
    // Judge every matching statement (a file can hold a safe one first), and point at a value-carrying one.
    const h = hits[hits.length - 1];
    const statements = [...content.matchAll(new RegExp(sqlHit.source, sqlHit.flags.includes('g') ? sqlHit.flags : sqlHit.flags + 'g'))]
      .map((m) => content.slice(m.index!, m.index! + m[0].length + 120));
    const valueStmt = statements.find((s) => SQL_VALUE_POSITION.test(s));
    if (valueStmt) {
      // Map the statement back to its first raw line (statements may span several lines)
      const head = (/(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]{0,30}/i.exec(valueStmt)?.[0] ?? '').trim();
      const at = head ? lines.findIndex((l) => l.includes(head)) : -1;
      if (at !== -1) h.lineIdx = at;
    } else {
      h.severity = 'MEDIUM';
      h.why = 'The SQL text is assembled from pieces (column lists, table names, conditions). No value is placed directly into it here, but if any piece can come from a request, the query can be changed.';
      h.fix = 'Build the pieces only from fixed allow-lists (column and table names) and pass every value as a bind parameter.';
    }
  }

  // CORE-02: OS command built from dynamic values
  const cmdByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    // A bare `...` only runs a command where an expression starts; inside "...", as in error messages
    // ("`#{k}` is not a valid attribute"), backticks are plain text
    // Kernel#system / exec / spawn, not a method of the same name (DB.exec "SET ...", connection.exec("SHOW ...")).
    // A bare `...#{x}...` closes on the line and is followed by code, not prose ("`#{col}` and the foreign key")
    ruby: /(?:(?<![.\w])(?:system|exec|spawn)|IO\.popen|Open3\.\w+|%x)\s*[\(\{]?\s*["`][^"`\n]*#\{|(?<=(?:^|[=(,;]|\breturn|\bputs|&&|\|\|)[ \t]*)`[^`\n]*#\{[^`\n]*`(?=\s*(?:$|[.;)\],}]|\bif\b|\bunless\b|\|\||&&|#))/m,
    // Global functions only: $pdo->exec() / $sqlite->exec() run SQL, not a shell
    php: /(?<!->|::)(?<!function\s{1,4})\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:["'][^"'\n]*["']\s*\.\s*\$|"[^"\n]*\$\w|\$\w)/i,
    // shell=True only counts when the command itself is built from values (f-string, +, %, .format) in the same call
    // An argument list (subprocess.run(["lsof", f"TCP:{port}"])) runs no shell, so values inside it are safe
    // "..." % x is formatting; a bare % inside the command (celery's --pidfile=%n.pid) is not
    python: /\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\((?!\s*\[)(?=[^)]*(?:\+\s*[\w(]|["']\s*%\s*[\w(\[{]|\.format\(|f["']))/,
    java: /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+\s*[a-z_]/,
    kotlin: /(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*\$\{?[a-z_]/,
    csharp: /Process\.Start\s*\([^)]*(?:\+\s*[a-z_]|\$")/,
    go: /exec\.Command(?:Context)?\s*\([^)]*"(?:sh|bash|cmd)"\s*,\s*"-c"\s*,\s*[^)"]*(?:\+|fmt\.Sprintf)/,
    rust: /Command::new\(\s*"(?:sh|bash|cmd(?:\.exe)?)"\s*\)[\s\S]{0,80}?\.args?\(\s*(?:"(?:-c|\/C)"|\[\s*"(?:-c|\/C)")[\s\S]{0,80}?(?:format!\(|\+\s*&?[a-z_])/
  };
  const cmd = cmdByLang[lang as keyof typeof cmdByLang];
  // Python: cmd = f"..." / "..." + x / "...".format(x) on one line, then subprocess.*(cmd, shell=True) on another
  const pyShellVar = lang === 'python' && [...content.matchAll(/\b(\w+)\s*=\s*(?:f["']|["'][^"'\n]*["']\s*(?:\+|%)|["'][^"'\n]*["']\.format\()/g)]
    .some((m) => new RegExp(String.raw`subprocess\.\w+\(\s*` + m[1] + String.raw`\b[^)]*shell\s*=\s*True`).test(content));
  // The command must sit on a line of its own: a match only across lines ([^)]* running past the call) is noise
  // Escaped values (Shellwords.escape, escapeshellarg, shlex.quote, .shelljoin) and Ruby backticks inside a
  // double-quoted string ("... (`#{ref}`).") are not commands built from raw input
  const cmdLine = (l: string) => !!cmd && cmd.test(l)
    && !/Shellwords\.escape|shellescape|escapeshell(?:arg|cmd)|shlex\.quote|\.shelljoin/.test(l)
    && !(lang === 'ruby' && l.includes('`') && ((l.slice(0, l.indexOf('`')).match(/"/g) ?? []).length % 2 === 1));
  // Normalized lines map 1:1 to the raw ones; a raw-only match is an interpolation the normalizer cleared (#{x.pid})
  const cmdIdx = cmd && cmd.test(content) ? normLines.findIndex(cmdLine) : -1;
  const cmdLocated = cmdIdx !== -1 || pyShellVar;
  if (cmd && !isDevTooling && cmdLocated) {
    add({
      ruleId: 24102, code: 'CORE-02', severity: 'CRITICAL',
      title: 'OS Command Injection: Shell Command Built From Dynamic Values',
      why: 'A shell command string includes a variable, so input containing ; | && or $() runs extra commands on the server.',
      fix: 'Avoid the shell: pass an argument array (Open3.capture2(cmd, arg), subprocess.run([...]), ProcessBuilder(list), escapeshellarg) and validate input against an allowlist.'
    }, cmdIdx !== -1 ? cmd : /shell\s*=\s*True/);
    if (cmdIdx !== -1) hits[hits.length - 1].lineIdx = cmdIdx;
  }

  // CORE-03: deserialization of untrusted data
  const deserByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    // Marshal.load(Marshal.dump(x)) is a deep copy; YAML.load is safe_load since Psych 4 (Ruby 3.1), unsafe_load is not
    ruby: /\bMarshal\.(?:load|restore)\s*\((?!\s*Marshal\.dump\b)|\bYAML\.unsafe_load\s*\(|\bOj\.load\s*\((?![^)]*mode:\s*:(?:strict|compat|json))/,
    java: /\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|\bnew\s+XMLDecoder\s*\(|\bXStream\b[^;]*\.fromXML\s*\(/,
    kotlin: /\bObjectInputStream\s*\(|\.readObject\s*\(\s*\)/,
    python: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\bjsonpickle\.decode\s*\(|\byaml\.load\s*\((?![^\n]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe|Full|CFull|Base|CBase)Loader)|\byaml\.unsafe_load\s*\(/,
    // The global function only: Serializable::unserialize() declarations and $this->unserialize() are methods;
    // allowed_classes => false cannot build objects
    php: /(?<!->|::)(?<!function\s{1,4})\bunserialize\s*\(\s*\$(?![^)\n]*allowed_classes['"]\s*=>\s*(?:false|\[))/,
    csharp: /\bBinaryFormatter\b|\bLosFormatter\b|\bNetDataContractSerializer\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)/
  };
  const deser = deserByLang[lang as keyof typeof deserByLang];
  // ObjectInputStream behind an allowlist, or reading bytes the app wrote itself, cannot load attacker classes
  const guardedObjectStream = (lang === 'java' || lang === 'kotlin') && !/XMLDecoder|XStream/.test(content) && javaDeserializationIsSafe(content);
  // Maintenance scripts, docs builds, CI helpers and course homework load the repo's own files
  const ownFilesOnly = isDevTooling || /(?:^|\/)(?:docs?|\.gitlab|\.github|homework|cohorts|notebooks)\//i.test(file.path);
  if (deser && !ownFilesOnly && deser.test(content) && !guardedObjectStream) {
    add({
      ruleId: 24103, code: 'CORE-03', severity: 'CRITICAL',
      title: 'Insecure Deserialization of Untrusted Data',
      why: 'Native object deserializers (Marshal, pickle, ObjectInputStream, BinaryFormatter, unsafe YAML) can instantiate attacker-chosen classes and run code.',
      fix: 'Exchange data as JSON validated by a schema; for YAML use safe_load / SafeLoader; never deserialize native objects from requests, cookies or uploads.'
    }, deser);
    // Blocking only when the file reads outside input; deserializing the app's own cache, queue or database rows is
    // dangerous only if an attacker can write that storage, which a scan of this file cannot see
    if (!UNTRUSTED_INPUT.test(content)) {
      const h = hits[hits.length - 1];
      h.severity = 'MEDIUM';
      h.why = 'A native object deserializer (Marshal, pickle, unserialize, unsafe YAML) reads data here. Nothing in this file takes it from a request, but if an attacker can ever write that data (cache, queue, database, uploaded file) it can run code.';
    }
  }

  // CORE-04: XML parsers with external entities enabled
  const javaXxeHardening = /disallow-doctype-decl|external-general-entities|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|ACCESS_EXTERNAL_DTD|setExpandEntityReferences\s*\(\s*false|FEATURE_SECURE_PROCESSING/;
  // Hardening that only runs inside an `if (...)` block (e.g. `if (securityEnabled)`) leaves the default path open.
  const hardenedUnconditionally = () => {
    const src = content.split('\n');
    const indent = (s: string) => s.length - s.trimStart().length;
    return src.some((line, i) => {
      if (!javaXxeHardening.test(line)) return false;
      for (let j = i - 1; j >= 0; j--) {
        if (!src[j].trim() || indent(src[j]) >= indent(line)) continue;
        return !/^\s*(?:\}\s*)?(?:if|else)\b/.test(src[j]);
      }
      return true;
    });
  };
  const xxeByLang: Partial<Record<Exclude<Lang, null>, () => boolean>> = {
    java: () => /(?:XMLInputFactory|DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory|TransformerFactory)\.new(?:Instance|Factory|DefaultInstance)\s*\(|createXMLReader\s*\(/.test(content) &&
      !hardenedUnconditionally(),
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
  const isForeachLocalFile = Boolean(includedVar &&
    new RegExp('foreach\\s*\\([^)]*\\bas\\s*(?:\\$[a-z_]\\w*\\s*=>\\s*)?\\$' + includedVar + '\\b').test(content) &&
    /glob\s*\(|scandir\s*\(|DirectoryIterator|FilesystemIterator/i.test(content));
  if (includedVar && !isForeachLocalFile && (new RegExp(String.raw`\$` + includedVar + String.raw`\s*=\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)`).test(content) ||
      (!new RegExp('foreach\\s*\\([^)]*\\bas\\s*(?:\\$[a-z_]\\w*\\s*=>\\s*)?\\$' + includedVar + '\\b').test(content) && !new RegExp(String.raw`\$` + includedVar + String.raw`\s*=`).test(content)))) {
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

  const isTestCode = /(?:^|\/)(?:tests?|spec|__tests__|\w+Tests)\/|(?:_test|_spec|Tests?)\.\w+$/i.test(file.path);

  // CORE-09: TLS certificate validation turned off in an HTTP client
  const tlsOffByLang: Partial<Record<Exclude<Lang, null>, RegExp>> = {
    dart: /badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;)/,
    csharp: /ServerCertificateCustomValidationCallback\s*=\s*(?:\([^)]*\)\s*=>\s*true\b|(?:HttpClientHandler\.)?DangerousAcceptAnyServerCertificateValidator)|ServerCertificateValidationCallback\s*\+?=\s*(?:\([^)]*\)\s*=>\s*true\b|delegate[^{]*\{\s*return\s+true\s*;)/,
    php: /CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b|['"]verify['"]\s*=>\s*false\b/i,
    ruby: /OpenSSL::SSL::VERIFY_NONE|\bverify_ssl:\s*false\b|ssl:\s*\{\s*verify:\s*false/
  };
  const tlsOff = tlsOffByLang[lang as keyof typeof tlsOffByLang];
  // A client that only ever talks to this machine (127.0.0.1 / localhost) has no network path to intercept
  const loopbackOnly = /\b(?:127\.0\.0\.1|localhost)\b/.test(content) && !/https?:\/\/(?!127\.0\.0\.1|localhost)[\w-]+\./.test(content);
  if (tlsOff && !isTestCode && !loopbackOnly && tlsOff.test(content)) {
    add({
      ruleId: 24109, code: 'CORE-09', severity: 'HIGH',
      title: 'TLS Certificate Validation Disabled',
      why: 'The HTTP client accepts any certificate, so anyone on the network path can impersonate the API and read or change tokens and personal data in transit.',
      fix: 'Remove the override and keep the default certificate checks. For a private CA, trust that CA explicitly instead of accepting every certificate.'
    }, tlsOff);
  }

  // CORE-10: file path built from request input (path traversal)
  const requestParams = new Set<string>();
  if (lang === 'java' || lang === 'kotlin') {
    for (const m of content.matchAll(/@(?:RequestParam|PathVariable|RequestHeader)(?:\([^)]*\))?\s+(?:final\s+)?(?:String\s+(\w+)|(\w+)\s*:\s*String)/g)) requestParams.add(m[1] ?? m[2]);
    for (const m of content.matchAll(/(?:String|val|var)\s+(\w+)\s*=\s*\w+\.getParameter\(/g)) requestParams.add(m[1]);
  } else if (lang === 'csharp' && /Controller\b|\[Http(?:Get|Post|Put|Delete)\]|MapGet\(/.test(content)) {
    // String parameters of controller actions and minimal-API handlers are bound from the request
    for (const m of content.matchAll(/(?:\[From(?:Query|Route|Form|Body|Header)\]\s*)?\bstring\??\s+(\w+)\s*[,)=]/g)) requestParams.add(m[1]);
  }
  const fileSink = /(?:Paths\.get|Path\.of|new\s+File(?:InputStream|OutputStream|Reader)?|Files\.\w+|PhysicalFile|File\.(?:ReadAll\w+|OpenRead|OpenWrite|Open|Delete|WriteAll\w+|Exists)|new\s+FileStream|Path\.Combine)\s*\(/;
  const pathGuard = /getCanonicalPath|toRealPath|\.normalize\(\)[^;\n]*\.startsWith|Path\.GetFileName\s*\(|GetFullPath\([^)]*\)[^;\n]*\.StartsWith|FilenameUtils\.getName|\bbasename\s*\(|realpath\s*\(/;
  let pathIdx = -1;
  if (!isTestCode && !pathGuard.test(content)) {
    if (lang === 'php') {
      pathIdx = lines.findIndex((l) => /\b(?:readfile|file_get_contents|fopen|file|unlink|file_put_contents|fpassthru)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/i.test(l));
    } else if (requestParams.size) {
      const names = [...requestParams].map((n) => n.replace(/\W/g, '')).join('|');
      const argUse = new RegExp(String.raw`[(,]\s*(?:` + names + String.raw`)\s*[),+]|\+\s*(?:` + names + String.raw`)\b|\$\{?(?:` + names + String.raw`)\b`);
      pathIdx = lines.findIndex((l) => fileSink.test(l) && argUse.test(l) && !/^\s*(?:\/\/|\*)/.test(l));
    }
  }
  if (pathIdx !== -1) {
    hits.push({
      ruleId: 24110, code: 'CORE-10', severity: 'HIGH', lineIdx: pathIdx,
      title: 'Path Traversal: File Path Built From Request Input',
      why: 'A file name from the request goes straight into a file path, so ../../ sequences can read or overwrite files outside the intended folder (config, keys, other users\' uploads).',
      fix: 'Strip the value to a bare file name (Path.GetFileName, basename, FilenameUtils.getName), or resolve the full path and reject it unless it starts with the allowed base directory.'
    });
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
