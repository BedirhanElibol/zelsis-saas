/**
 * Injection, archive, crypto, Android and framework-setting defects the other packs missed (IGAP-01.., Rule IDs 31001-31099).
 * Each rule needs a request value reaching the sink, or a setting that is wrong in any deployed app, so a hit is a real defect.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface InjectionGapRuleResult {
  findings: Finding[];
  logs: string[];
}

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const SAMPLE_PATH = /(?:^|\/)(?:tests?|__tests__|spec|e2e|fixtures?|examples?|samples?|demos?|docs?)\//i;
const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*|#)/.test(l);

/** Request values as they appear inline in Java, Kotlin, Python and JS/TS handlers. */
const REQUEST_INPUT = /\.getParameter\(|\brequest\.(?:getHeader|args|form|values|GET|POST|query|body|params)\b|\breq\.(?:query|body|params|headers)\b/;

/** Names assigned from request input, plus Spring handler parameters. */
function requestVars(content: string): Set<string> {
  const vars = new Set<string>();
  for (const m of content.matchAll(/\b(\w+)\s*(?::\s*[\w<>?]+\s*)?=\s*[^;\n]*(?:\.getParameter\(|\brequest\.(?:getHeader|args|form|values|GET|POST|query|body|params)\b|\breq\.(?:query|body|params|headers)\b)/g)) vars.add(m[1]);
  for (const m of content.matchAll(/@(?:RequestParam|PathVariable|RequestHeader)\b(?:\([^)]*\))?\s+(?:final\s+)?\w+\s+(\w+)/g)) vars.add(m[1]);
  return vars;
}

const usesVar = (text: string, vars: Set<string>) => [...vars].some((v) => new RegExp(`\\b${v}\\b`).test(text));

export function evaluateInjectionGapRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): InjectionGapRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SAMPLE_PATH.test(path)) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => hits.push(h);
  const eachLine = (test: (l: string) => boolean, emit: (i: number) => void) => lines.forEach((l, i) => { if (!isComment(l) && test(l)) emit(i); });

  const isJava = /\.java$/i.test(path);
  const isKotlin = /\.kt$/i.test(path);
  const isPython = /\.py$/i.test(path);
  const isJs = /\.[cm]?[jt]sx?$/i.test(path);
  const isGo = /\.go$/i.test(path);
  const isC = /\.(?:c|cc|cpp|cxx)$/i.test(path);

  // IGAP-01: Archive entry name used as a write path without a containment check (Zip Slip)
  const zipSlip = (i: number) => add({ ruleId: 31001, code: 'IGAP-01', severity: 'HIGH', category: 'Path Traversal', lineIdx: i,
    title: 'Archive Entry Name Used as a Write Path (Zip Slip)',
    why: 'An entry named ../../app/config overwrites files outside the target folder when the archive is unpacked, which can lead to code execution.',
    fix: 'Resolve the final path and refuse the entry unless it stays inside the target folder.' });
  if ((isJava || isKotlin) && /\b(?:ZipEntry|ZipInputStream|ZipFile|TarArchiveEntry|TarArchiveInputStream)\b/.test(cleanContent)
    && !/\.startsWith\(|getCanonical(?:Path|File)\b/.test(cleanContent)) {
    eachLine((l) => /(?:\bFile\(\s*\w+\s*,\s*\w+\.(?:getName\(\)|name)\s*\)|\.resolve\(\s*\w+\.(?:getName\(\)|name)\s*\))/.test(l), zipSlip);
  }
  if (isGo && /\b(?:zip\.OpenReader|zip\.NewReader|tar\.NewReader)\b/.test(cleanContent)
    && !/strings\.HasPrefix|filepath\.IsLocal|filepath\.Rel\(|securejoin|os\.OpenRoot/.test(cleanContent)) {
    eachLine((l) => /filepath\.Join\([^)]*\b\w+\.Name\b/.test(l), zipSlip);
  }
  if (isJs && /\b(?:adm-zip|yauzl|unzipper|tar-stream)\b/.test(cleanContent) && /createWriteStream|writeFile/.test(cleanContent)
    && !/\.startsWith\(|\.relative\(/.test(cleanContent)) {
    eachLine((l) => /path\.(?:join|resolve)\([^)]*\b\w+\.(?:entryName|fileName|path)\b/.test(l), zipSlip);
  }
  if (isPython && /\btarfile\b/.test(cleanContent)) {
    eachLine((l) => /\.extractall\(/.test(l) && !/\bfilter\s*=/.test(l), zipSlip);
  }

  // IGAP-02: Fixed initialization vector
  const fixedIv = (i: number) => add({ ruleId: 31002, code: 'IGAP-02', severity: 'HIGH', category: 'Cryptography', lineIdx: i,
    title: 'Encryption Uses a Fixed Initialization Vector',
    why: 'Equal plaintexts encrypt to equal ciphertexts, and in GCM or CTR mode reusing the IV with the same key lets an attacker recover data.',
    fix: 'Generate a random IV for every encryption and store it next to the ciphertext.' });
  if (isJava || isKotlin) {
    eachLine((l) => /\bIvParameterSpec\(\s*(?:"[^"]*"|new\s+byte\s*\[)/.test(l), fixedIv);
  }
  if (isJs) {
    eachLine((l) => /\bcreateCipheriv\(\s*[^,]+,\s*[^,]+,\s*(?:['"`][^'"`$]*['"`]|Buffer\.(?:from\(\s*['"`]|alloc\())/.test(l), fixedIv);
  }

  const vars = isJava || isKotlin || isPython || isJs ? requestVars(cleanContent) : new Set<string>();

  // IGAP-03: JNDI lookup of a request value
  if (isJava || isKotlin) {
    eachLine((l) => {
      const arg = l.match(/\.lookup\(([^)]*\)?)\)/)?.[1];
      return !!arg && /\b(?:InitialContext|Context|ctx|jndi)\b/i.test(l) && (REQUEST_INPUT.test(arg) || usesVar(arg, vars));
    }, (i) => add({ ruleId: 31003, code: 'IGAP-03', severity: 'CRITICAL', category: 'Injection', lineIdx: i,
      title: 'JNDI Lookup of a Request Value',
      why: 'A name such as ldap://attacker/x makes the server fetch and can load remote objects, the mechanism behind Log4Shell.',
      fix: 'Look up names from a fixed allowlist and never pass request input to Context.lookup.' }));
  }

  // IGAP-04: XPath query built from a request value
  if (isJava || isKotlin || isPython || isJs) {
    eachLine((l) => {
      if (!/(?:\.xpath\(|\bxpath\.(?:evaluate|compile|select|select1)\()/i.test(l)) return false;
      const built = /["'`]\s*\+|\+\s*["'`]|\$\{|\bf["']|%\s*\w|\.format\(/.test(l);
      return built && (REQUEST_INPUT.test(l) || usesVar(l.replace(/["'`][^"'`]*["'`]/g, ' '), vars) || usesVar(l.match(/\$\{([^}]*)\}/)?.[1] || '', vars));
    }, (i) => add({ ruleId: 31004, code: 'IGAP-04', severity: 'HIGH', category: 'Injection', lineIdx: i,
      title: 'XPath Query Built from a Request Value',
      why: "A value such as ' or '1'='1 changes the query, which can bypass a login check or return every node in the document.",
      fix: 'Use XPath variables or bound parameters, or validate the value against a strict pattern.' }));
  }

  // IGAP-05: Non-literal printf format string
  if (isC) {
    eachLine((l) => /\b(?:printf\(\s*|fprintf\(\s*\w+\s*,\s*|syslog\(\s*\w+\s*,\s*)(?!_\(|gettext)[a-z_]\w*(?:\[\w+\])?(?:->\w+)?\s*\)\s*;/.test(l),
      (i) => add({ ruleId: 31005, code: 'IGAP-05', severity: 'HIGH', category: 'Memory Safety', lineIdx: i,
        title: 'Variable Used as a printf Format String',
        why: 'If the value holds %x or %n, the call reads the stack or writes to memory.',
        fix: 'Pass a literal format: printf("%s", value).' }));
  }

  // IGAP-06: JavaScript-enabled WebView loads a URL from the launching Intent
  if ((isJava || isKotlin) && /setJavaScriptEnabled\(\s*true\s*\)|\bjavaScriptEnabled\s*=\s*true\b/.test(cleanContent)) {
    const intentVars = new Set([...cleanContent.matchAll(/\b(\w+)\s*(?::\s*[\w?]+\s*)?=\s*[^;\n]*\bgetStringExtra\(|\b(\w+)\s*(?::\s*[\w?]+\s*)?=\s*[^;\n]*\bintent\.(?:data|dataString)\b/g)].map((m) => m[1] || m[2]));
    eachLine((l) => {
      const arg = l.match(/\.loadUrl\((.*)\)/)?.[1];
      return !!arg && (/\b(?:getStringExtra|getIntent\(\)\.get(?:Data|DataString)|intent\.(?:data|dataString))\b/.test(arg) || usesVar(arg, intentVars));
    }, (i) => add({ ruleId: 31006, code: 'IGAP-06', severity: 'HIGH', category: 'Mobile Security', lineIdx: i,
      title: 'JavaScript WebView Loads a URL from the Intent',
      why: 'Another app or a crafted link can open this screen on an attacker page, which then runs script inside the app and can reach its bridges and cookies.',
      fix: 'Check the URL host against an allowlist before loading it, or keep the Activity unexported.' }));
  }

  // IGAP-07: Intent taken from extras and started as-is (Intent redirection)
  if (isJava || isKotlin) {
    const nested = /\(\s*Intent\s*\)\s*[^;\n]*getParcelableExtra\(|getParcelableExtra<Intent>\(|getParcelableExtra\([^)]*Intent(?:\.class|::class\.java)\s*\)/;
    const intentVars = new Set(lines.filter((l) => nested.test(l)).map((l) => l.match(/\b(\w+)\s*(?::\s*Intent\??\s*)?=/)?.[1]).filter((v): v is string => !!v));
    eachLine((l) => {
      const arg = l.match(/\b(?:startActivity|startActivityForResult|startService|sendBroadcast)\((.*)\)/)?.[1];
      return !!arg && (nested.test(arg) || usesVar(arg, intentVars));
    }, (i) => add({ ruleId: 31007, code: 'IGAP-07', severity: 'HIGH', category: 'Mobile Security', lineIdx: i,
      title: 'Intent from Extras Started Without Validation',
      why: 'A malicious app sends a nested Intent and uses this component to open private Activities or read content it has no permission for.',
      fix: 'Do not forward Intents from extras. If needed, check the target component and strip URI permission flags first.' }));
  }

  // IGAP-08: Struts development mode
  if (/(?:^|\/)struts[\w.-]*\.(?:xml|properties)$/i.test(path)) {
    eachLine((l) => /struts\.devMode["'\s]*(?:value\s*=\s*["']|=\s*)true\b/i.test(l), (i) => add({ ruleId: 31008, code: 'IGAP-08', severity: 'HIGH', category: 'Misconfiguration', lineIdx: i,
      title: 'Struts Development Mode Enabled',
      why: 'devMode exposes debugging features and detailed errors, and has been used to run OGNL expressions on the server.',
      fix: 'Set struts.devMode to false in every deployed configuration.' }));
  }

  // IGAP-09: Sinatra request protections switched off
  if (/\.(?:rb|ru)$/i.test(path) && /\bsinatra\b/i.test(cleanContent)) {
    eachLine((l) => /^\s*(?:disable\s+:protection\b|set\s+:protection\s*,\s*false\b)/.test(l), (i) => add({ ruleId: 31009, code: 'IGAP-09', severity: 'MEDIUM', category: 'Misconfiguration', lineIdx: i,
      title: 'Sinatra Request Protections Disabled',
      why: 'This removes the built-in defenses against session hijacking, clickjacking and path traversal for every route.',
      fix: 'Keep protection on and turn off only the single check that conflicts: set :protection, except: :frame_options.' }));
  }

  // IGAP-10: Django accepts any password
  if (/(?:^|\/)(?:settings|production|prod|base|common)\.py$/i.test(path) && /\bINSTALLED_APPS\b|\bdjango\b/.test(cleanContent)) {
    eachLine((l) => /^\s*AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]/.test(l), (i) => add({ ruleId: 31010, code: 'IGAP-10', severity: 'MEDIUM', category: 'Authentication', lineIdx: i,
      title: 'Django Password Validators Are Empty',
      why: 'Users can register with a one-character password or a common one, which makes account takeover by guessing easy.',
      fix: 'Restore the default validators: minimum length, common password and similarity checks.' }));
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `igap${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [IGAP] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
