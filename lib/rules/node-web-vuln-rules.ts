/**
 * Node.js / Express / Fastify / Hono / Koa web vulnerabilities (NODE-WEB-xx, Rule IDs 28101-28199).
 *
 * Every injection-style rule here needs a taint signal: the sink argument is request input
 * (req.query/params/body, request.*, c.req.query()/param(), ctx.query/params/request.*) on the
 * same line, or a variable assigned / destructured from it a few lines earlier (and not
 * re-declared or sanitized in between). Classes already handled elsewhere (fs.* traversal,
 * exec(), fetch(req.*), res.redirect(req.*), eval, md5/sha1, Math.random, jwt.decode, $where,
 * CORS origin:true + credentials, mass assignment, raw SQL with SELECT/INSERT) are not repeated.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

/** Express / Fastify request input (prefix match: `req.query` also matches `req.query.file`). */
const EXPRESS_SRC = String.raw`\breq(?:uest)?\.(?:query|params|body)\b`;
/** Hono (`c.req.query('x')`) and Koa (`ctx.query.x`, `ctx.request.body`) request input. */
const HK_SRC = String.raw`\bc\.req\.(?:query|param|queries)\s*\(|\bctx\.(?:query|params)\b|\bctx\.request\.(?:query|body)\b|\(\s*await\s+c\.req\.json\(\s*\)\s*\)`;
const ANY_SRC = `(?:${EXPRESS_SRC}|${HK_SRC})`;
/** A whole request object (not one field) - for "passed as a filter / locals" sinks. */
const WHOLE_REQ_OBJ = String.raw`(?:req(?:uest)?\.(?:query|body)|ctx\.query|ctx\.request\.(?:query|body))`;
/** Assignments whose right-hand side is sanitized / converted do not propagate taint. */
const SANITIZER = /\b(?:basename|parseInt|parseFloat|Number|Boolean|safeParse|parse|escape\w*|sanitize\w*|validate\w*|encodeURIComponent|isValid\w*|valid|DOMPurify|xss|slugify|ObjectId|isUUID|uuidValidate)\s*\(|\bz\.|\.(?:includes|has)\(|^\s*[A-Z][A-Z0-9_]*\s*\[/;
const TAINT_WINDOW = 30;

interface VarDecl { line: number; tainted: boolean; rhs: string; whole: boolean }

const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*)/.test(l);

/** Split the text after a call's "(" into its top-level arguments (stops at the closing paren). */
function topLevelArgs(s: string): string[] {
  const args: string[] = [];
  let depth = 0, cur = '', quote = '';
  for (const ch of s) {
    if (quote) { cur += ch; if (ch === quote) quote = ''; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) { if (depth === 0) { args.push(cur); return args; } depth--; }
    if (ch === ',' && depth === 0) { args.push(cur); cur = ''; continue; }
    cur += ch;
  }
  return args;
}

export function evaluateNodeWebVulnRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  if (!/\.[cm]?[jt]sx?$/i.test(file.path) || /(?:^|\/)node_modules\//.test(file.path) || /\.d\.ts$/i.test(file.path)) return { findings, logs };
  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };

  // ---- taint bookkeeping -------------------------------------------------------------------
  const hasSource = new RegExp(ANY_SRC).test(cleanContent);
  const decls = new Map<string, VarDecl[]>();
  const record = (name: string, d: VarDecl) => {
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return;
    const list = decls.get(name) || [];
    list.push(d);
    decls.set(name, list);
  };
  if (hasSource) {
    const srcRe = new RegExp(ANY_SRC);
    const wholeRe = new RegExp(String.raw`^\s*(?:await\s+)?(?:${WHOLE_REQ_OBJ}|c\.req\.json\(\s*\))\s*(?:as\s+[\w<>[\]{}:;,\s|]+)?;?\s*$`);
    lines.forEach((l, i) => {
      for (const m of l.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]|\s]+)?=\s*([^;]*)/g)) {
        const rhs = m[2];
        record(m[1], { line: i, tainted: srcRe.test(rhs) && !SANITIZER.test(rhs), rhs, whole: wholeRe.test(rhs) });
      }
      const destr = l.match(/\b(?:const|let|var)\s*\{([^=]*)\}\s*(?::\s*[^=]+)?=\s*([^;]*)/);
      if (destr) {
        const rhs = destr[2];
        const tainted = new RegExp(String.raw`^\s*(?:await\s+)?(?:${WHOLE_REQ_OBJ}|req(?:uest)?\.params|ctx\.params|c\.req\.(?:query|param)\(\s*\)|c\.req\.json\(\s*\))\b`).test(rhs);
        for (const part of destr[1].split(',')) {
          const name = (part.split(':').pop() || '').split('=')[0].replace(/[{}\s.]/g, '');
          record(name, { line: i, tainted, rhs, whole: false });
        }
      }
    });
  }
  /** Names that hold request input at line idx (the latest declaration before idx is tainted). */
  const taintedVarsAt = (idx: number, srcFilter?: RegExp, wholeOnly = false): string[] => {
    const out: string[] = [];
    for (const [name, list] of decls) {
      let last: VarDecl | undefined;
      for (const d of list) if (d.line < idx) last = d;
      if (!last || idx - last.line > TAINT_WINDOW) continue;
      if (wholeOnly ? !last.whole : !last.tainted) continue;
      if (srcFilter && !srcFilter.test(last.rhs)) continue;
      out.push(name.replace(/\$/g, '\\$'));
    }
    return out;
  };
  const reCache = new Map<string, RegExp>();
  const rx = (src: string, flags = '') => {
    const key = flags + '|' + src;
    let r = reCache.get(key);
    if (!r) { r = new RegExp(src, flags); reCache.set(key, r); }
    return r;
  };
  /** Regex source for "request input" at line idx: direct source or a tainted variable. */
  const taint = (idx: number, src = ANY_SRC, srcFilter?: RegExp, excludeVars: string[] = []): string => {
    const vars = taintedVarsAt(idx, srcFilter).filter((v) => !excludeVars.includes(v));
    return vars.length ? String.raw`(?:${src}|\b(?:${vars.join('|')})\b(?![\w$]))` : src;
  };
  /** Scan each code line; `build(idx)` returns the sink regex for that line (or null to skip). */
  const scan = (pre: RegExp | null, build: (idx: number) => RegExp | null, onHit: (idx: number) => void, skip?: (idx: number) => boolean) => {
    lines.forEach((l, i) => {
      if (isComment(l) || (pre && !pre.test(l))) return;
      const re = build(i);
      if (re && re.test(l) && !(skip && skip(i))) onHit(i);
    });
  };
  const nearby = (idx: number, before: number, after: number, re: RegExp) =>
    lines.slice(Math.max(0, idx - before), Math.min(lines.length, idx + after + 1)).some((l) => re.test(l));
  const windowText = (idx: number, size: number) => lines.slice(idx, Math.min(lines.length, idx + size)).join(' ');
  const pathArg = (t: string) => String.raw`(?:path\.(?:join|resolve)\([^)]*?|\x60[^\x60]*\$\{\s*|[^,()]*\+\s*)?` + t;
  const strArg = (t: string) => String.raw`(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)` + t;

  if (hasSource) {
    // NODE-WEB-01: res.sendFile / res.download with a request-controlled path (no root option)
    scan(/\bres\.(?:sendFile|download)\s*\(/, (i) => rx(String.raw`\bres\.(?:sendFile|download)\s*\(\s*` + pathArg(taint(i))),
      (i) => add({ ruleId: 28101, code: 'NODE-WEB-01', severity: 'HIGH', category: 'Path Traversal', lineIdx: i,
        title: 'Path Traversal in res.sendFile / res.download (CWE-22)',
        why: 'The file path comes from the request; "../" segments (or an absolute path) let a caller download any file the process can read, e.g. .env or /etc/passwd.',
        fix: 'Pass only a file name with the { root: SAFE_DIR } option (res.sendFile(name, { root })), or resolve the path and reject it unless it startsWith the allowed directory.' }),
      (i) => /\broot\s*:|basename\s*\(/.test(lines[i]) || nearby(i, 6, 0, /\.startsWith\(|path\.relative\(|isPathInside|isSubPath/));

    // NODE-WEB-02: prototype pollution through request-controlled nested keys
    scan(/\]\s*\[[^\]]+\]\s*=(?!=)/, (i) => rx(String.raw`[\w$.]+\[\s*` + taint(i) + String.raw`[^\]]*\]\s*\[[^\]]+\]\s*=(?![=>])`),
      (i) => add({ ruleId: 28102, code: 'NODE-WEB-02', severity: 'HIGH', category: 'Prototype Pollution', lineIdx: i,
        title: 'Prototype Pollution via Request-Controlled Object Keys (CWE-1321)',
        why: 'obj[key][prop] = value with key from the request lets a caller send key="__proto__" and set properties on Object.prototype for the whole process (auth bypass, DoS, or RCE gadgets).',
        fix: 'Reject "__proto__", "constructor" and "prototype" keys, check the key against an allow-list, or store user-keyed data in a Map / Object.create(null).' }),
      (i) => nearby(i, 6, 0, /__proto__|hasOwn(?:Property)?\(|\.includes\(|\.has\(|Object\.create\(\s*null\s*\)|ALLOWED|allowed/));

    // NODE-WEB-03: whole request object used as a database filter (operator injection)
    const queryMethods = String.raw`\.(?:find|findOne|findMany|findFirst|findAll|findAndCountAll|count|countDocuments|deleteMany|deleteOne|updateMany|updateOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|exists)\s*\(\s*`;
    scan(rx(queryMethods), (i) => {
      const whole = taintedVarsAt(i, undefined, true);
      const obj = whole.length ? String.raw`(?:${WHOLE_REQ_OBJ}|\b(?:${whole.join('|')})\b)` : WHOLE_REQ_OBJ;
      return rx(queryMethods + String.raw`(?:\{\s*where\s*:\s*|\{\s*\.\.\.\s*)?` + obj + String.raw`\s*[,)}]`);
    }, (i) => add({ ruleId: 28103, code: 'NODE-WEB-03', severity: 'HIGH', category: 'Injection', lineIdx: i,
      title: 'NoSQL / ORM Operator Injection via Request Object Used as Query Filter (CWE-943)',
      why: 'The parsed query string / JSON body is the filter itself, so ?password[$ne]=x (MongoDB) or {"password":{"startsWith":"a"}} (Prisma) turns a lookup into an operator query that bypasses checks or leaks fields.',
      fix: 'Build the filter from validated scalar fields (e.g. zod schema -> { email: String(email) }); never pass req.query / req.body as the where clause.' }));

    // NODE-WEB-04: login lookup with the request password inside the DB query
    scan(/\.(?:findOne|findFirst|findUnique|find|findOneBy|findBy|where)\s*\(/, () => /./, (i) => {
      const text = windowText(i, 6);
      const call = text.match(/\.(?:findOne|findFirst|findUnique|find|findOneBy|findBy|where)\s*\(\s*\{([^)]*)/);
      if (!call) return;
      const body = call[1];
      const t = taint(i + 1);
      const explicit = rx(String.raw`\bpassword\s*:\s*` + t).test(body);
      const shorthand = /(?:[{,]\s*)password\s*[,}]/.test(body) && taintedVarsAt(i + 1).includes('password');
      if (explicit || shorthand) add({ ruleId: 28104, code: 'NODE-WEB-04', severity: 'HIGH', category: 'Authentication', lineIdx: i,
        title: 'Login Query Matches the Request Password in the Database Filter',
        why: 'Querying { email, password } with the submitted password means passwords are stored in plaintext, and with a JSON body {"password":{"$ne":null}} (MongoDB) or a Prisma filter object it bypasses the login entirely.',
        fix: 'Look the user up by email only, then compare with bcrypt.compare / argon2.verify against the stored hash.' });
    });

    // NODE-WEB-05: regular expression built from request input (ReDoS / regex injection)
    scan(/new\s+RegExp\s*\(|\$regex\s*:/, (i) => rx(String.raw`new\s+RegExp\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?` + taint(i) + String.raw`|\$regex\s*:\s*(?:\x60[^\x60]*\$\{\s*)?` + taint(i)),
      (i) => add({ ruleId: 28105, code: 'NODE-WEB-05', severity: 'MEDIUM', category: 'Denial of Service', lineIdx: i,
        title: 'Regular Expression Built From Request Input (ReDoS / Regex Injection, CWE-1333)',
        why: 'A caller-supplied pattern such as (a+)+$ blocks the single Node event loop (or MongoDB) with catastrophic backtracking, and ".*" turns a search into a match-everything query.',
        fix: 'Escape the input before building the pattern (escape-string-regexp / lodash escapeRegExp) or use a plain substring / text-index search.' }),
      (i) => /escape/i.test(lines[i]));

    // NODE-WEB-10: reflected XSS - request input interpolated into an HTML response
    const htmlSink = String.raw`(?:\bres(?:\.status\(\s*\d+\s*\))?\.send|\bc\.html|\breply\.type\(\s*['"]text\/html['"]\s*\)\.send)\s*\(\s*`;
    const rawSink = String.raw`\bres\.(?:write|end)\s*\(\s*`;
    scan(/\b(?:res|c|reply)\b[^;]*\.(?:send|html|write|end)\s*\(/, (i) => {
      const t = taint(i);
      return rx(htmlSink + strArg(t) + '|' + rawSink + String.raw`(?:\x60[^\x60]*<[^\x60]*\$\{\s*|['"][^'"]*<[^'"]*['"]\s*\+\s*)` + t);
    }, (i) => add({ ruleId: 28110, code: 'NODE-WEB-10', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'Reflected XSS: Request Input Interpolated Into an HTML Response (CWE-79)',
      why: 'res.send(string) is served as text/html, so ?name=<script>... in the interpolated value runs in the victim\'s browser on this origin.',
      fix: 'Return JSON (res.json), render through an auto-escaping template, or HTML-escape the value (e.g. escape-html) before interpolating it.' }),
    (i) => /escape|sanitize|encode|DOMPurify|xss\(/i.test(lines[i]));

    // NODE-WEB-11: view name chosen by the request (template / local file inclusion)
    scan(/\b(?:res|ctx)\.render\s*\(/, (i) => rx(String.raw`\b(?:res|ctx)\.render\s*\(\s*(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)?` + taint(i)),
      (i) => add({ ruleId: 28111, code: 'NODE-WEB-11', severity: 'HIGH', category: 'Injection', lineIdx: i,
        title: 'Template Path Injection: res.render View Name From Request (CWE-73)',
        why: 'The view engine resolves the request-supplied name as a file path, so "../" names render arbitrary files as templates (file disclosure, and code execution with EJS/Pug).',
        fix: 'Map the request value to a fixed set of view names (const VIEWS = { a: "a", b: "b" }) and render only known keys.' }));

    // NODE-WEB-12: whole request object passed as render locals (EJS / hbs options injection)
    scan(/\b(?:res|ctx)\.render\s*\(/, () => rx(String.raw`\b(?:res|ctx)\.render\s*\(\s*[^,()]+,\s*(?:\{\s*\.\.\.\s*)?` + WHOLE_REQ_OBJ + String.raw`\s*[,)}]`),
      (i) => add({ ruleId: 28112, code: 'NODE-WEB-12', severity: 'HIGH', category: 'Injection', lineIdx: i,
        title: 'Request Object Passed as Template Locals (EJS / hbs Option Injection RCE)',
        why: 'Express merges locals into the engine options, so ?settings[view options][outputFunctionName]=x;process.mainModule.require("child_process").execSync(...) gives RCE in EJS (CVE-2022-29078) and file reads in hbs.',
        fix: 'Pass an explicit object with only the fields the view needs: res.render("search", { q: String(req.query.q ?? "") }).' }));

    // NODE-WEB-14: node:vm running request input (vm is not a sandbox)
    scan(/\bvm\.|runIn(?:New|This)?Context|compileFunction|new\s+Script\s*\(/, (i) =>
      rx(String.raw`(?:\bvm\.)?(?:runInNewContext|runInContext|runInThisContext|compileFunction)\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?` + taint(i) + String.raw`|new\s+(?:vm\.)?Script\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?` + taint(i)),
    (i) => add({ ruleId: 28114, code: 'NODE-WEB-14', severity: 'CRITICAL', category: 'Code Injection', lineIdx: i,
      title: 'Remote Code Execution: node:vm Evaluates Request Input (CWE-94)',
      why: 'node:vm is not a security boundary; this.constructor.constructor("return process")() escapes the context and runs arbitrary code on the server.',
      fix: 'Do not evaluate user code in-process. Use a declarative format (JSON / expression parser with an allow-list) or an isolated runtime (isolated-vm, a separate container).' }));

    // NODE-WEB-16: spawn / execFile with a request-chosen binary or shell: true
    scan(/\b(?:spawn|spawnSync|execFile|execFileSync|fork|execaCommand|execaCommandSync)\s*\(/, (i) => {
      const t = taint(i);
      const binary = rx(String.raw`\b(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(\s*` + t + String.raw`|\bexecaCommand(?:Sync)?\s*\(\s*(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)?` + t);
      if (binary.test(lines[i])) return /./;
      const text = windowText(i, 4);
      return rx(t).test(text) && /\bshell\s*:\s*true/.test(text) && /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(/.test(text) ? /./ : null;
    }, (i) => add({ ruleId: 28116, code: 'NODE-WEB-16', severity: 'CRITICAL', category: 'Command Injection', lineIdx: i,
      title: 'Command Injection: spawn / execFile With Request-Controlled Command or shell: true (CWE-78)',
      why: 'Either the executable itself comes from the request, or shell: true re-parses the arguments through /bin/sh, so ";" / "$()" in the input run arbitrary commands.',
      fix: 'Use a fixed executable path with an argument array and shell: false; map request values to an allow-list of commands.' }));

    // NODE-WEB-17: require() / import() of request input
    scan(/\b(?:require|import)\s*\(/, (i) => rx(String.raw`\b(?:require|import)\s*\(\s*` + pathArg(taint(i))),
      (i) => add({ ruleId: 28117, code: 'NODE-WEB-17', severity: 'CRITICAL', category: 'Code Injection', lineIdx: i,
        title: 'Dynamic require() / import() of Request Input (CWE-94)',
        why: 'Loading a module named by the request executes any reachable .js file (including uploads) and discloses JSON files such as config with secrets.',
        fix: 'Resolve the name through a static map of allowed modules: const handlers = { csv: csvHandler }; handlers[name] ?? reject.' }));

    // NODE-WEB-18: SSRF from Hono / Koa input, or axios/got config objects with a request URL
    const httpClient = String.raw`(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|https?\.(?:get|request)|needle(?:\.(?:get|post|request))?|got(?:\.(?:get|post|stream))?|superagent\.(?:get|post)|undici\.request|ky(?:\.(?:get|post))?)`;
    const ssrfGuard = /validateSafeTargetUrl|isAllowedWebhookUrl|\b(?:ALLOWED|allowed|ALLOW|allow)\w*\.(?:has|includes)\(\s*\w+\.(?:hostname|host|origin)|\.(?:hostname|host|origin)\s*(?:===|!==)|isAllowed\w*\(|validate\w*Url\(|(?:assert|ensure|is)Safe\w*Url\(|ssrfGuard|ssrf-?(?:req-)?filter|request-filtering-agent/i;
    if (!ssrfGuard.test(cleanContent)) {
      // Variables fed from req.query/body/params (incl. Hono's c.req.query) are already handled by SEC-34
      const hkFilter = new RegExp(String.raw`^(?![\s\S]*\breq(?:uest)?\.(?:query|body|params)\b)[\s\S]*(?:${HK_SRC})`);
      scan(rx(String.raw`\b` + httpClient + String.raw`\s*\(`), (i) => {
        const hk = taint(i, HK_SRC, hkFilter);
        return rx(String.raw`\b` + httpClient + String.raw`\s*\(\s*(?:\x60[^\x60]*\$\{\s*|new\s+URL\(\s*)?` + hk +
          String.raw`|\b(?:axios|got|needle|request|ky|undici\.request)(?:\.request)?\s*\(\s*\{[^}]*\b(?:url|uri|baseURL)\s*:\s*(?:\x60[^\x60]*\$\{\s*)?` + taint(i));
      }, (i) => add({ ruleId: 28118, code: 'NODE-WEB-18', severity: 'HIGH', category: 'Network & SSRF', lineIdx: i,
        title: 'Server-Side Request Forgery: Outbound Request to a Request-Supplied URL (CWE-918)',
        why: 'The server fetches a URL chosen by the caller, reaching internal services and cloud metadata (http://169.254.169.254/) from inside your network.',
        fix: 'Parse the URL, require https and an allow-listed hostname, and resolve DNS to reject private / link-local ranges (or use request-filtering-agent).' }));
    }

    // NODE-WEB-19: open redirect forms not covered by the generic rule (Hono / Koa / Fastify / status-first / location)
    const redirectGuard = /\.startsWith\(\s*['"]\/['"]\s*\)|new URL\(|allowed|ALLOWED|isSafe\w*\(|isRelative\w*\(|isValidRedirect|isAllowed\w*\(|\.includes\(|\.has\(/;
    const genericNames = ['next', 'url', 'redirectUrl', 'redirectTo', 'target', 'targetUrl', 'returnTo', 'returnUrl', 'callbackUrl'];
    scan(/\.(?:redirect|location)\s*\(/, (i) => {
      const hkT = taint(i, HK_SRC, new RegExp(HK_SRC), genericNames);
      const reqT = taint(i, String.raw`\brequest\.(?:query|body|params)\b`, /\brequest\./, genericNames);
      const expT = taint(i, EXPRESS_SRC, undefined, genericNames);
      return rx(String.raw`\b(?:c|ctx)\.redirect\s*\(\s*` + hkT +
        String.raw`|\breply\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?` + reqT +
        String.raw`|\bres\.redirect\s*\(\s*\d{3}\s*,\s*` + expT +
        String.raw`|\bres\.location\s*\(\s*` + expT);
    }, (i) => add({ ruleId: 28119, code: 'NODE-WEB-19', severity: 'MEDIUM', category: 'Open Redirect', lineIdx: i,
      title: 'Open Redirect to a Request-Supplied URL (CWE-601)',
      why: 'The redirect target comes straight from the request, so a link on your domain can bounce users to a phishing page (and leak OAuth codes / tokens in the URL).',
      fix: 'Only redirect to relative paths (value.startsWith("/") && !value.startsWith("//")) or to hosts in an allow-list; fall back to a fixed page.' }),
    (i) => nearby(i, 6, 0, redirectGuard));

    // NODE-WEB-25: SQL fragment builders with request input (knex whereRaw / orderByRaw / raw, Sequelize.literal, TypeORM where)
    scan(/(?:Raw|\.raw|literal|\.(?:where|andWhere|orWhere|having|orderBy))\s*\(/, (i) => {
      const t = taint(i);
      return rx(String.raw`\.(?:whereRaw|orWhereRaw|andWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw|fromRaw)\s*\(\s*` + strArg(t) +
        String.raw`|\b(?:knex|db|trx|this\.knex)\.raw\s*\(\s*` + strArg(t) +
        String.raw`|\b(?:Sequelize|sequelize)\.literal\s*\(\s*` + strArg(t) +
        String.raw`|\.(?:where|andWhere|orWhere|having)\s*\(\s*\x60[^\x60]*\$\{\s*` + t);
    }, (i) => add({ ruleId: 28125, code: 'NODE-WEB-25', severity: 'CRITICAL', category: 'Injection', lineIdx: i,
      title: 'SQL Injection: Request Input Interpolated Into a Raw Query Fragment (CWE-89)',
      why: 'Query-builder escape hatches (whereRaw, orderByRaw, knex.raw, Sequelize.literal, TypeORM string where) send the string to the database verbatim, so the interpolated request value is executed as SQL.',
      fix: 'Use bindings: whereRaw("price > ?", [value]), .where("u.id = :id", { id }); map sort columns through an allow-list instead of interpolating them.' }));
  }

  // NODE-WEB-13: Zip Slip - archive entry name joined into an output path without a containment check
  if (/['"](?:unzipper|adm-zip|yauzl|yauzl-promise|tar-stream|jszip|node-stream-zip|unzip-stream|decompress)['"]/.test(cleanContent)) {
    scan(/path\.(?:join|resolve)\s*\(/, () => /path\.(?:join|resolve)\s*\([^)]*\b(?:entry|zipEntry|header|item|zipFile|archiveEntry|e)\.(?:path|entryName|fileName|name)\b/,
      (i) => add({ ruleId: 28113, code: 'NODE-WEB-13', severity: 'HIGH', category: 'Path Traversal', lineIdx: i,
        title: 'Zip Slip: Archive Entry Name Used as an Output Path (CWE-22)',
        why: 'Archive entry names are attacker-controlled; an entry named "../../app/server.js" is written outside the extraction directory, overwriting code or config.',
        fix: 'Resolve the destination and skip the entry unless resolved.startsWith(path.resolve(outDir) + path.sep).' }),
      (i) => nearby(i, 4, 6, /\.startsWith\(|path\.relative\(|isPathInside|isSubPath|includes\(\s*['"]\.\.['"]\s*\)/));
  }

  // NODE-WEB-06: hardcoded JWT signing / verification secret
  const jwtSecondArgLiteral = (idx: number) => {
    const text = windowText(idx, 4);
    const start = text.search(/\bjwt\.(?:sign|verify)\s*\(/);
    if (start === -1) return false;
    const args = topLevelArgs(text.slice(text.indexOf('(', start) + 1));
    return args.length >= 2 && /^(['"])[^'"\s]{3,}\1$/.test(args[1].trim());
  };
  scan(/\bjwt\.(?:sign|verify)\s*\(|\bsecretOrKey\s*:|\bexpressjwt\s*\(|\bexpressJwt\s*\(/,
    (i) => jwtSecondArgLiteral(i) || /\bsecretOrKey\s*:\s*['"][^'"]{3,}['"]|\bexpress[jJ]wt\s*\(\s*\{[^}]*\bsecret\s*:\s*['"][^'"]{3,}['"]/.test(lines[i]) ? /./ : null,
    (i) => add({ ruleId: 28106, code: 'NODE-WEB-06', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
      title: 'Hardcoded JWT Signing Secret in Source Code (CWE-798)',
      why: 'Anyone with the repository (or a leaked bundle) can mint valid tokens for any user, including admins, with this literal key.',
      fix: 'Load the key from the environment / secret manager (process.env.JWT_SECRET) and fail startup when it is missing; rotate the leaked value.' }));

  // NODE-WEB-08: crypto.createCipher / createDecipher (no IV, MD5 key derivation; removed in Node 22)
  const cryptoDestructured = /\{[^}]*\bcreate(?:Cipher|Decipher)\b[^}]*\}\s*=\s*require\(\s*['"](?:node:)?crypto['"]\s*\)|import\s*\{[^}]*\bcreate(?:Cipher|Decipher)\b[^}]*\}\s*from\s*['"](?:node:)?crypto['"]/.test(cleanContent);
  scan(/create(?:Cipher|Decipher)\s*\(/, () => cryptoDestructured ? /(?:\bcrypto\.|(?<![.\w]))create(?:Cipher|Decipher)\s*\(/ : /\bcrypto\.create(?:Cipher|Decipher)\s*\(/,
    (i) => add({ ruleId: 28108, code: 'NODE-WEB-08', severity: 'HIGH', category: 'Cryptography', lineIdx: i,
      title: 'Deprecated crypto.createCipher Without IV (Weak Key Derivation, CWE-327)',
      why: 'createCipher derives the key with a single MD5 pass and a fixed IV, so identical plaintexts encrypt identically and CTR/GCM modes reuse the keystream; it was removed in Node 22.',
      fix: 'Use crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12)) with a 32-byte key from scrypt/HKDF, and store the IV and auth tag with the ciphertext.' }));

  // NODE-WEB-09: createCipheriv with a constant IV
  if (/createCipheriv\s*\(/.test(cleanContent)) {
    const constIv = String.raw`(?:Buffer\.alloc\(\s*\d+\s*(?:,\s*0\s*)?\)|Buffer\.from\(\s*['"][^'"]*['"]\s*(?:,\s*['"]\w+['"]\s*)?\)|['"][^'"]{8,}['"]|new\s+Uint8Array\(\s*\d+\s*\))`;
    const ivVars = [...cleanContent.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(\w*(?:iv|IV|Iv|nonce|Nonce|NONCE)\w*)\s*=\s*` + constIv + String.raw`\s*;?\s*$`, 'gm'))].map((m) => m[1]);
    const ivArg = ivVars.length ? String.raw`(?:${constIv}|\b(?:${ivVars.join('|')})\b)` : constIv;
    scan(/createCipheriv\s*\(/, () => rx(String.raw`createCipheriv\s*\(\s*[^,]+,\s*[^,]+,\s*` + ivArg + String.raw`\s*[,)]`),
      (i) => add({ ruleId: 28109, code: 'NODE-WEB-09', severity: 'MEDIUM', category: 'Cryptography', lineIdx: i,
        title: 'Static / Zero IV Passed to createCipheriv (CWE-329)',
        why: 'Reusing one IV for every message makes CBC deterministic and breaks GCM/CTR completely (keystream reuse reveals plaintext XORs and allows tag forgery).',
        fix: 'Generate a fresh IV per message with crypto.randomBytes(12) (GCM) or randomBytes(16) (CBC) and store it alongside the ciphertext.' }));
  }

  // NODE-WEB-07: non-constant-time comparison of an HMAC signature
  if (/createHmac\s*\(/.test(cleanContent)) {
    const operand = String.raw`([\w$.]+(?:\[[^\]]+\])?(?:\([^)]*\))?)`;
    scan(/[!=]==/, () => /./, (i) => {
      const l = lines[i];
      if (/timingSafeEqual|typeof|\.length\b|byteLength/.test(l)) return;
      const m = l.match(new RegExp(operand + String.raw`\s*(?:===|!==)\s*` + operand));
      if (!m) return;
      const [a, b] = [m[1], m[2]];
      const sig = /signature|\bsig\b|sig$|^sig|digest|hmac/i;
      const literal = /^(?:null|undefined|true|false|\d+|['"`])/;
      if (literal.test(a) || literal.test(b) || /^['"`]/.test(l.slice(l.indexOf(m[0]) + m[0].length - b.length))) return;
      if ((sig.test(a) && (sig.test(b) || /expected|computed|calculated/i.test(b))) || (sig.test(b) && /expected|computed|calculated/i.test(a))) {
        add({ ruleId: 28107, code: 'NODE-WEB-07', severity: 'MEDIUM', category: 'Cryptography', lineIdx: i,
          title: 'HMAC Signature Compared With === (Timing Attack, CWE-208)',
          why: 'String equality returns at the first differing byte, so response timing lets an attacker recover a valid webhook / token signature byte by byte.',
          fix: 'Compare equal-length Buffers with crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)) after checking their lengths.' });
      }
    });
  }

  // NODE-WEB-15: vm2 (abandoned; sandbox escapes with no fix, e.g. CVE-2023-37466)
  scan(/vm2/, () => /require\(\s*['"]vm2['"]\s*\)|from\s+['"]vm2['"]/,
    (i) => add({ ruleId: 28115, code: 'NODE-WEB-15', severity: 'HIGH', category: 'Code Injection', lineIdx: i,
      title: 'vm2 Sandbox Used to Run Code (Abandoned, Known Escapes)',
      why: 'vm2 was discontinued in 2023 with unpatched sandbox escapes (CVE-2023-37466, CVE-2023-37903); any code it runs can take over the host process.',
      fix: 'Replace vm2 with isolated-vm or run untrusted code in a separate container / process with no secrets.' }));

  // NODE-WEB-20: password-reset / verification link built from the Host header
  {
    const hostSrc = String.raw`(?:\breq\.headers\.host\b|\breq\.headers\[\s*['"](?:host|x-forwarded-host)['"]\s*\]|\breq\.(?:get|header)\(\s*['"](?:host|x-forwarded-host)['"]\s*\)|\breq\.hostname\b|\bc\.req\.header\(\s*['"](?:host|x-forwarded-host)['"]\s*\)|\bctx\.(?:host|hostname|origin)\b|\brequest\.headers\.host\b|\brequest\.hostname\b)`;
    const linkWord = /reset|verify|verification|confirm|invite|magic|activat|token=|\/auth\//i;
    const hostRe = new RegExp(hostSrc);
    const hostVars = new Map<string, number>();
    lines.forEach((l, i) => {
      if (isComment(l) || !hostRe.test(l)) return;
      const decl = l.match(/\b(?:const|let|var)\s+(\w+)\s*=/);
      if (linkWord.test(l) && /\x60|\+/.test(l)) {
        add({ ruleId: 28120, code: 'NODE-WEB-20', severity: 'HIGH', category: 'Authentication', lineIdx: i,
          title: 'Password Reset / Verification Link Built From the Host Header (CWE-640)',
          why: 'The Host header is client-controlled; an attacker requests a reset for the victim with Host: evil.com, the emailed link points to their server, and the victim\'s click leaks the reset token.',
          fix: 'Build emailed links from a configured base URL (process.env.APP_URL), never from req.headers.host / req.get("host").' });
      } else if (decl) hostVars.set(decl[1], i);
    });
    for (const [name, at] of hostVars) {
      const use = new RegExp(String.raw`\$\{\s*` + name + String.raw`\s*\}|\b` + name + String.raw`\s*\+`);
      for (let i = at + 1; i < Math.min(lines.length, at + 20); i++) {
        if (!isComment(lines[i]) && use.test(lines[i]) && linkWord.test(lines[i])) {
          add({ ruleId: 28120, code: 'NODE-WEB-20', severity: 'HIGH', category: 'Authentication', lineIdx: i,
            title: 'Password Reset / Verification Link Built From the Host Header (CWE-640)',
            why: `${name} is taken from the client-controlled Host header; an attacker requests a reset for the victim with Host: evil.com and the emailed link leaks the reset token to them.`,
            fix: 'Build emailed links from a configured base URL (process.env.APP_URL), never from req.headers.host / req.get("host").' });
          break;
        }
      }
    }
  }

  // NODE-WEB-21: password hashed with a fast unsalted SHA-2 digest (md5/sha1 are covered elsewhere)
  scan(/createHash\s*\(/, () => /./, (i) => {
    const text = windowText(i, 3);
    if (/createHash\s*\(\s*['"](?:sha224|sha256|sha384|sha512|sha3-256|sha3-512|sha512-256)['"]\s*\)\s*\.update\(\s*[^)]*\b(?:password|passwd|pwd|plainPassword|plainTextPassword|newPassword)\b(?!\s*(?:Reset|Token|Hash))/.test(text)) {
      add({ ruleId: 28121, code: 'NODE-WEB-21', severity: 'HIGH', category: 'Cryptography', lineIdx: i,
        title: 'Password Hashed With a Fast SHA-2 Digest (CWE-916)',
        why: 'SHA-256/512 run billions of times per second on a GPU, so a leaked table of these hashes is cracked quickly; password storage needs a slow, salted KDF.',
        fix: 'Hash passwords with argon2id (argon2.hash), bcrypt (cost >= 12) or crypto.scrypt with a per-user salt, and verify with the matching compare function.' });
    }
  });

  // NODE-WEB-22: CORS reflects the request Origin while allowing credentials
  if (/credentials\s*:\s*true|Access-Control-Allow-Credentials['"]\s*,\s*(?:['"]true['"]|true)/.test(cleanContent)) {
    const originSrc = String.raw`(?:req\.headers\.origin|req\.headers\[\s*['"]origin['"]\s*\]|req\.(?:get|header)\(\s*['"]origin['"]\s*\)|c\.req\.header\(\s*['"]origin['"]\s*\)|ctx\.(?:get\(\s*['"]origin['"]\s*\)|request\.header\.origin|headers\.origin)|request\.headers\.origin)`;
    const originVars = [...cleanContent.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(\w+)\s*=\s*` + originSrc + String.raw`\s*;?\s*$`, 'gm'))].map((m) => m[1]);
    const value = originVars.length ? String.raw`(?:${originSrc}|\b(?:${originVars.join('|')})\b\s*[,)])` : originSrc;
    const guard = /\.includes\(|\.has\(|\.indexOf\(|\.test\(|allowed|ALLOWED|whitelist|allowList|===|!==|\.endsWith\(/;
    scan(/Access-Control-Allow-Origin|origin\s*:/, () => rx(
      String.raw`(?:setHeader|header|set|append)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*` + value +
      String.raw`|\borigin\s*:\s*(?:function\s*)?\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*(?:=>)?\s*\{?\s*(?:return\s+)?\2\(\s*null\s*,\s*(?:true|\1)\s*\)` +
      String.raw`|\borigin\s*:\s*(?:\(\s*(\w+)\s*(?:,\s*\w+\s*)?\)|(\w+))\s*=>\s*(?:\3|\4)\s*[,}]`),
    (i) => add({ ruleId: 28122, code: 'NODE-WEB-22', severity: 'HIGH', category: 'CORS', lineIdx: i,
      title: 'CORS Reflects Any Origin With Credentials Allowed (CWE-942)',
      why: 'Echoing the request Origin together with Access-Control-Allow-Credentials lets any website make authenticated requests with the user\'s cookies and read the responses.',
      fix: 'Compare the Origin against an explicit allow-list and only then echo it (and set Vary: Origin); otherwise omit the CORS headers.' }),
    (i) => nearby(i, 6, 0, guard) && !/origin\s*:/.test(lines[i]));
  }

  // NODE-WEB-23: static file middleware serving the project root (exposes .env, source, package.json)
  scan(/static|serveStatic|\broot\s*:/, () => /\b(?:express\.static|serveStatic|koaStatic)\s*\(\s*(?:__dirname|process\.cwd\(\)|['"]\.\/?['"]|path\.(?:join|resolve)\(\s*(?:__dirname|process\.cwd\(\))\s*(?:,\s*['"]\.\.?\/?['"]\s*)?\)|__dirname\s*\+\s*['"]\/\.\.\/?['"])\s*[,)]|\bserveStatic\s*\(\s*\{\s*root\s*:\s*['"]\.\/?['"]\s*[,}]/,
    (i) => add({ ruleId: 28123, code: 'NODE-WEB-23', severity: 'HIGH', category: 'Information Disclosure', lineIdx: i,
      title: 'Static File Server Exposes the Project Directory (.env, Source Code)',
      why: 'Serving the application directory publishes every file in it: GET /.env, /package.json or /server.js return secrets and source to anyone.',
      fix: 'Serve a dedicated assets directory only: express.static(path.join(__dirname, "public")).' }));

  // NODE-WEB-24: JWT algorithm confusion (HMAC and RSA/EC accepted together) or tokens signed with "none"
  scan(/algorithms?\s*:/, () => /\balgorithms\s*:\s*\[[^\]]*['"]HS\d{3}['"][^\]]*['"](?:RS|ES|PS)\d{3}['"]|\balgorithms\s*:\s*\[[^\]]*['"](?:RS|ES|PS)\d{3}['"][^\]]*['"]HS\d{3}['"]|\balgorithm\s*:\s*['"]none['"]/i,
    (i) => add({ ruleId: 28124, code: 'NODE-WEB-24', severity: 'HIGH', category: 'Authentication', lineIdx: i,
      title: 'JWT Algorithm Confusion: HMAC and Public-Key Algorithms Accepted Together',
      why: 'When both HS* and RS*/ES* are allowed, an attacker signs a forged token with HS256 using the public key as the HMAC secret and it verifies; alg "none" tokens carry no signature at all.',
      fix: 'Pin exactly the algorithm family that matches the key: { algorithms: ["RS256"] } for public keys, ["HS256"] for shared secrets.' }));

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `nodeweb${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [NODE WEB] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
