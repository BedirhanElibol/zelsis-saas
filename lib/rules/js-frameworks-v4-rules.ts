/**
 * JS/TS framework security (Express, NestJS, Next.js, Remix, SvelteKit, Nuxt, Hono, Fastify, Electron,
 * browser DOM) (JSF-xx, Rule IDs 28901-28999).
 *
 * Sources: CWE (79, 601, 918, 640, 943, 1321, 1333, 942, 352, 798, 345, 89, 732, 295), OWASP Cheat Sheets
 * (DOM XSS, Unvalidated Redirects, CSRF, Nodejs Security), framework security docs (Next.js data security,
 * SvelteKit csrf, Auth.js callbacks, Nuxt runtimeConfig, Vite env, Electron security checklist, Express behind
 * proxies, Apollo Server CSRF prevention). Detection logic and wording are our own.
 *
 * Classes already handled elsewhere are not repeated: Express-sourced injection sinks (node-web-vuln-rules),
 * exec/fs/fetch/raw SQL with any request input (security-rules), NEXT_PUBLIC_ secrets (SEC-36), multi-line
 * hardcoded session secrets (GAP-08), postMessage without origin check (SAAS3-04), localStorage JWTs.
 * Injection rules need a taint signal: request / URL input on the line or in a variable assigned from it shortly before.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

// ─── Sources ────────────────────────────────────────────────────────────────────────────────

/** Request input in the Web Request API frameworks (Next.js App Router, Remix, SvelteKit, Astro) and Nuxt/h3. */
const MODERN_SRC = String.raw`(?:\bsearchParams\.get\s*\(|\b(?:formData|form|fd)\.get\s*\(|\(\s*await\s+req(?:uest)?\.(?:json|formData|text)\(\s*\)\s*\)|\b(?:getQuery|readBody|getRouterParams?|readFormData)\s*\(\s*event\b|\bcontext\.(?:query|params)\b)`;
/** Express / Fastify / Next pages API / Hono / Koa request input. */
const CLASSIC_SRC = String.raw`(?:\breq(?:uest)?\.(?:query|params|body)\b|\bc\.req\.(?:query|param|queries)\s*\(|\bctx\.(?:query|params)\b|\bctx\.request\.(?:query|body)\b)`;
const SERVER_SRC = `(?:${MODERN_SRC}|${CLASSIC_SRC})`;
/** Parsed JSON bodies (values can be objects, not only strings). */
const MODERN_WHOLE = String.raw`^\s*(?:await\s+)?(?:req(?:uest)?\.json\(\s*\)|readBody\(\s*event\s*\)|JSON\.parse\(\s*(?:${SERVER_SRC})[^)]*\))\s*(?:as\s+[\w<>[\]{}:;,\s|]+)?;?\s*$`;
const CLASSIC_WHOLE = String.raw`^\s*(?:await\s+)?req(?:uest)?\.(?:body|query)\s*(?:as\s+[\w<>[\]{}:;,\s|]+)?;?\s*$`;
/** RHS that yields an object whose .get() returns request input. */
const SERVER_GETTER = String.raw`^\s*(?:await\s+)?(?:req(?:uest)?\.formData\(\s*\)|(?:new\s+URL\([^)]*\)|req(?:uest)?\.nextUrl|url)\.searchParams|new\s+URLSearchParams\(\s*(?:await\s+)?req(?:uest)?\.text\(\s*\)\s*\))\s*;?\s*$`;

/** Browser-side URL / navigation input. */
const DOM_SRC = String.raw`(?:\b(?:window\.|document\.)?location\.(?:hash|search|href)\b|\bdocument\.(?:URL|documentURI|referrer)\b|\bwindow\.name\b|\bsearchParams\.get\s*\(|\bnew\s+URLSearchParams\s*\(\s*(?:window\.)?location\.(?:search|hash)[^)]*\)\.get\s*\(|(?:\bthis\.)?\$route\.(?:query|params)\b|\broute\.(?:query|params)\b|\buseRoute\(\s*\)\.(?:query|params)\b|\brouter\.query\b|\$?page\.url\.searchParams\b|\bAstro\.(?:url\.searchParams|params)\b|\b(?:route|activatedRoute)\.snapshot\.(?:queryParams|params|queryParamMap|paramMap|fragment)\b)`;
/** URL query input only (no location.href / referrer: self-navigation and "go back" are not redirects). */
const NAV_SRC = String.raw`(?:\bsearchParams\.get\s*\(|\bnew\s+URLSearchParams\s*\(\s*(?:window\.)?location\.(?:search|hash)[^)]*\)\.get\s*\(|\b(?:window\.)?location\.hash\.(?:slice|substring|substr)\s*\(|(?:\bthis\.)?\$?route\.query\b|\buseRoute\(\s*\)\.query\b|\brouter\.query\b)`;
const DOM_GETTER = String.raw`^\s*new\s+URLSearchParams\s*\(\s*(?:window\.)?location\.(?:search|hash)[^)]*\)\s*;?\s*$|^\s*useSearchParams\(\s*\)\s*;?\s*$`;

/** Assignments whose right-hand side is sanitized / converted do not propagate taint. */
const SANITIZER = /\b(?:basename|parseInt|parseFloat|Number|Boolean|safeParse|escape\w*|sanitize\w*|validate\w*|encodeURIComponent|isValid\w*|DOMPurify|xss|slugify|ObjectId|isUUID|uuidValidate|String)\s*\(|\bz\.|\.(?:includes|has)\(|\.parse\(|^\s*[A-Z][A-Z0-9_]*\s*\[/;
const TAINT_WINDOW = 40;

const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*)/.test(l);
const esc = (s: string) => s.replace(/\$/g, '\\$');

interface Decl { line: number; tainted: boolean; whole: 'modern' | 'classic' | ''; getter: boolean; rhs: string }

/** Per-file variable taint tracking for one source family. */
class Taint {
  private decls = new Map<string, Decl[]>();
  constructor(lines: string[], private src: string, wholeModern: string | null, wholeClassic: string | null, getter: string, private globals: string[] = []) {
    const srcRe = new RegExp(src);
    const wm = wholeModern ? new RegExp(wholeModern) : null;
    const wc = wholeClassic ? new RegExp(wholeClassic) : null;
    const gr = new RegExp(getter);
    const getterNames: string[] = [];
    lines.forEach((l, i) => {
      if (isComment(l)) return;
      for (const m of l.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]|\s]+)?=\s*([^;]*)/g)) {
        const rhs = m[2];
        const whole = wm && wm.test(rhs) ? 'modern' : wc && wc.test(rhs) ? 'classic' : '';
        const viaGetter = getterNames.length > 0 && new RegExp(String.raw`\b(?:${getterNames.map(esc).join('|')})\.get\s*\(`).test(rhs);
        const getter = gr.test(rhs);
        this.add(m[1], { line: i, tainted: (srcRe.test(rhs) || viaGetter || whole !== '') && !SANITIZER.test(rhs), whole, getter, rhs });
        if (getter) getterNames.push(m[1]);
      }
      const d = l.match(/\b(?:const|let|var)\s*\{([^=]*)\}\s*(?::\s*[^=]+)?=\s*([^;]*)/);
      if (d) {
        const rhs = d[2];
        const tainted = ((wm && wm.test(rhs)) || (wc && wc.test(rhs)) || new RegExp(String.raw`^\s*(?:await\s+)?(?:${src})\s*;?\s*$`).test(rhs)) && !SANITIZER.test(rhs);
        for (const part of d[1].split(',')) {
          const name = (part.split(':').pop() || '').split('=')[0].replace(/[{}\s.]/g, '');
          this.add(name, { line: i, tainted: !!tainted, whole: '', getter: false, rhs });
        }
      }
    });
  }
  private add(name: string, d: Decl) {
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return;
    const list = this.decls.get(name) || [];
    list.push(d);
    this.decls.set(name, list);
  }
  private latest(idx: number, pick: (d: Decl) => boolean): string[] {
    const out: string[] = [];
    for (const [name, list] of this.decls) {
      let last: Decl | undefined;
      for (const d of list) if (d.line < idx) last = d;
      if (last && idx - last.line <= TAINT_WINDOW && pick(last)) out.push(esc(name));
    }
    return out;
  }
  /** Regex source matching tainted input at line idx. `filter` restricts which declarations count. */
  at(idx: number, filter?: (d: Decl) => boolean): string {
    const vars = [...this.latest(idx, (d) => d.tainted && (!filter || filter(d))), ...this.globals.map(esc)];
    const getters = this.latest(idx, (d) => d.getter);
    const parts = [this.src];
    if (vars.length) parts.push(String.raw`\b(?:${vars.join('|')})\b(?![\w$])`);
    if (getters.length) parts.push(String.raw`\b(?:${getters.join('|')})\.get\s*\(`);
    return `(?:${parts.join('|')})`;
  }
  wholeVars(idx: number, kind: 'modern' | 'classic'): string[] {
    return this.latest(idx, (d) => d.whole === kind);
  }
}

// ─── Function body extraction (regex scanner, no AST) ─────────────────────────────────────────

function matchClose(src: string, open: number, o: string, c: string): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const q = ch;
      for (i++; i < src.length && src[i] !== q; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (ch === o) depth++;
    else if (ch === c && --depth === 0) return i;
  }
  return -1;
}

interface FnBlock { name: string; exported: boolean; params: string; body: string; bodyOffset: number }

function functionBlocks(src: string): FnBlock[] {
  const out: FnBlock[] = [];
  const decl = /(export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(\w*)\s*(?:<[^>(]*>)?\s*\(|(export\s+)?(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?\(/g;
  for (const m of src.matchAll(decl)) {
    const parenOpen = m.index! + m[0].length - 1;
    const close = matchClose(src, parenOpen, '(', ')');
    if (close === -1) continue;
    let bodyOpen = -1;
    let angle = 0;
    for (let i = close + 1; i < src.length; i++) {
      const ch = src[i];
      if (ch === '=' && src[i + 1] === '>') { i++; continue; }
      if (ch === '<') angle++;
      else if (ch === '>') angle--;
      else if (ch === '{' && angle <= 0) { bodyOpen = i; break; }
      else if ((ch === ';' || ch === '\n') && angle <= 0 && i > close + 120) break;
      else if (ch === ';' && angle <= 0) break;
    }
    if (bodyOpen === -1) continue;
    const bodyClose = matchClose(src, bodyOpen, '{', '}');
    if (bodyClose === -1) continue;
    out.push({ name: m[2] || m[4] || 'default', exported: Boolean(m[1] || m[3]), params: src.slice(parenOpen + 1, close), body: src.slice(bodyOpen + 1, bodyClose), bodyOffset: bodyOpen + 1 });
  }
  return out;
}

const lineAt = (content: string, offset: number) => content.slice(0, Math.max(0, offset)).split('\n').length - 1;

// Caller verification inside a function body (providers, local helpers, signed tokens)
const CALLER_CHECK = new RegExp([
  String.raw`\.auth\.(?:getUser|getClaims|getSession)\s*\(|\bauth\(\s*\)|currentUser\s*\(|getAuth\s*\(|getServerSession\s*\(|\bgetSession\s*\(|getToken\s*\(`,
  String.raw`verifyIdToken\s*\(|validateRequest\s*\(|validateSession\s*\(|getKindeServerSession|auth\.api\.getSession|jwtVerify\s*\(|jwt\.verify\s*\(|verifyToken\s*\(|session\.user\b|\bctx\.user\b|\bcookies\(\)`,
  String.raw`\b(?:get|require|ensure|assert|verify|check|validate|protect|authorize|authenticate|with|current)\w*(?:User|Auth|Session|Admin|Owner|Member|Role|Permission|Access|Viewer|Claims|Account)\w*\s*\(`
].join('|'), 'i');

export function evaluateJsFrameworksV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const isJs = /\.[cm]?[jt]sx?$/i.test(path) && !/\.d\.ts$/i.test(path);
  const isTemplate = /\.(?:vue|svelte|astro)$/i.test(path);
  if ((!isJs && !isTemplate) || /(?:^|\/)node_modules\//.test(path) || /\.min\.js$/i.test(path)) return { findings, logs };
  const c = cleanContent;
  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  const reCache = new Map<string, RegExp>();
  const rx = (s: string, flags = '') => { const k = flags + '|' + s; let r = reCache.get(k); if (!r) { r = new RegExp(s, flags); reCache.set(k, r); } return r; };
  const scan = (pre: RegExp, build: (i: number) => RegExp | null, onHit: (i: number) => void, skip?: (i: number) => boolean) => {
    lines.forEach((l, i) => {
      if (isComment(l) || !pre.test(l)) return;
      const re = build(i);
      if (re && re.test(l) && !(skip && skip(i))) onHit(i);
    });
  };
  const nearby = (idx: number, before: number, after: number, re: RegExp) =>
    lines.slice(Math.max(0, idx - before), Math.min(lines.length, idx + after + 1)).some((l) => re.test(l));
  const windowText = (idx: number, size: number) => lines.slice(idx, Math.min(lines.length, idx + size)).join(' ');
  const strArg = (t: string) => String.raw`(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)` + t;

  const hasServerSrc = rx(SERVER_SRC).test(c) || /\breq(?:uest)?\.(?:json|formData|text)\(|\breadBody\(/.test(c);
  const hasDomSrc = rx(DOM_SRC).test(c);

  // NestJS decorated parameters (@Query('x') x, @Body() dto) are request input for the whole method
  const nestParams = [...c.matchAll(/@(?:Query|Param|Body|Headers)\(\s*(?:['"][^'"]*['"])?\s*\)\s*(\w+)/g)].map((m) => m[1]);
  const server = hasServerSrc || nestParams.length ? new Taint(lines, SERVER_SRC, MODERN_WHOLE, CLASSIC_WHOLE, SERVER_GETTER, nestParams) : null;
  const modern = rx(MODERN_SRC).test(c) ? new Taint(lines, MODERN_SRC, MODERN_WHOLE, null, SERVER_GETTER) : null;
  const dom = hasDomSrc ? new Taint(lines, DOM_SRC, null, null, DOM_GETTER) : null;
  const nav = hasDomSrc ? new Taint(lines, NAV_SRC, null, null, DOM_GETTER) : null;

  // ─── Server-side request-input sinks ─────────────────────────────────────────────────────

  if (server) {
    // JSF-01: open redirect through framework redirect helpers that the generic rule does not parse
    const legacyRedirect = new RegExp(String.raw`(?:res\.redirect|redirect|NextResponse\.redirect)\s*\(\s*(?:req\.(?:query|body|params)|searchParams\.get|\b(?:next|url|redirectUrl|redirectTo|target|targetUrl|returnTo|returnUrl|callbackUrl)\b(?:\s+as\s+\w+)?\s*(?:[),]|\|\||\?\?)|\x60\$\{\s*\b(?:next|url|redirectUrl|redirectTo|target|targetUrl|returnTo|returnUrl|callbackUrl)\b\s*\}|new\s+URL\(\s*\b(?:next|url|redirectUrl|redirectTo|target|targetUrl|returnTo|returnUrl|callbackUrl)\b)`, 'i');
    const redirectGuard = /startsWith\(\s*['"]\/['"]|isSafe\w*\(|isRelative\w*\(|isValidRedirect|safeRedirect|sanitizeRedirect|allowed|ALLOWED|\.origin\s*[!=]==|[!=]==\s*\w+\.origin\b|\.(?:includes|has)\(/;
    scan(/redirect\s*\(|sendRedirect\s*\(|destination\s*:|navigateTo\s*\(/, (i) => {
      const t = server.at(i);
      const u = String.raw`(?:new\s+URL\(\s*)?(?:String\(\s*)?` + t;
      const gssp = /getServerSideProps|getStaticProps/.test(c) ? String.raw`|\bdestination\s*:\s*(?:String\(\s*)?` + t : '';
      return rx(String.raw`\bredirect\s*\(\s*(?:30[0-8]|status\w*)\s*,\s*` + u +
        String.raw`|\bsendRedirect\s*\(\s*event\s*,\s*` + u +
        String.raw`|\b(?:NextResponse|Response)\.redirect\s*\(\s*` + u +
        String.raw`|\bnavigateTo\s*\(\s*` + t + String.raw`[^)]*\bexternal\s*:\s*true` + gssp);
    }, (i) => add({ ruleId: 28901, code: 'JSF-01', severity: 'MEDIUM', category: 'Open Redirect', lineIdx: i,
      title: 'Open Redirect: Framework Redirect Helper Sends Users to a Request-Supplied URL (CWE-601)',
      why: 'The redirect target comes from the query string / form; new URL(value, base) keeps an absolute or //host value, so a link on your domain bounces users to a phishing site and can leak OAuth codes.',
      fix: 'Accept only relative paths (value.startsWith("/") && !value.startsWith("//")) or hosts from an allow-list, and fall back to a fixed page.' }),
    (i) => legacyRedirect.test(lines[i]) || nearby(i, 8, 0, redirectGuard));

    // JSF-02: Next.js middleware rewrite to a request-supplied URL (reverse-proxy SSRF)
    scan(/\.rewrite\s*\(/, (i) => {
      const t = server.at(i);
      return rx(String.raw`\bNextResponse\.rewrite\s*\(\s*(?:new\s+URL\(\s*)?(?:` + t + String.raw`|\x60(?:https?:\/\/)?\$\{\s*` + t + ')');
    }, (i) => add({ ruleId: 28902, code: 'JSF-02', severity: 'HIGH', category: 'Network & SSRF', lineIdx: i,
      title: 'SSRF: NextResponse.rewrite Proxies to a Request-Supplied URL (CWE-918)',
      why: 'A rewrite to an absolute URL makes the Next.js server fetch that URL and return the response, so a caller reaches internal services or cloud metadata (169.254.169.254) through your deployment.',
      fix: 'Rewrite only to fixed origins: map the request value to an allow-listed host, or build the URL from a constant origin and a validated path.' }),
    (i) => nearby(i, 8, 0, /allowed|ALLOWED|\.hostname\s*[!=]==|\.host\s*[!=]==|isAllowed\w*\(|\.(?:includes|has)\(/));

    // JSF-04: reflected XSS in a Web Response served as text/html
    scan(/new\s+Response\s*\(/, (i) => {
      if (!/text\/html/i.test(windowText(i, 5))) return null;
      return rx(String.raw`new\s+Response\s*\(\s*(?:\x60[^\x60]*<[^\x60]*\$\{\s*|['"][^'"]*<[^'"]*['"]\s*\+\s*)` + server.at(i));
    }, (i) => add({ ruleId: 28904, code: 'JSF-04', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'Reflected XSS: Request Input Interpolated Into a text/html Response (CWE-79)',
      why: 'The route handler returns HTML that embeds a query / form value unescaped, so ?title=<script>... runs in the victim\'s browser on your origin with their cookies.',
      fix: 'Return JSON, render through React / an auto-escaping template, or HTML-escape the value (escape-html) before interpolating it.' }),
    (i) => /escape|sanitize|encode|DOMPurify/i.test(lines[i]));

    // JSF-05: parsed JSON body (Request API / h3 / JSON.parse) used as the database filter
    const queryMethods = String.raw`\.(?:find|findOne|findMany|findFirst|findAll|findAndCountAll|count|countDocuments|deleteMany|deleteOne|updateMany|updateOne|findOneAndUpdate|findOneAndDelete|exists)\s*\(\s*`;
    scan(rx(queryMethods), (i) => {
      const whole = [...server.wholeVars(i, 'modern'), ...nestWhole(c)];
      const obj = String.raw`(?:\(\s*await\s+req(?:uest)?\.json\(\s*\)\s*\)|await\s+readBody\(\s*event\s*\)` + (whole.length ? String.raw`|\b(?:${whole.join('|')})\b` : '') + ')';
      return rx(queryMethods + String.raw`(?:\{\s*where\s*:\s*|\{\s*\.\.\.\s*)?` + obj + String.raw`\s*[,)}]`);
    }, (i) => add({ ruleId: 28905, code: 'JSF-05', severity: 'HIGH', category: 'Injection', lineIdx: i,
      title: 'NoSQL / ORM Operator Injection: Parsed Request Body Used as the Query Filter (CWE-943)',
      why: 'The JSON body is passed as the filter itself, so {"email":{"$ne":null}} (MongoDB) or {"token":{"not":""}} (Prisma) turns a lookup into an operator query that bypasses checks or returns other users\' rows.',
      fix: 'Validate the body with a schema (zod) and build the filter from scalar fields: { email: String(body.email) }.' }));

    // JSF-06: secret-token lookup with an object-capable request value (operator injection -> auth bypass)
    const tokenField = String.raw`(\w*(?:[tT]oken|TOKEN|[oO]tp|OTP|(?:[vV]erification|[vV]erify|[rR]eset|[iI]nvite|[aA]uth|[cC]onfirm(?:ation)?|[mM]agic|[lL]ogin|[aA]ctivation|[rR]ecovery|[mM]fa)_?[cC]ode|[aA]pi_?[kK]ey|[sS]ecret))`;
    const objectCapable = (i: number) => {
      const whole = [...server.wholeVars(i, 'modern'), ...server.wholeVars(i, 'classic')];
      return String.raw`(?:\breq(?:uest)?\.(?:body|query)\.\w+|\(\s*await\s+req(?:uest)?\.json\(\s*\)\s*\)\.\w+` + (whole.length ? String.raw`|\b(?:${whole.join('|')})\.\w+` : '') + ')';
    };
    const tokenGuard = /\bString\(|typeof\s+\w+(?:\.\w+)*\s*!==?\s*['"]string['"]|\.parse\(|safeParse|validate|Joi\.|yup\.|sanitize|mongo-?sanitize|sanitizeFilter/;
    scan(/\.(?:findOne|findFirst|find|findOneBy|findBy|count|countDocuments|exists|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne)\s*\(/, (i) => {
      const text = windowText(i, 4);
      const call = text.match(/\.(?:findOne|findFirst|find|findOneBy|findBy|count|countDocuments|exists|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne)\s*\(\s*\{([^)]*)/);
      if (!call) return null;
      return rx(String.raw`(?:^|[{,])\s*` + tokenField + String.raw`\s*:\s*` + objectCapable(i) + String.raw`\s*[,}]`).test(call[1]) ? /./ : null;
    }, (i) => add({ ruleId: 28906, code: 'JSF-06', severity: 'HIGH', category: 'Authentication', lineIdx: i,
      title: 'Token Lookup Accepts an Object From the Request (Operator Injection Auth Bypass, CWE-943)',
      why: 'A JSON body (or Express qs query) can send {"token":{"$ne":null}} (MongoDB) or {"token":{"not":""}} (Prisma); the lookup then matches the first user with any token, bypassing password reset / verification.',
      fix: 'Coerce and validate the value before querying: const token = z.string().min(20).parse(body.token) (or String(body.token)), then look it up.' }),
    (i) => nearby(i, 12, 0, tokenGuard) || /express-mongo-sanitize|sanitizeFilter\s*['"]?\s*,\s*true/.test(c));

    // JSF-07: regular expression built from Request-API / h3 input (Express sources: NODE-WEB-05)
    if (modern) {
      scan(/new\s+RegExp\s*\(/, (i) => rx(String.raw`new\s+RegExp\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?` + modern.at(i)),
        (i) => add({ ruleId: 28907, code: 'JSF-07', severity: 'MEDIUM', category: 'Denial of Service', lineIdx: i,
          title: 'Regular Expression Built From Request Input (ReDoS / Regex Injection, CWE-1333)',
          why: 'A caller-supplied pattern such as (a+)+$ blocks the server\'s event loop with catastrophic backtracking, and ".*" turns a search into a match-everything query.',
          fix: 'Escape the input (escape-string-regexp) before building the pattern, or use a plain substring / full-text search.' }),
        (i) => /escape/i.test(lines[i]));
    }

    // JSF-28: TypeORM query builder ORDER BY / GROUP BY / SELECT from request input (not escaped)
    if (/['"]typeorm['"]|createQueryBuilder\s*\(/.test(c)) {
      scan(/\.(?:orderBy|addOrderBy|groupBy|addGroupBy|select|addSelect)\s*\(/, (i) =>
        rx(String.raw`\.(?:orderBy|addOrderBy|groupBy|addGroupBy|select|addSelect)\s*\(\s*(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)?` + server.at(i)),
      (i) => add({ ruleId: 28928, code: 'JSF-28', severity: 'HIGH', category: 'Injection', lineIdx: i,
        title: 'SQL Injection: Request Input in a TypeORM orderBy / groupBy / select Expression (CWE-89)',
        why: 'TypeORM copies the sort / select expression into the SQL verbatim, so ?sort=(CASE WHEN (SELECT ...) THEN id ELSE name END) runs attacker SQL (blind data extraction).',
        fix: 'Map the request value through an allow-list of column names: const SORTS = { name: "user.name", created: "user.createdAt" }; qb.orderBy(SORTS[sort] ?? "user.id").' }),
      (i) => nearby(i, 6, 0, /allowed|ALLOWED|\.includes\(|\.has\(|SORT|sortable|whitelist|allowList/));
    }
  }

  // JSF-03: password reset / verification link built from the Host header (Request API / h3)
  {
    const hostSrc = /\.get\(\s*['"](?:host|x-forwarded-host)['"]\s*\)|getRequestHost\s*\(\s*event|getHeader\s*\(\s*event\s*,\s*['"](?:host|x-forwarded-host)['"]/;
    const linkWord = /reset|verify|verification|confirm|invite|magic|activat|token=/i;
    const supabaseValidated = /emailRedirectTo|redirectTo\s*:/;
    const hostVars = new Map<string, number>();
    const hit = (i: number, name?: string) => add({ ruleId: 28903, code: 'JSF-03', severity: 'HIGH', category: 'Authentication', lineIdx: i,
      title: 'Password Reset / Verification Link Built From the Host Header (CWE-640)',
      why: `${name ? name + ' comes from' : 'The link uses'} the client-controlled Host / X-Forwarded-Host header; an attacker requests a reset for the victim with Host: evil.com and the emailed link sends the token to them.`,
      fix: 'Build emailed links from a configured base URL (process.env.APP_URL / NEXT_PUBLIC_SITE_URL), never from request headers.' });
    lines.forEach((l, i) => {
      if (isComment(l) || !hostSrc.test(l)) return;
      const decl = l.match(/\b(?:const|let|var)\s+(\w+)\s*=/);
      if (linkWord.test(l) && /\x60|\+/.test(l) && !supabaseValidated.test(l)) hit(i);
      else if (decl) hostVars.set(decl[1], i);
    });
    for (const [name, at] of hostVars) {
      const use = new RegExp(String.raw`\$\{\s*` + name + String.raw`\s*\}|\b` + name + String.raw`\s*\+`);
      for (let i = at + 1; i < Math.min(lines.length, at + 25); i++) {
        if (!isComment(lines[i]) && use.test(lines[i]) && linkWord.test(lines[i]) && !supabaseValidated.test(lines[i])) { hit(i, name); break; }
      }
    }
  }

  // ─── Browser DOM sinks ────────────────────────────────────────────────────────────────────

  if (dom && nav) {
    // JSF-08: DOM XSS - URL-derived value written to an HTML sink
    const usesJquery = /\$\(|jQuery\(/.test(c);
    const pre = String.raw`(?:\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*)?(?:decodeURI(?:Component)?\(\s*|unescape\(\s*)?`;
    scan(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc|createContextualFragment|\.(?:html|append|prepend|after|before|replaceWith)\s*\(|[sS]cript\w*\.src\s*=/, (i) => {
      const t = dom.at(i);
      return rx(String.raw`\.(?:innerHTML|outerHTML)\s*\+?=\s*` + pre + t +
        String.raw`|\.insertAdjacentHTML\s*\(\s*[^,]+,\s*` + pre + t +
        String.raw`|\bdocument\.write(?:ln)?\s*\(\s*` + pre + t +
        String.raw`|\.srcdoc\s*=\s*` + pre + t + String.raw`|createContextualFragment\s*\(\s*` + pre + t +
        String.raw`|\b\w*[sS]cript\w*\.src\s*=\s*` + pre + t +
        (usesJquery ? String.raw`|\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*` + pre + t : ''));
    }, (i) => add({ ruleId: 28908, code: 'JSF-08', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'DOM XSS: URL Fragment / Query Written to an HTML Sink (CWE-79)',
      why: 'location.hash / the query string is attacker-controlled through a crafted link; writing it with innerHTML / document.write / insertAdjacentHTML runs <img src=x onerror=...> on your origin.',
      fix: 'Assign with textContent (or createTextNode), or sanitize with DOMPurify.sanitize() before inserting HTML.' }),
    (i) => /DOMPurify|sanitize|escape/i.test(lines[i]));

    // JSF-09: DOM open redirect / javascript: URL execution
    scan(/location|window\.open\s*\(/, (i) => {
      const t = nav.at(i);
      return rx(String.raw`\b(?:window\.|document\.)?location(?:\.href)?\s*=(?![=>])\s*(?:decodeURIComponent\(\s*)?` + t +
        String.raw`|\blocation\.(?:assign|replace)\s*\(\s*(?:decodeURIComponent\(\s*)?` + t +
        String.raw`|\bwindow\.open\s*\(\s*(?:decodeURIComponent\(\s*)?` + t);
    }, (i) => add({ ruleId: 28909, code: 'JSF-09', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'DOM Open Redirect / javascript: URL: Navigation Target Taken From the Query String (CWE-601, CWE-79)',
      why: 'A link with ?next=https://evil.example sends users off-site, and ?next=javascript:fetch(...) executes script on your origin when assigned to location.',
      fix: 'Navigate only to relative paths (next.startsWith("/") && !next.startsWith("//")) or parse with new URL() and require your own origin.' }),
    (i) => nearby(i, 8, 0, /startsWith\(\s*['"]\/['"]|isSafe\w*\(|isRelative\w*\(|isValidRedirect|safeRedirect|allowed|ALLOWED|\.origin\s*[!=]==|[!=]==\s*\w+\.origin\b|\.protocol\b/));

    // JSF-10: framework raw-HTML bindings fed from the URL
    scan(/v-html|\{@html|set:html|dangerouslySetInnerHTML|bypassSecurityTrust/, (i) => {
      const t = dom.at(i);
      return rx(String.raw`\bv-html\s*=\s*"\s*` + t +
        String.raw`|\{@html\s+` + t +
        String.raw`|\bset:html\s*=\s*\{\s*` + t +
        String.raw`|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:decodeURIComponent\(\s*)?` + t +
        String.raw`|bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(\s*` + t);
    }, (i) => add({ ruleId: 28910, code: 'JSF-10', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'XSS: URL Parameter Rendered Through a Raw-HTML Binding (v-html / {@html} / set:html / __html)',
      why: 'Raw-HTML bindings skip the framework\'s escaping; a crafted link (?msg=<img src=x onerror=...>) runs script in every visitor\'s session.',
      fix: 'Render the value as text ({{ value }}, {value}) or pass it through DOMPurify.sanitize() before binding it as HTML.' }),
    (i) => /DOMPurify|sanitize/i.test(lines[i]));
  }

  // ─── Configuration and framework options ─────────────────────────────────────────────────

  if (isJs) {
    // JSF-11: proxy headers trusted from any hop (client-spoofable IP / protocol)
    scan(/trust proxy|trustProxy|\.proxy\s*=/, () => /\.set\(\s*['"]trust proxy['"]\s*,\s*true\s*\)|\.enable\(\s*['"]trust proxy['"]\s*\)|\btrustProxy\s*:\s*true\b|\bapp\.proxy\s*=\s*true\b/,
      (i) => add({ ruleId: 28911, code: 'JSF-11', severity: 'MEDIUM', category: 'Security Misconfiguration', lineIdx: i,
        title: 'Every Proxy Hop Trusted: Client Can Spoof req.ip via X-Forwarded-For (CWE-348)',
        why: 'With trust proxy = true the left-most X-Forwarded-For entry becomes req.ip, and most proxies append to the client-sent header, so attackers rotate fake IPs to bypass rate limits, IP allow-lists and audit logs.',
        fix: 'Trust only the real hop count or proxy addresses: app.set("trust proxy", 1) / trustProxy: 1 (or the load balancer CIDR); for Koa set app.maxIpsCount.' }),
      (i) => /\.proxy\s*=/.test(lines[i]) && /maxIpsCount/.test(c));

    // JSF-12: the whole server environment inlined into client bundles / responses
    scan(/process\.env\b(?!\s*\.\s*\w)(?!\s*\[)/, () => rx(String.raw`['"]process\.env['"]\s*:\s*(?:JSON\.stringify\(\s*)?process\.env\s*\)?\s*[,}]` +
      String.raw`|\b(?:json|Response\.json|NextResponse\.json|res\.json|res\.send|c\.json|reply\.send)\s*\(\s*(?:\{[^}]*?(?:\b\w+\s*:\s*|\.\.\.\s*))?process\.env\s*[,)}]` +
      String.raw`|\bprops\s*:\s*\{[^}]*?(?:\b\w+\s*:\s*|\.\.\.\s*)process\.env\s*[,}]` +
      String.raw`|\$\{\s*JSON\.stringify\(\s*process\.env\s*\)\s*\}`),
    (i) => add({ ruleId: 28912, code: 'JSF-12', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
      title: 'Entire process.env Exposed to the Browser (Bundle define / Props / Response)',
      why: 'The full server environment (database URLs, API secrets, CI tokens) is serialized into client JavaScript or a response anyone can read in DevTools.',
      fix: 'Expose only named public values (define: { __APP_VERSION__: JSON.stringify(v) }, or ENV: { STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY }).' }),
    (i) => /\benv\s*:\s*process\.env\s*[,}]/.test(lines[i]) && !/props|json|define|send/i.test(lines[i]));

    // JSF-13: secret-named variable behind a client-exposed env prefix (NEXT_PUBLIC_ is SEC-36, LLM keys 28201)
    {
      const re = /\b((?:VITE|PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|REACT_APP|GATSBY|VUE_APP|STORYBOOK)_[A-Z0-9_]*?(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|SERVICE_KEY|DATABASE_URL|DB_PASSWORD|DB_PASS|ADMIN_KEY|PASSWORD)[A-Z0-9_]*)\b/;
      const llm = /OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|GOOGLE_GENERATIVE_AI|MISTRAL|COHERE|REPLICATE|DEEPSEEK|PERPLEXITY|TOGETHER|FIREWORKS|XAI|OPENROUTER|HUGGINGFACE|HF_/;
      scan(re, () => /./, (i) => {
        const l = lines[i];
        const m = l.match(re)!;
        if (llm.test(m[1]) || /PUBLISHABLE|PUBLIC_KEY|SITE_KEY|CLIENT_ID/.test(m[1].replace(/^(?:NUXT_|EXPO_)?PUBLIC_/, ''))) return;
        if (m[1].startsWith('PUBLIC_') && !/import\.meta\.env|\$env\/(?:static|dynamic)\/public/.test(l + c.slice(0, 2000))) return;
        if (!/import\.meta\.env|process\.env|\$env\/|import\s*\{/.test(l)) return;
        add({ ruleId: 28913, code: 'JSF-13', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
          title: `Server Secret Exposed Through a Client-Bundled Env Variable (${m[1]})`,
          why: `Variables prefixed ${m[1].split('_')[0]}_ are inlined into the browser bundle at build time, so this secret ships to every visitor.`,
          fix: 'Rename it without the public prefix, read it only in server code (API route / server action / +page.server.ts), and rotate the exposed value.' });
      });
    }

    // JSF-14: Nuxt runtimeConfig.public holding a secret
    if (/runtimeConfig/.test(c) && /defineNuxtConfig|nuxt\.config/.test(c + path)) {
      for (const m of c.matchAll(/\bpublic\s*:\s*\{/g)) {
        const before = c.slice(Math.max(0, m.index! - 600), m.index!);
        if (!/runtimeConfig/.test(before)) continue;
        const open = m.index! + m[0].length - 1;
        const close = matchClose(c, open, '{', '}');
        if (close === -1) continue;
        const block = c.slice(open + 1, close);
        for (const k of block.matchAll(/(?:^|[\s,{])(['"]?)(\w*(?:[sS]ecret|[pP]rivateKey|[sS]ervice(?:Role|Key)|[pP]assword|SECRET|PASSWORD)\w*)\1\s*:/g)) {
          if (/publishable|siteKey/i.test(k[2])) continue;
          add({ ruleId: 28914, code: 'JSF-14', severity: 'HIGH', category: 'Secrets Management', lineIdx: lineAt(c, open + 1 + k.index! + k[0].indexOf(k[2])),
            title: `Secret Placed in Nuxt runtimeConfig.public (${k[2]})`,
            why: 'Everything under runtimeConfig.public is serialized into the page payload (window.__NUXT__) and readable by any visitor.',
            fix: 'Move the key to the top level of runtimeConfig (server-only, read with useRuntimeConfig() in server/ routes) and rotate the exposed value.' });
        }
      }
    }

    // JSF-15: SvelteKit CSRF origin check disabled
    if (/svelte\.config\.[cm]?[jt]s$/.test(path) || /\bkit\s*:/.test(c)) {
      scan(/checkOrigin|trustedOrigins/, () => /\bcheckOrigin\s*:\s*false\b|\btrustedOrigins\s*:\s*\[[^\]]*['"]\*['"]/,
        (i) => add({ ruleId: 28915, code: 'JSF-15', severity: 'MEDIUM', category: 'CSRF', lineIdx: i,
          title: 'SvelteKit CSRF Origin Check Disabled',
          why: 'SvelteKit rejects cross-site form POSTs by checking Origin; turning it off lets any website submit your form actions with the victim\'s cookies.',
          fix: 'Remove checkOrigin: false; list specific partner origins in csrf.trustedOrigins if another site must post to you.' }));
    }

    // JSF-16: Auth.js / NextAuth redirect callback returns the requested URL unchecked
    if (/next-auth|@auth\/|NextAuth|callbacks\s*:/.test(c)) {
      scan(/\bredirect\b/, (i) => /\bredirect\s*(?::\s*)?(?:async\s*)?(?:function\s*)?\(\s*\{[^}]*\burl\b[^}]*\}[^)]*\)\s*(?::\s*[\w<>]+\s*)?(?:=>\s*\(?\s*url\s*\)?\s*[,}\n]|=>\s*\{?\s*return\s+url\s*;?\s*\}|\{\s*return\s+url\s*;?\s*\})/.test(windowText(i, 4) + '\n') ? /./ : null,
        (i) => add({ ruleId: 28916, code: 'JSF-16', severity: 'MEDIUM', category: 'Open Redirect', lineIdx: i,
          title: 'Auth.js redirect Callback Returns Any URL (Open Redirect After Sign-In)',
          why: 'The default callback only allows your own origin; returning url as-is lets /api/auth/signin?callbackUrl=https://evil.example send freshly signed-in users to a phishing page.',
          fix: 'Keep the same-origin check: if (url.startsWith("/")) return `${baseUrl}${url}`; if (new URL(url).origin === baseUrl) return url; return baseUrl.' }));
    }

    // JSF-17: JWT verification that ignores expiry
    if (/jsonwebtoken|jwt\.verify|passport-jwt|ExtractJwt/.test(c) && !/refresh/i.test(c)) {
      scan(/ignoreExpiration/, () => /\bignoreExpiration\s*:\s*true\b/,
        (i) => add({ ruleId: 28917, code: 'JSF-17', severity: 'MEDIUM', category: 'Authentication', lineIdx: i,
          title: 'JWT Verified With ignoreExpiration: true (Tokens Never Expire)',
          why: 'Expired tokens keep working forever, so a token leaked in logs, a stolen laptop or a revoked session remains a valid login.',
          fix: 'Remove ignoreExpiration (expiry is checked by default) and issue short-lived access tokens with a refresh flow.' }));
    }

    // JSF-18: template engine HTML auto-escaping disabled globally
    if (/handlebars|\bhbs\b|nunjucks|swig|\beta\b|express-handlebars/i.test(c) && /express|app\.(?:set|engine)\(|res\.render|reply\.view|koa|fastify|\.html['"]|\.njk['"]|\.hbs['"]/i.test(c)) {
      scan(/noEscape|autoescape|autoEscape/, () => /\bnoEscape\s*:\s*true\b|\bautoescape\s*:\s*false\b|\bautoEscape\s*:\s*false\b/,
        (i) => add({ ruleId: 28918, code: 'JSF-18', severity: 'MEDIUM', category: 'Cross-Site Scripting', lineIdx: i,
          title: 'Template Engine HTML Auto-Escaping Disabled (Stored / Reflected XSS)',
          why: 'Every {{ value }} is emitted as raw HTML, so any user-controlled field rendered in a view (name, comment, query) executes script.',
          fix: 'Keep auto-escaping on and mark the few trusted HTML fragments explicitly ({{{ trusted }}} / | safe) after sanitizing them.' }));
    }

    // JSF-21: Next.js draft / preview mode enabled without a secret check
    if (/(?:^|\/)(?:app\/.*\/route|pages\/api\/.*)\.[cm]?[jt]s$/.test(path) && !/secret|token|process\.env|validatePreviewUrl|defineEnableDraftMode|redirectToPreviewURL|isValid\w*\(|verify\w*\(|auth\(\s*\)|getServerSession|currentUser/i.test(c)) {
      scan(/draftMode|setPreviewData|setDraftMode/, () => /draftMode\(\s*\)\s*\)?\s*\.enable\s*\(|\.setPreviewData\s*\(|\.setDraftMode\s*\(\s*\{\s*enable\s*:\s*true/,
        (i) => add({ ruleId: 28921, code: 'JSF-21', severity: 'MEDIUM', category: 'Broken Access Control', lineIdx: i,
          title: 'Draft / Preview Mode Enabled Without Checking a Secret',
          why: 'Anyone who opens this route gets the draft-mode cookie, which renders unpublished CMS content and bypasses the static cache on every request.',
          fix: 'Compare a secret query parameter with process.env.DRAFT_SECRET (or use your CMS helper such as defineEnableDraftMode) before enabling draft mode.' }));
    }

    // JSF-22: server state serialized into an inline <script> with JSON.stringify (</script> breakout)
    scan(/JSON\.stringify\(/, (i) => {
      const l = lines[i];
      if (/ld\+json/.test(l) || nearby(i, 3, 0, /application\/ld\+json/)) return null;
      if (/\.replace\(\s*\/[<\\]|\\u003c|serialize\(|devalue|htmlEscape|escapeJson|jsesc|safeJson/i.test(l)) return null;
      if (/<script[^\x60]*\$\{\s*JSON\.stringify\(/.test(l)) return /./;
      if (/__html\s*:\s*(?:\x60[^\x60]*\$\{\s*)?JSON\.stringify\(/.test(l) && nearby(i, 3, 0, /<script\b|<Script\b/)) return /./;
      return null;
    }, (i) => add({ ruleId: 28922, code: 'JSF-22', severity: 'MEDIUM', category: 'Cross-Site Scripting', lineIdx: i,
      title: 'Server State Embedded in an Inline <script> With Plain JSON.stringify',
      why: 'JSON.stringify does not escape "</script>", so a user-controlled string in the state (name, comment, query) closes the script tag and injects HTML / script into the page.',
      fix: 'Escape "<" when inlining: JSON.stringify(state).replace(/</g, "\\\\u003c"), or use serialize-javascript / devalue.' }));

    // JSF-23: CORS reflecting any origin with credentials (NestJS enableCors and multi-line option objects)
    scan(/enableCors\s*\(|\bcors\s*[:(]|\borigin\s*:\s*true\b/, (i) => {
      if (!/\borigin\s*:\s*true\b/.test(windowText(i, 6))) return null;
      const text = windowText(i, 8);
      const call = text.match(/(?:enableCors\s*\(|\bcors\s*\(|\bcors\s*:)\s*\{([^}]*)\}/);
      if (!call || !/\borigin\s*:\s*true\b/.test(call[1]) || !/\bcredentials\s*:\s*true\b/.test(call[1])) return null;
      return /enableCors\s*\(|\bcors\s*[:(]/.test(lines[i]) ? /./ : null;
    }, (i) => add({ ruleId: 28923, code: 'JSF-23', severity: 'HIGH', category: 'CORS', lineIdx: i,
      title: 'CORS Reflects Any Origin With Credentials (origin: true + credentials: true, CWE-942)',
      why: 'origin: true echoes whatever Origin the browser sends; with credentials allowed, any website can call your API with the user\'s cookies and read the responses.',
      fix: 'Pass an explicit allow-list: enableCors({ origin: ["https://app.example.com"], credentials: true }).' }),
    (i) => /(?:origin:\s*(?:true|['"]\*['"])|Access-Control-Allow-Origin[^;]+(?:\*|true))\s*[^;}]*(?:credentials:\s*true)/i.test(lines[i]) && /cors\(/.test(c));

    // JSF-24: origin allow-list that an attacker domain can satisfy
    {
      const creds = /credentials\s*:\s*true|Access-Control-Allow-Credentials/i.test(c);
      const corsFile = /cors|Access-Control-Allow-Origin|enableCors/i.test(c);
      scan(/origin/i, (i) => {
        const l = lines[i];
        const regexLit = corsFile && /\borigin\s*:\s*\[?[^\]\n]*?\/((?:\\.|[^/\\\n])+)\/[gimsuy]*\s*[,\]}]/.exec(l);
        if (regexLit && /\\\.|\.(?:com|io|net|org|dev|app)/.test(regexLit[1]) && !/\$\)?$/.test(regexLit[1])) return /./;
        const strCheck = /\b(?:origin|requestOrigin|event\.origin|e\.origin|evt\.origin|msg\.origin|message\.origin)\??\.(includes|endsWith|startsWith|indexOf)\(\s*['"]([^'"]+)['"]\s*\)/.exec(l);
        if (!strCheck || !(corsFile || /\.origin/.test(strCheck[0]))) return null;
        const [, method, value] = strCheck;
        if (!/[a-z0-9-]+\.[a-z]{2,}/i.test(value)) return null;
        if (method === 'endsWith' && /^[.]/.test(value)) return null;
        if (method === 'startsWith' && /^https?:\/\/[^/]+\/$|^https?:\/\/[^/]+\/./.test(value)) return null;
        if (method === 'startsWith' && !/^https?:\/\//.test(value)) return null;
        return /./;
      }, (i) => add({ ruleId: 28924, code: 'JSF-24', severity: creds ? 'HIGH' : 'MEDIUM', category: 'CORS', lineIdx: i,
        title: 'Origin Allow-List Bypassable (Unanchored Regex / includes / endsWith / startsWith)',
        why: 'The check accepts attacker-registrable origins such as https://example.com.evil.net (includes / startsWith / unanchored regex) or https://evilexample.com (endsWith without a dot), so their pages pass the CORS / postMessage origin test.',
        fix: 'Compare the full origin exactly against a Set of allowed origins, or anchor the regex (/^https:\\/\\/([a-z0-9-]+\\.)?example\\.com$/).' }));
    }

    // JSF-25: hardcoded secrets in inline framework auth / session configuration (multi-line forms: GAP-08)
    {
      const fastifyPlugin = /['"](?:@fastify\/(?:jwt|cookie|secure-session|session)|fastify-(?:jwt|cookie|secure-session|session))['"]/.test(c);
      const honoJwt = /['"]hono\/jwt['"]/.test(c);
      const jose = /\b(?:SignJWT|jwtVerify)\b/.test(c);
      const betterAuth = /['"](?:better-auth|lucia)['"]/.test(c);
      const authJs = /['"](?:next-auth|@auth\/[\w-]+)['"]/.test(c);
      const lit = String.raw`['"][^'"\s]{6,}['"]`;
      scan(/secret|keys|password|TextEncoder/, (i) => {
        const l = lines[i];
        if (/process\.env|import\.meta\.env|\$env\//.test(l)) return null;
        const checks = [
          fastifyPlugin && rx(String.raw`\bregister\s*\([^,]+,\s*\{[^}]*\b(?:secret|key)\s*:\s*` + lit).test(l),
          honoJwt && rx(String.raw`\bjwt\s*\(\s*\{[^}]*\bsecret\s*:\s*` + lit).test(l),
          rx(String.raw`\bapp\.keys\s*=\s*\[\s*` + lit).test(l),
          jose && rx(String.raw`new\s+TextEncoder\(\s*\)\.encode\(\s*` + lit + String.raw`\s*\)`).test(l),
          rx(String.raw`\b(?:session|expressSession|cookieSession)\s*\(\s*\{[^}]*\b(?:secret|keys)\s*:\s*\[?\s*` + lit).test(l),
          rx(String.raw`getIronSession\s*(?:<[^>]*>)?\([^)]*\bpassword\s*:\s*` + lit).test(l),
          betterAuth && rx(String.raw`^\s*secret\s*:\s*` + lit + String.raw`\s*,?\s*$`).test(l),
          authJs && rx(String.raw`(?:^|[{,]\s*)secret\s*:\s*` + lit).test(l)
        ];
        return checks.some(Boolean) ? /./ : null;
      }, (i) => add({ ruleId: 28925, code: 'JSF-25', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
        title: 'Hardcoded Session / JWT Signing Secret in Framework Auth Configuration (CWE-798)',
        why: 'Anyone with the source (or a leaked bundle / fork) can sign their own session cookies or JWTs and log in as any user, including admins.',
        fix: 'Load the secret from the environment (process.env.SESSION_SECRET), fail startup when it is missing, and rotate the committed value.' }));
    }

    // JSF-26: JWT decoded without signature verification in server-side auth code
    if (/(?:^|\/)(?:middleware|proxy|hooks\.server|server|auth)\.[cm]?[jt]s$|(?:^|\/)(?:app\/.*\/route|pages\/api\/.*|server\/.*|src\/server\/.*|api\/.*|.*\.server)\.[cm]?[jt]s$|\+(?:page\.)?server\.[jt]s$/.test(path) &&
      !/jwtVerify|jwt\.verify|verifyToken|verifyJwt|verifyIdToken|\.verify\s*\(|getServerSession|\bauth\(\s*\)|getToken\s*\(|createRemoteJWKSet|clerk|\.auth\.getUser/i.test(c)) {
      scan(/decodeJwt|jwtDecode|jwt_decode/, () => /\b(?:decodeJwt|jwtDecode|jwt_decode)\s*(?:<[^>]*>)?\s*\(/,
        (i) => add({ ruleId: 28926, code: 'JSF-26', severity: 'HIGH', category: 'Authentication', lineIdx: i,
          title: 'Server Trusts JWT Claims Decoded Without Verifying the Signature (CWE-345)',
          why: 'decodeJwt / jwt-decode only base64-decode the payload; anyone can craft a token with role: "admin" or another user\'s sub and it is accepted here.',
          fix: 'Verify before trusting claims: const { payload } = await jwtVerify(token, secretOrJWKS, { algorithms: ["HS256"] }).' }));
    }

    // JSF-27: Apollo Server CSRF prevention disabled
    if (/ApolloServer/.test(c)) {
      scan(/csrfPrevention/, () => /\bcsrfPrevention\s*:\s*false\b/,
        (i) => add({ ruleId: 28927, code: 'JSF-27', severity: 'MEDIUM', category: 'CSRF', lineIdx: i,
          title: 'Apollo Server CSRF Prevention Disabled',
          why: 'Without the preflight requirement, a cross-site form or <img> can send GET queries / simple POST mutations with the user\'s cookies.',
          fix: 'Remove csrfPrevention: false (enabled by default in Apollo Server 4); have non-browser clients send the apollo-require-preflight header.' }));
    }

    // JSF-29 / JSF-30: Electron renderer hardening switched off
    if (/BrowserWindow|webPreferences|BrowserView|webviewTag/.test(c)) {
      scan(/webSecurity|allowRunningInsecureContent/, () => /\bwebSecurity\s*:\s*false\b|\ballowRunningInsecureContent\s*:\s*true\b/,
        (i) => add({ ruleId: 28929, code: 'JSF-29', severity: 'HIGH', category: 'Security Misconfiguration', lineIdx: i,
          title: 'Electron Window Disables Web Security (Same-Origin Policy / Mixed Content)',
          why: 'webSecurity: false turns off the same-origin policy, so any loaded page or injected script reads local files and other origins\' data; insecure content allows MITM script injection.',
          fix: 'Remove webSecurity: false / allowRunningInsecureContent; serve local content through a custom protocol handler instead.' }));
      const ctxOff = /\bcontextIsolation\s*:\s*false\b/.test(c);
      scan(/nodeIntegration|contextIsolation/, () => /\bnodeIntegration(?:InSubFrames|InWorker)?\s*:\s*true\b|\bcontextIsolation\s*:\s*false\b/,
        (i) => add({ ruleId: 28930, code: 'JSF-30', severity: /nodeIntegration/.test(lines[i]) || ctxOff && /nodeIntegration\w*\s*:\s*true/.test(c) ? 'HIGH' : 'MEDIUM', category: 'Security Misconfiguration', lineIdx: i,
          title: 'Electron Renderer Runs With Node Integration / Without Context Isolation',
          why: 'With Node in the renderer (or no context isolation), any XSS or malicious page loaded in the window gets require("child_process") and runs commands on the user\'s machine.',
          fix: 'Use nodeIntegration: false, contextIsolation: true, sandbox: true and expose a minimal API through contextBridge in a preload script.' }));
    }

    // JSF-31: TLS certificate verification disabled process-wide
    scan(/NODE_TLS_REJECT_UNAUTHORIZED/, () => /process\.env(?:\.NODE_TLS_REJECT_UNAUTHORIZED|\[\s*['"]NODE_TLS_REJECT_UNAUTHORIZED['"]\s*\])\s*=\s*['"]?0['"]?/,
      (i) => add({ ruleId: 28931, code: 'JSF-31', severity: 'HIGH', category: 'Cryptography', lineIdx: i,
        title: 'NODE_TLS_REJECT_UNAUTHORIZED = 0 Disables Certificate Checks for the Whole Process',
        why: 'Every HTTPS call the process makes (payment APIs, databases, OAuth) accepts any certificate, so anyone on the network path can intercept credentials and responses.',
        fix: 'Remove the assignment; trust a private CA with NODE_EXTRA_CA_CERTS or a per-client ca option instead.' }));

    // JSF-32: world-writable file permissions
    scan(/chmod|mode\s*:|umask/, () => /\b(?:chmod|chmodSync|fchmod|fchmodSync|lchmod|lchmodSync)\s*\([^,]+,\s*(?:0o?[0-7]?[0-7][0-7][2367]\b|['"][0-7]?[0-7][0-7][2367]['"]|(?:511|438|0o777|0o666)\b)|\b(?:mkdir|mkdirSync|writeFile|writeFileSync|open|openSync|createWriteStream)\s*\([^)]*\bmode\s*:\s*(?:0o[0-7]?[0-7][0-7][2367]\b|511\b|438\b)|\bprocess\.umask\(\s*0\s*\)/,
      (i) => add({ ruleId: 28932, code: 'JSF-32', severity: 'MEDIUM', category: 'Security Misconfiguration', lineIdx: i,
        title: 'File or Directory Made World-Writable (CWE-732)',
        why: 'Any local user or compromised service on the host can replace these files (uploads, config, scripts) and get their content served or executed by the app.',
        fix: 'Use the narrowest mode that works: 0o755 / 0o750 for directories, 0o644 / 0o600 for files.' }));

    // JSF-35: password check on an unawaited Promise (always truthy)
    {
      const cmp = String.raw`\b(?:bcrypt|bcryptjs|argon2|bcryptjs)\.(?:compare|verify)\s*\(`;
      scan(/\.(?:compare|verify)\s*\(/, (i) => {
        const l = lines[i];
        if (rx(String.raw`(?:\bif\s*\(\s*!?\s*|&&\s*!?\s*|\|\|\s*!?\s*|\breturn\s+!\s*)` + cmp).test(l) && !rx(String.raw`await\s+` + cmp).test(l)) return /./;
        const v = l.match(rx(String.raw`\b(?:const|let|var)\s+(\w+)\s*=\s*` + cmp));
        if (v && !/\bawait\b|\.then\(|=>|function/.test(l)) {
          const use = new RegExp(String.raw`\bif\s*\(\s*!?\s*` + v[1] + String.raw`\s*[)&|]`);
          for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
            if (new RegExp(String.raw`await\s+` + v[1] + String.raw`\b`).test(lines[j])) return null;
            if (use.test(lines[j])) return /./;
          }
        }
        return null;
      }, (i) => add({ ruleId: 28935, code: 'JSF-35', severity: 'HIGH', category: 'Authentication', lineIdx: i,
        title: 'Password Check Uses an Unawaited Promise (Any Password Accepted)',
        why: 'bcrypt.compare / argon2.verify return a Promise, which is always truthy; without await the check passes for every password (and "!promise" never rejects).',
        fix: 'Await the result: if (!(await bcrypt.compare(password, user.passwordHash))) return unauthorized().' }));
    }

    // JSF-36: auth token stored in a script-readable cookie
    {
      const authName = String.raw`(?:access[_-]?token|accessToken|auth[_-]?token|authToken|token|jwt|session|sessionid|session[_-]?token|sessionToken|refresh[_-]?token|refreshToken|id[_-]?token|idToken)`;
      scan(/document\.cookie|Cookies\.set\s*\(/, () => rx(String.raw`\bdocument\.cookie\s*=\s*[\x60'"]` + authName + '=' + String.raw`|\bCookies\.set\(\s*['"\x60]` + authName + String.raw`['"\x60]`, 'i'),
        (i) => add({ ruleId: 28936, code: 'JSF-36', severity: 'MEDIUM', category: 'Session Management', lineIdx: i,
          title: 'Auth Token Stored in a JavaScript-Readable Cookie',
          why: 'Cookies written from JavaScript can never be HttpOnly, so any XSS or malicious dependency reads the session token and replays it from elsewhere.',
          fix: 'Have the server set the token with Set-Cookie: HttpOnly; Secure; SameSite=Lax (res.cookie / cookies().set with httpOnly: true).' }),
        (i) => /csrf|xsrf/i.test(lines[i]));
    }

    // JSF-37: Socket.IO identity taken from client-sent handshake data
    if (/socket\.handshake/.test(c) && !/jwt\.verify|jwtVerify|verifyToken|verifyIdToken|getSession|getServerSession|\.auth\.getUser|decode\w*\(|verify\w*\(|validate\w*\(/i.test(c)) {
      scan(/socket\.handshake/, () => /(?:\b(?:userId|user_id|uid|userID|user)\b|socket\.(?:data\.)?(?:userId|user|uid))\s*=\s*socket\.handshake\.(?:query|auth)(?:\.|\[\s*['"])(?:userId|user_id|uid|userID|user|id)\b|\{[^}]*\b(?:userId|user_id|uid|userID)\b[^}]*\}\s*=\s*socket\.handshake\.(?:query|auth)\b/,
        (i) => add({ ruleId: 28937, code: 'JSF-37', severity: 'HIGH', category: 'Authentication', lineIdx: i,
          title: 'Socket.IO User Identity Taken From Client Handshake Data (Impersonation)',
          why: 'socket.handshake.query / auth is whatever the client sends, so io("/", { auth: { userId: "victim" } }) joins the victim\'s rooms and receives or sends their events.',
          fix: 'Send a token in handshake.auth, verify it in io.use() (jwt.verify / session lookup) and set socket.data.userId from the verified claims.' }));
    }

    // JSF-38: user identity deserialized from an unsigned cookie
    scan(/JSON\.parse\s*\(/, () => /JSON\.parse\(\s*(?:decodeURIComponent\(\s*|atob\(\s*|Buffer\.from\(\s*)?(?:(?:event\.|request\.|req\.)?cookies(?:\(\s*\))?(?:\.get\(\s*['"](?:user|currentUser|session|auth|account|profile|userInfo|user_info)['"]\s*\)(?:\?\.value|\.value)?|\.(?:user|currentUser|session|auth|account|profile|userInfo)\b|\[\s*['"](?:user|currentUser|session|auth|account|profile|userInfo|user_info)['"]\s*\]))/,
      (i) => add({ ruleId: 28938, code: 'JSF-38', severity: 'HIGH', category: 'Authentication', lineIdx: i,
        title: 'User Identity Parsed From a Plain (Unsigned) Cookie',
        why: 'The cookie is client-editable; changing it to {"id":"<victim>","role":"admin"} logs the attacker in as anyone with any role.',
        fix: 'Store only an opaque session id (or a signed / encrypted token via iron-session, jose, signed cookies) and load the user from the server-side session.' }),
      (i) => /signedCookies|unseal|verify|decrypt/i.test(lines[i]));

    // JSF-34: CSP that allows inline scripts without a nonce / hash
    scan(/script-src|default-src/, () => /\bscript-src\b[^;"\x60]*'unsafe-inline'/,
      (i) => add({ ruleId: 28934, code: 'JSF-34', severity: 'LOW', category: 'Security Misconfiguration', lineIdx: i,
        title: "Content-Security-Policy script-src Allows 'unsafe-inline' Without a Nonce or Hash",
        why: "With 'unsafe-inline' and no nonce / hash, injected <script> tags and inline event handlers still run, so the policy gives no protection against XSS.",
        fix: "Use a per-request nonce ('nonce-<random>' 'strict-dynamic') or script hashes, and drop 'unsafe-inline' from script-src." }),
      (i) => /'nonce-|nonce-\$\{|'sha(?:256|384|512)-|'strict-dynamic'/.test(lines[i]) || /\/[^/\n]*script-src[^/\n]*\/[gimsuy]*/.test(lines[i]) && /\.(?:match|test|replace)\(/.test(lines[i]));

    // JSF-33: sandboxed iframe that can remove its own sandbox
    scan(/sandbox/, () => /\bsandbox\s*=\s*["'{\x60][^"'}\x60]*(?:allow-scripts[^"'}\x60]*allow-same-origin|allow-same-origin[^"'}\x60]*allow-scripts)/,
      (i) => add({ ruleId: 28933, code: 'JSF-33', severity: 'MEDIUM', category: 'Cross-Site Scripting', lineIdx: i,
        title: 'Sandboxed srcdoc iframe Allows Scripts and Same-Origin (Sandbox Escape)',
        why: 'srcdoc content is same-origin with your page; with allow-scripts + allow-same-origin its script can reach parent.document, read cookies / storage and remove its own sandbox.',
        fix: 'Drop allow-same-origin for untrusted HTML (keep allow-scripts only), or serve the content from a separate sandbox origin.' }),
      (i) => !nearby(i, 2, 2, /\bsrc[dD]oc\s*=/));
  }

  // JSF-19: prototype pollution in a hand-rolled deep merge / path setter
  if (isJs && /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+in\b|Object\.(?:keys|entries)\(|\.split\(\s*['"]\.['"]\s*\)/.test(c)) {
    const guard = /__proto__|['"]constructor['"]|['"]prototype['"]|isPrototypePolluted|isUnsafeKey|isSafeKey|isPrototypeKey|DANGEROUS|FORBIDDEN|BLOCKED|unsafeKeys|forbiddenKeys|Object\.create\(\s*null/;
    for (const fn of functionBlocks(c)) {
      if (fn.name === 'default' || guard.test(fn.body)) continue;
      const loop = fn.body.match(/\bfor\s*\(\s*(?:const|let|var)\s+(\w+)\s+in\s+\w+|Object\.keys\(\s*\w+\s*\)\.forEach\(\s*(?:\(\s*)?(\w+)|for\s*\(\s*(?:const|let|var)\s+(\w+)\s+of\s+Object\.keys\(|for\s*\(\s*(?:const|let|var)\s+\[\s*(\w+)\s*,/);
      const recursive = new RegExp(String.raw`\b${fn.name}\s*\(`).test(fn.body);
      let at = -1;
      if (loop && recursive) {
        const key = loop[1] || loop[2] || loop[3] || loop[4];
        // Pollution needs in-place recursion: fn(target[key], ...) mutating the destination object itself.
        // `result[key] = fn(a[key], b[key])` builds new objects and only changes result's own prototype.
        for (const call of fn.body.matchAll(new RegExp(String.raw`\b${fn.name}\s*\(\s*(\w+)\[\s*${key}\s*\]`, 'g'))) {
          const lineStart = fn.body.lastIndexOf('\n', call.index!) + 1;
          if (/[^=!<>]=(?!=)/.test(fn.body.slice(lineStart, call.index!).replace(/=>/g, ''))) continue;
          const write = new RegExp(String.raw`\b${call[1]}\[\s*${key}\s*\]\s*=(?![=>])`).exec(fn.body);
          if (write) { at = fn.bodyOffset + write.index; break; }
        }
      } else if (/\.split\(\s*['"]\.['"]\s*\)/.test(fn.body)) {
        const walk = /(\w+)\[(\w+)\]\s*=\s*\1\[\2\]\s*(?:\|\||\?\?)\s*\{\s*\}|if\s*\(\s*!\s*(\w+)\[(\w+)\]\s*\)\s*\{?\s*\3\[\4\]\s*=\s*\{\s*\}|(\w+)\[(\w+)\]\s*\?\?=\s*\{\s*\}/.exec(fn.body);
        if (walk) at = fn.bodyOffset + walk.index;
      }
      if (at >= 0) add({ ruleId: 28919, code: 'JSF-19', severity: 'MEDIUM', category: 'Prototype Pollution', lineIdx: lineAt(c, at),
        title: `Prototype Pollution in Hand-Rolled Deep Merge / Path Setter (${fn.name}, CWE-1321)`,
        why: 'Keys are copied without rejecting "__proto__" / "constructor"; JSON.parse keeps "__proto__" as an own key, so merging {"__proto__":{"isAdmin":true}} sets isAdmin on every object in the process. hasOwnProperty checks do not stop this.',
        fix: 'Skip the keys "__proto__", "constructor" and "prototype" (if (key === "__proto__" || key === "constructor") continue;) or build into Object.create(null) / a Map.' });
    }
  }

  // JSF-20: Server Action mutates records without verifying the caller (Supabase/RLS clients: NEXT-SB-01)
  if (isJs && /['"]use server['"]/.test(c) && !/actionClient|authAction|protectedAction|createSafeActionClient|createServerAction|withAuth\w*\(|authedProcedure|adminAction|userAction/i.test(c)) {
    const topDirective = /^\s*['"]use server['"]/m.test(c.split('\n').filter((l) => l.trim()).slice(0, 3).join('\n'));
    const blocks = functionBlocks(c);
    const guardedHelpers = new Set(blocks.filter((b) => !b.exported && CALLER_CHECK.test(b.body)).map((b) => b.name));
    const mutation = /\b\w+\.\w+\.(?:update|updateMany|delete|deleteMany|upsert)\s*\(\s*\{|\bdb\.(?:update|delete)\s*\(|\.(?:findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany)\s*\(|\.(?:updateTable|deleteFrom)\s*\(|\.destroy\s*\(/;
    for (const b of blocks) {
      const inline = /^\s*['"]use server['"]/.test(b.body);
      if (!(topDirective ? b.exported : inline) || !b.params.trim()) continue;
      const m = mutation.exec(b.body);
      if (!m || /supabase/i.test(b.body.slice(Math.max(0, m.index - 120), m.index + 40))) continue;
      if (CALLER_CHECK.test(b.body) || [...guardedHelpers].some((h) => new RegExp(String.raw`\b${h}\s*\(`).test(b.body))) continue;
      const call = b.body.slice(m.index, m.index + 400);
      if (/increment\s*:|\$inc\b|[tT]oken\b|unsubscribe/.test(call)) continue;
      add({ ruleId: 28920, code: 'JSF-20', severity: 'HIGH', category: 'Broken Access Control', lineIdx: lineAt(c, b.bodyOffset + m.index),
        title: `Server Action Updates / Deletes Records Without Verifying the Caller (${b.name})`,
        why: `Server Action \`${b.name}\` is a public POST endpoint (its ID ships in the client bundle). It changes records by the id it is given but never checks who is calling, so anyone can modify or delete other users' data.`,
        fix: 'At the top of the action, load the session (auth() / getServerSession / currentUser) and scope the write to the caller: where: { id, userId: session.user.id }.' });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `jsf${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [JS FRAMEWORKS] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}

/** NestJS `@Body() body: any` / `@Query() query: any` (whole, untyped request objects). */
function nestWhole(c: string): string[] {
  return [...c.matchAll(/@(?:Body|Query)\(\s*\)\s*(\w+)\s*(?::\s*(?:any|Record<[^>]*>|object|unknown))?\s*[,)]/g)]
    .filter((m) => /:\s*(?:any|Record<|object|unknown)/.test(m[0]) || !/:/.test(m[0])).map((m) => m[1]);
}
