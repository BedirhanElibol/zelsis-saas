/**
 * React / Next.js / UI logic bugs that AI-written apps ship with (BUG-20.., Rule IDs 29620-29659).
 *
 * Same contract as logic-bug-rules.ts: reliability findings (type VIBECARE) for code that compiles but breaks a
 * feature: hydration mismatches, render loops, stale closures, inputs that cannot be typed in, App Router APIs used
 * the Pages Router way, layouts that overflow on phones. Every rule matches a specific mistake on the reported line
 * (React docs, Next.js docs and error messages); none fires on the mere absence of a call.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const lineAt = (content: string, offset: number) => content.slice(0, Math.max(0, offset)).split('\n').length - 1;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const OPEN = '([{';
const CLOSE = ')]}';

/* ------------------------------------------------------------------------------------------------------------ */
/* Masking: string and template literal contents become spaces (same length, newlines kept), so bracket matching  */
/* and identifier searches never trip over quotes, apostrophes in JSX text or braces inside strings.               */
/* ------------------------------------------------------------------------------------------------------------ */
const QUOTE_KW = /(?:^|[^\w$])(?:return|case|typeof|in|of|else|yield|await|export|import|from|default|throw|void|new)$/;

function skipTemplate(c: string, i: number): number {
  // c[i] === '`'; returns the index of the closing backtick (or c.length)
  for (let j = i + 1; j < c.length; j++) {
    const ch = c[j];
    if (ch === '\\') { j++; continue; }
    if (ch === '`') return j;
    if (ch === '$' && c[j + 1] === '{') {
      let depth = 0;
      for (j = j + 1; j < c.length; j++) {
        const e = c[j];
        if (e === '`') { j = skipTemplate(c, j); continue; }
        if (e === '"' || e === "'") { for (j++; j < c.length && c[j] !== e && c[j] !== '\n'; j++) if (c[j] === '\\') j++; continue; }
        if (e === '{') depth++;
        else if (e === '}' && --depth === 0) break;
      }
    }
  }
  return c.length;
}

function maskCode(c: string): string {
  const out = c.split('');
  const blank = (a: number, b: number) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  for (let i = 0; i < c.length; i++) {
    const ch = c[i];
    if (ch !== '"' && ch !== "'" && ch !== '`') continue;
    if (ch === '`') { const e = skipTemplate(c, i); blank(i + 1, e); i = e; continue; }
    let j = i - 1;
    while (j >= 0 && /\s/.test(c[j])) j--;
    const p = j >= 0 ? c[j] : '';
    if (p && !/[=([{,:;!&|?+\-*/%<>~^}]/.test(p) && !QUOTE_KW.test(c.slice(Math.max(0, j - 9), j + 1))) continue; // JSX text: Don't
    let k = i + 1;
    for (; k < c.length && c[k] !== ch && c[k] !== '\n'; k++) if (c[k] === '\\') k++;
    if (k >= c.length || c[k] === '\n') continue; // not a string literal after all (JSX text)
    blank(i + 1, k);
    i = k;
  }
  return out.join('');
}

/** Index of the bracket closing the one at `open` in masked code, or -1. */
function matchFwd(m: string, open: number): number {
  let depth = 0;
  for (let i = open; i < m.length; i++) {
    const ch = m[i];
    if (OPEN.includes(ch)) depth++;
    else if (CLOSE.includes(ch) && --depth === 0) return i;
  }
  return -1;
}

/** Index of the bracket opening the one at `close` in masked code, or -1. */
function matchBack(m: string, close: number): number {
  let depth = 0;
  for (let i = close; i >= 0; i--) {
    const ch = m[i];
    if (CLOSE.includes(ch)) depth++;
    else if (OPEN.includes(ch) && --depth === 0) return i;
  }
  return -1;
}

/** Top-level comma-separated arguments of the call whose '(' is at `open`, with their absolute start offsets. */
function argsOf(m: string, open: number): { args: { text: string; at: number }[]; end: number } {
  const end = matchFwd(m, open);
  if (end === -1) return { args: [], end: -1 };
  const args: { text: string; at: number }[] = [];
  let depth = 0, start = open + 1;
  for (let i = open + 1; i < end; i++) {
    const ch = m[i];
    if (OPEN.includes(ch)) depth++;
    else if (CLOSE.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) { args.push({ text: m.slice(start, i), at: start }); start = i + 1; }
  }
  if (m.slice(start, end).trim()) args.push({ text: m.slice(start, end), at: start });
  return { args, end };
}

/** End (exclusive) of an arrow function's expression body starting at `s`. */
function exprEnd(m: string, s: number, limit: number): number {
  let depth = 0;
  for (let i = s; i < limit; i++) {
    const ch = m[i];
    if (OPEN.includes(ch)) depth++;
    else if (CLOSE.includes(ch)) { if (depth === 0) return i; depth--; }
    else if (depth === 0 && (ch === ',' || ch === ';')) return i;
    else if (depth === 0 && ch === '\n') {
      const before = m.slice(s, i).trimEnd();
      const after = m.slice(i + 1, i + 40).trimStart();
      if (/(?:=>|[?:&|+\-*/=(,<]|\b(?:return|await|new|typeof))$/.test(before) || /^(?:[.?:&|+\-*/=]|\)|>)/.test(after)) continue;
      return i;
    }
  }
  return limit;
}

interface FnRegion { head: number; start: number; end: number; kind: 'render' | 'deferred'; prefix: string }

/** Prefixes whose callback runs during render (array methods, lazy state / memo initializers). */
const RENDER_CALLBACK = /(?:\.(?:map|flatMap|filter|reduce|reduceRight|find|findIndex|findLast|some|every|sort|toSorted|forEach)|\b(?:useMemo|useState|useReducer|Array\.from))\s*\(\s*(?:[^(),]*,\s*)?$/;

/** Function bodies (arrow and `function`) inside [from, to) of masked code. */
function fnRegions(m: string, from: number, to: number): FnRegion[] {
  const out: FnRegion[] = [];
  for (let k = from; k < to - 1; k++) {
    if (m[k] === '=' && m[k + 1] === '>') {
      let j = k - 1;
      while (j >= from && /\s/.test(m[j])) j--;
      let head = j;
      if (m[j] === ')') head = matchBack(m, j);
      else if (/[\w$]/.test(m[j])) { while (head > from && /[\w$]/.test(m[head - 1])) head--; }
      else {
        // TS return type: (e: Event): void =>
        const win = m.slice(Math.max(from, k - 160), k);
        const rt = /\)\s*:\s*[^()=;{}]*$/.exec(win);
        if (rt) head = matchBack(m, Math.max(from, k - 160) + rt.index);
      }
      if (head < from) continue;
      const pre = m.slice(Math.max(0, head - 80), head).replace(/\basync\s*$/, '');
      let s = k + 2;
      while (s < to && /\s/.test(m[s])) s++;
      const e = m[s] === '{' ? matchFwd(m, s) + 1 : exprEnd(m, s, to);
      if (e <= 0) continue;
      out.push({ head, start: s, end: e, kind: RENDER_CALLBACK.test(pre) ? 'render' : 'deferred', prefix: pre });
      k++;
    } else if (m.startsWith('function', k) && !/[\w$]/.test(m[k - 1] || '') && !/[\w$]/.test(m[k + 8] || '')) {
      const p = m.indexOf('(', k);
      if (p === -1 || p > k + 80) continue;
      const pc = matchFwd(m, p);
      if (pc === -1) continue;
      const b = m.indexOf('{', pc);
      if (b === -1 || !/^\s*(?::[^{]*)?$/.test(m.slice(pc + 1, b))) continue;
      const e = matchFwd(m, b) + 1;
      if (e <= 0) continue;
      const pre = m.slice(Math.max(0, k - 80), k).replace(/\basync\s*$/, '');
      out.push({ head: k, start: b, end: e, kind: RENDER_CALLBACK.test(pre) ? 'render' : 'deferred', prefix: pre + m.slice(k, b) });
    }
  }
  return out;
}

/** Copy of masked code where nested functions inside [from, to) are blanked: deferred ones only, or all of them. */
function blankFns(m: string, regions: FnRegion[], all: boolean): string {
  const out = m.split('');
  let until = -1;
  for (const r of regions) {
    if (r.start < until) continue;
    if (!all && r.kind === 'render') continue;
    for (let k = r.start; k < r.end; k++) if (out[k] !== '\n') out[k] = ' ';
    until = r.end;
  }
  return out.join('');
}

interface Comp { name: string; open: number; close: number; hook: boolean; async: boolean; params: string; decl: number }

/** Function components (capitalized, JSX-returning) and custom hooks, with their body range in masked code. */
function findComponents(m: string): Comp[] {
  const comps: Comp[] = [];
  const seen = new Set<number>();
  const push = (name: string, decl: number, paramOpen: number, isAsync: boolean) => {
    const pc = matchFwd(m, paramOpen);
    if (pc === -1) return;
    const rest = m.slice(pc + 1, pc + 200);
    const arrow = /^\s*(?::\s*[^=;{]+?)?\s*=>\s*/.exec(rest);
    const fn = /^\s*(?::\s*[^=;{]+?)?\s*\{/.exec(rest);
    let open: number, close: number;
    if (arrow) {
      open = pc + 1 + arrow[0].length;
      if (m[open] === '{') close = matchFwd(m, open);
      else if (m[open] === '(') close = matchFwd(m, open);
      else return;
    } else if (fn && !/=>/.test(fn[0])) {
      open = pc + fn[0].length;
      close = matchFwd(m, open);
    } else return;
    if (close === -1 || seen.has(open)) return;
    const hook = /^use[A-Z]/.test(name);
    const body = m.slice(open, close);
    if (!hook && (/^[A-Z0-9_]+$/.test(name) || !/<[A-Za-z>]/.test(body))) return; // GET/POST handlers, non-JSX helpers
    seen.add(open);
    comps.push({ name, open, close, hook, async: isAsync, params: m.slice(paramOpen + 1, pc), decl: decl });
  };
  for (const x of m.matchAll(/\b(async\s+)?function\s+([A-Z]\w*|use[A-Z]\w*)\s*(?:<[^>()]*>)?\s*\(/g)) {
    push(x[2], x.index!, x.index! + x[0].length - 1, !!x[1]);
  }
  for (const x of m.matchAll(/\b(?:const|let|var)\s+([A-Z]\w*|use[A-Z]\w*)\s*(?::\s*[^=;]+?)?=\s*(?:(?:React\.)?(?:memo|forwardRef)\s*(?:<[^>()]*>)?\s*\(\s*)?(async\s+)?(?:function\s*\w*\s*)?(?:<[^>()]*>)?\s*\(/g)) {
    push(x[1], x.index!, x.index! + x[0].length - 1, !!x[2]);
  }
  return comps.sort((a, b) => a.open - b.open);
}

/** Bracket depth of `pos` relative to `open` (the component body brace is depth 1). */
function depthAt(m: string, open: number, pos: number): number {
  let d = 0;
  for (let i = open; i < pos; i++) {
    if (OPEN.includes(m[i])) d++;
    else if (CLOSE.includes(m[i])) d--;
  }
  return d;
}

/** A JSX opening tag starting at `lt`: end index of '>' and flat attribute text (expression contents blanked). */
function jsxTag(m: string, lt: number): { end: number; name: string; flat: string; selfClose: boolean } | null {
  const nm = /^<([A-Za-z][\w.]*)/.exec(m.slice(lt, lt + 60));
  if (!nm) return null;
  const prev = m[lt - 1] || '';
  if (/[\w$)\]]/.test(prev)) return null; // generic type argument or comparison
  let i = lt + nm[0].length;
  let flat = '';
  for (; i < m.length; i++) {
    const ch = m[i];
    if (ch === '{') {
      const e = matchFwd(m, i);
      if (e === -1) return null;
      flat += '{' + ' '.repeat(e - i - 1) + '}';
      i = e;
      continue;
    }
    if (ch === '>') return { end: i, name: nm[1], flat, selfClose: m[i - 1] === '/' };
    if (ch === '<' || ch === ';') return null;
    flat += ch;
  }
  return null;
}

const attrRe = (name: string) => new RegExp(`(?:^|\\s)${name}(?=\\s*=|\\s|/|$)`);
/** Value text of attribute `name` in the original source for a tag at [lt, end]. */
function attrSpan(c: string, m: string, lt: number, end: number, name: string): { text: string; s: number; e: number } | null {
  const seg = m.slice(lt, end);
  const a = new RegExp(`\\s${name}\\s*=\\s*`).exec(seg);
  if (!a) return null;
  const s = lt + a.index + a[0].length;
  const e = m[s] === '{' ? matchFwd(m, s) : m[s] === '"' || m[s] === "'" ? m.indexOf(m[s], s + 1) : -1;
  return e === -1 ? null : { text: c.slice(s + 1, e), s: s + 1, e };
}
const attrValue = (c: string, m: string, lt: number, end: number, name: string) => attrSpan(c, m, lt, end, name)?.text ?? null;

/** Body text of a handler defined in this file (`function name(...) {}` / `const name = (...) => ...`). */
function handlerBody(m: string, name: string): { at: number; s: number; e: number; body: string; params: string } | null {
  const re = new RegExp(`(?:\\bfunction\\s+${esc(name)}\\s*\\(|\\b(?:const|let|var)\\s+${esc(name)}\\s*(?::[^=]+)?=\\s*(?:useCallback\\s*\\(\\s*)?(?:async\\s*)?(?:function\\s*\\w*\\s*)?\\()`);
  const d = re.exec(m);
  if (!d) return null;
  const p = d.index + d[0].length - 1;
  const pc = matchFwd(m, p);
  if (pc === -1) return null;
  const rest = /^\s*(?::\s*[^=;{]+?)?\s*(?:=>\s*)?/.exec(m.slice(pc + 1))!;
  const s = pc + 1 + rest[0].length;
  const e = m[s] === '{' ? matchFwd(m, s) + 1 : exprEnd(m, s, m.length);
  if (e <= 0) return null;
  return { at: d.index, s, e, body: m.slice(s, e), params: m.slice(p + 1, pc) };
}

const NEXT_APP = /(?:^|\/)app\//;
const NEXT_PAGES = /(?:^|\/)pages\//;
const BROWSER_GLOBALS = ['window', 'document', 'localStorage', 'sessionStorage', 'navigator'];

export function evaluateLogicReactNextRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.[cm]?[jt]sx?$/i.test(path) || /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__)\/|\.(?:test|spec|stories)\.[jt]sx?$/i.test(path)) {
    return { findings, logs };
  }
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };
  const m = maskCode(c);
  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  const at = (off: number) => lineAt(c, off);

  const directive = /^\s*(['"])use (client|server)\1/.exec(c);
  const isClient = directive?.[2] === 'client';
  const isServerFile = directive?.[2] === 'server';
  // pages/ is the Next.js Pages Router only in a Next.js app; Vite / CRA SPAs also keep routes in src/pages and never render on a server
  const nextPages = NEXT_PAGES.test(path) && !(context && context.packageMajors.size > 0 && !context.packageMajors.has('next'));
  const inApp = NEXT_APP.test(path) && !NEXT_PAGES.test(path);
  const appEntry = inApp && /(?:^|\/)(?:page|layout|template|not-found|default|loading)\.[jt]sx?$/.test(path);
  // Code that is rendered on the server and then hydrated in the browser
  const hydrates = isClient || (nextPages && !/(?:^|\/)pages\/api\//.test(path) && /\.[jt]sx$/.test(path));
  const usesReact = /from\s+['"]react['"]|\buse(?:State|Effect)\s*\(|<[A-Za-z]/.test(m);

  const comps = usesReact ? findComponents(m) : [];
  const compOpens = new Set(comps.map((k) => k.open));
  const regionsAll = comps.length ? fnRegions(m, 0, m.length).filter((r) => !compOpens.has(r.start)) : [];
  const rs = blankFns(m, regionsAll, false); // render scope: handlers / effects / callbacks blanked
  const rsStrict = blankFns(m, regionsAll, true); // every nested function blanked
  const compAt = (pos: number) => comps.filter((k) => k.open < pos && pos < k.close).sort((a, b) => b.open - a.open)[0];
  const inRender = (pos: number) => rs[pos] === m[pos];

  // useState pairs: setter -> state variable
  const setterOf = new Map<string, string>();
  const stateOfSetter = new Map<string, string>();
  for (const x of m.matchAll(/\b(?:const|let)\s*\[\s*(\w+)\s*,\s*(set\w+)\s*\]\s*=\s*(?:React\.)?useState\b/g)) {
    setterOf.set(x[1], x[2]);
    stateOfSetter.set(x[2], x[1]);
  }

  /* ---------------------------------------------------------------------------------------------------------- */
  /* Hydration and render-phase rules                                                                            */
  /* ---------------------------------------------------------------------------------------------------------- */
  if (hydrates) {
    // Only route entries are provably server-rendered (a nested component may live in a closed modal, a tooltip or
    // behind client-fetched data), and only up to the first data hook or early-return gate
    const ssrEntry = (isClient && appEntry) || (nextPages && !/(?:^|\/)pages\/(?:api|_document)\b/.test(path));
    for (const k of comps.filter((x) => !x.hook)) {
      const scope = rs.slice(k.open, k.close);
      const earlyReturnBefore = (pos: number) => [...rsStrict.slice(k.open, pos).matchAll(/\breturn\b/g)].some((r) => {
        let s = k.open + r.index! + 6;
        while (/\s/.test(m[s])) s++;
        const e = m[s] === '(' ? matchFwd(m, s) : m.slice(s).search(/[;\n]/) + s;
        return e < pos; // a return statement that ends before the line: the line sits behind a gate
      });
      const dataGate = /(?<![\w.$])use(?!State|Ref|Memo|Callback|Effect|LayoutEffect|Id|Transition|DeferredValue|Reducer|Translations?|Router|Pathname|SearchParams|Params)[A-Z]\w*\s*\(/.test(scope);
      const pageComp = /export\s+default\s+(?:async\s+)?$/.test(m.slice(Math.max(0, k.decl - 30), k.decl)) || new RegExp(`export\\s+default\\s+${esc(k.name)}\\b`).test(m);
      const provablySsr = (pos: number) => ssrEntry && pageComp && !dataGate && !earlyReturnBefore(pos);
      const lastJsxReturn = scope.search(/\breturn\s*\(?\s*<[A-Za-z>]/);
      const usedLater = (name: string, from: number) => new RegExp(`\\b${esc(name)}\\b`).test(rs.slice(from, k.close));
      const declOnLine = (pos: number) => {
        const ls = c.lastIndexOf('\n', pos) + 1;
        const d = /^\s*(?:const|let|var)\s+(?:\[\s*)?(\w+)/.exec(c.slice(ls, pos));
        return d ? { name: d[1], lineEnd: c.indexOf('\n', pos) } : null;
      };

      // BUG-20: non-deterministic value rendered (server and browser render different output)
      for (const x of scope.matchAll(/\b(Math\.random\s*\(\s*\)|crypto\.randomUUID\s*\(\s*\)|Date\.now\s*\(\s*\)|new\s+Date\s*\(\s*\))/g)) {
        const pos = k.open + x.index!;
        const line = c.slice(c.lastIndexOf('\n', pos) + 1, c.indexOf('\n', pos) === -1 ? c.length : c.indexOf('\n', pos));
        if (/suppressHydrationWarning|useRef\s*\(|useId\b/.test(line)) continue;
        const after = c.slice(pos + x[0].length, pos + x[0].length + 40);
        const random = /random|randomUUID/.test(x[1]);
        if (!random && /^\s*\.\s*getFullYear\s*\(/.test(after)) continue; // the year only differs over New Year's Eve
        const timeText = /^\s*\.\s*(?:toLocale\w*|toTimeString|toString|toISOString|get(?:Hours|Minutes|Seconds|Milliseconds|Time))\s*\(/.test(after);
        const d = declOnLine(pos);
        let rendered = false;
        if (d && d.lineEnd > 0) {
          const later = rs.slice(d.lineEnd, k.close);
          rendered = random
            ? usedLater(d.name, d.lineEnd) && new RegExp(`[{=]\\s*[^}\\n]*\\b${esc(d.name)}\\b`).test(later)
            : (timeText && new RegExp(`\\{\\s*${esc(d.name)}\\s*\\}`).test(later)) ||
              new RegExp(`\\{\\s*${esc(d.name)}\\s*(?:\\.\\s*(?:toLocale\\w*|toTimeString|toString|toISOString|get(?:Hours|Minutes|Seconds|Milliseconds|Time))\\s*\\(|\\})|\\b(?:format\\w*)\\(\\s*${esc(d.name)}\\b`).test(later);
        } else if (lastJsxReturn !== -1 && x.index! > lastJsxReturn) {
          rendered = random || timeText;
        }
        if (!rendered || !provablySsr(pos)) continue;
        add({ ruleId: 29620, code: 'BUG-20', severity: 'MEDIUM', lineIdx: at(pos),
          title: `Hydration Mismatch: ${x[1].replace(/\s*\(\s*\)/, '()')} Rendered During Render`,
          why: `${x[1].replace(/\s*\(\s*\)/, '()')} returns a different value on the server and in the browser, so the HTML React hydrates does not match the server HTML: React throws a hydration error, discards the server markup and re-renders the tree on the client (flicker, lost SSR, console errors).`,
          fix: random
            ? 'Use useId() for ids, or generate the value in useEffect (useEffect(() => setId(crypto.randomUUID()), [])) and render a placeholder until then.'
            : 'Compute the time on the client after mount (useEffect + state), or render it on the server only and pass it down as a prop / string.' });
      }

      // BUG-21: date formatted with the runtime's locale / time zone during render
      for (const x of scope.matchAll(/\.\s*(toLocaleDateString|toLocaleTimeString|toLocaleString)\s*\(|\bnew\s+Intl\.DateTimeFormat\s*\(/g)) {
        const pos = k.open + x.index!;
        const open = pos + x[0].length - 1;
        const { end } = argsOf(m, open);
        if (end === -1) continue;
        const argText = c.slice(open, end);
        if (/timeZone/.test(argText) || !provablySsr(pos)) continue;
        if (x[1] === 'toLocaleString') {
          const recv = m.slice(Math.max(k.open, pos - 60), pos);
          if (!/(?:new\s+Date\s*\([^()]*(?:\([^()]*\))?[^()]*\)|\b\w*(?:[dD]ate|[tT]ime|At|[tT]imestamp)\w*(?:\(\s*\))?)\s*$/.test(recv)) continue;
        }
        add({ ruleId: 29621, code: 'BUG-21', severity: 'MEDIUM', lineIdx: at(pos),
          title: 'Hydration Mismatch: Date Formatted With the Runtime Time Zone During Render',
          why: 'The server formats the date in its own time zone (usually UTC) and locale; the browser formats it in the visitor\'s. The rendered text differs, so React reports a hydration mismatch and re-renders, and near midnight the visible date can even jump by a day.',
          fix: 'Pass an explicit timeZone (and locale): date.toLocaleDateString("en-US", { timeZone: "UTC" }), or format on the client after mount (useEffect) and render a placeholder first.' });
      }

      // BUG-22: browser-only global read while rendering (ReferenceError during server rendering)
      // (crash claim: route entries only, since a nested component may sit behind a client-only gate)
      const guarded = (pos: number) => /typeof\s+(?:window|document|navigator|localStorage|sessionStorage)\b|\b(?:isMounted|mounted|hasMounted|isClient|isBrowser|hydrated)\b/.test(rsStrict.slice(k.open, pos)) || earlyReturnBefore(pos);
      for (const g of ssrEntry && pageComp ? BROWSER_GLOBALS : []) {
        if (new RegExp(`(?:\\b(?:const|let|var|function|import)\\s+(?:[^=;]*[,{\\s])?${g}\\b|[({,]\\s*${g}\\s*[,:}=)?]|\\b${g}\\s*:\\s*\\w|\\.\\.\\.${g}\\b)`).test(m)) continue; // a local named document
        for (const x of scope.matchAll(new RegExp(`(?<![\\w$.])${g}\\s*\\??\\.\\s*[A-Za-z_]`, 'g'))) {
          const pos = k.open + x.index!;
          if (/typeof\s*$/.test(m.slice(pos - 12, pos)) || guarded(pos)) continue;
          const line = c.slice(c.lastIndexOf('\n', pos) + 1, pos);
          if (/typeof\s+(?:window|document)|\?\s*$|&&\s*$/.test(line)) continue;
          add({ ruleId: 29622, code: 'BUG-22', severity: 'HIGH', lineIdx: at(pos),
            title: `${g} Read During Render Crashes Server Rendering`,
            why: `Client components are rendered on the server first, where ${g} does not exist. This line runs during render, so the server throws ReferenceError: ${g} is not defined and the page fails with a 500 or an error boundary.`,
            fix: `Read ${g} inside useEffect (or an event handler) and keep the value in state, or guard it with typeof ${g} !== "undefined" in a lazy initializer and accept that the first render uses the default.` });
          break;
        }
      }

      // BUG-23: output branches on typeof window, so server and client render different markup
      for (const x of c.slice(k.open, k.close).matchAll(/typeof\s+window\s*[!=]==?\s*(['"])\s*undefined\s*\1|(['"])\s*undefined\s*\2\s*[!=]==?\s*typeof\s+window/g)) {
        const pos = k.open + x.index!;
        if (!inRender(pos) || !provablySsr(pos)) continue;
        const tail = m.slice(pos + x[0].length, pos + x[0].length + 200);
        const stmt = c.slice(c.lastIndexOf('\n', pos) + 1, pos);
        let mismatch = /^\s*\)?\s*(?:\?|&&)\s*\(?\s*<|^\s*\)?\s*\?\s*null\s*:\s*\(?\s*</.test(tail);
        if (!mismatch && /^\s*if\s*\(\s*!?\s*$/.test(stmt)) mismatch = /^\s*\)\s*(?:\{\s*)?return\b/.test(tail);
        const d = declOnLine(pos);
        if (!mismatch && d && d.lineEnd > 0) mismatch = new RegExp(`\\{\\s*!?\\s*${esc(d.name)}\\s*(?:\\?|&&|\\})`).test(rs.slice(d.lineEnd, k.close));
        if (!mismatch) continue;
        add({ ruleId: 29623, code: 'BUG-23', severity: 'MEDIUM', lineIdx: at(pos),
          title: 'Hydration Mismatch: Render Output Branches on typeof window',
          why: 'On the server typeof window is "undefined" and in the browser it is not, so the first client render produces different markup than the server HTML. React throws a hydration error and re-renders the whole tree on the client, and the server-rendered branch flashes first.',
          fix: 'Keep the first render identical: const [mounted, setMounted] = useState(false); useEffect(() => setMounted(true), []); and branch on mounted, or load the browser-only part with next/dynamic({ ssr: false }).' });
      }
    }
  }

  /* ---------------------------------------------------------------------------------------------------------- */
  /* State and effect rules                                                                                      */
  /* ---------------------------------------------------------------------------------------------------------- */
  if (comps.length) {
    for (const k of comps) {
      // State declared in this component / hook only (a prop of the same name elsewhere is not state)
      const localSetterOf = new Map<string, string>();
      const localStateOf = new Map<string, string>();
      for (const x of m.slice(k.open, k.close).matchAll(/\b(?:const|let)\s*\[\s*(\w+)\s*,\s*(set\w+)\s*\]\s*=\s*(?:React\.)?useState\b/g)) {
        localSetterOf.set(x[1], x[2]);
        localStateOf.set(x[2], x[1]);
      }
      // BUG-24: setState as an unconditional statement of the component body (render loop)
      for (const x of m.slice(k.open, k.close).matchAll(/(^|\n)([ \t]*)(set[A-Z]\w*)\s*\(/g)) {
        if (!localStateOf.has(x[3])) continue;
        const pos = k.open + x.index! + x[1].length + x[2].length;
        if (!inRender(pos) || depthAt(m, k.open, pos) !== 1 || compAt(pos) !== k) continue;
        const prevLine = m.slice(k.open, pos).trimEnd().split('\n').pop() || '';
        if (/^\s*(?:if|else|for|while)\b|(?:=>|[?:&|(,=])\s*$|\belse\s*$/.test(prevLine)) continue;
        add({ ruleId: 29624, code: 'BUG-24', severity: 'HIGH', lineIdx: at(pos),
          title: `${x[3]}() Called During Render (Infinite Re-render Loop)`,
          why: `${x[3]}() runs every time ${k.name} renders and schedules another render, so React aborts with "Too many re-renders" and the component never shows.`,
          fix: `Move it into an event handler or useEffect, or compute the value directly during render instead of storing it in state.` });
      }

      // BUG-30: effect unconditionally updates one of its own dependencies with a new value (endless loop)
      // BUG-26: interval / listener registered once ([] deps) reads a state value it closed over
      // BUG-28: dependency recreated on every render
      const body = m.slice(k.open, k.close);
      for (const x of body.matchAll(/\b(useEffect|useLayoutEffect|useMemo|useCallback)\s*\(/g)) {
        const callAt = k.open + x.index!;
        if (compAt(callAt) !== k) continue;
        const { args, end } = argsOf(m, callAt + x[0].length - 1);
        if (end === -1 || args.length !== 2) continue;
        const cb = args[0];
        const deps = args[1].text.trim();
        if (!deps.startsWith('[')) continue;
        const depItems = deps.slice(1, -1).split(',').map((s) => s.trim()).filter(Boolean);
        const isEffect = /Effect$/.test(x[1]);
        const cbOpen = m.indexOf('{', cb.at);
        const cbBlock = isEffect && cbOpen !== -1 && cbOpen < cb.at + cb.text.length && /^\s*(?:async\s*)?\(\s*\)\s*=>\s*$/.test(m.slice(cb.at, cbOpen));

        if (isEffect && cbBlock) {
          const cbClose = matchFwd(m, cbOpen);
          for (const s of m.slice(cbOpen, cbClose).matchAll(/(^|[\n;{]\s*)(set[A-Z]\w*)\s*\(/g)) {
            const st = localStateOf.get(s[2]);
            if (!st || !depItems.includes(st)) continue;
            const sp = cbOpen + s.index! + s[1].length;
            if (depthAt(m, cbOpen, sp) !== 1 || regionsAll.some((r) => r.start > cbOpen && r.start <= sp && sp < r.end)) continue;
            if (/\breturn\b/.test(blankFns(m, regionsAll.filter((r) => r.start > cbOpen), true).slice(cbOpen, sp))) continue; // behind an early exit
            const prevLine = m.slice(cbOpen, sp).trimEnd().split('\n').pop() || '';
            if (/^\s*(?:if|else|for|while)\b|(?:=>|[?:&|(,=])\s*$/.test(prevLine)) continue;
            const ao = sp + s[2].length + m.slice(sp + s[2].length).indexOf('(');
            const a = argsOf(m, ao).args[0]?.text.trim() || '';
            if (!(new RegExp(`\\b${esc(st)}\\b`).test(a) || /^[[{]/.test(a) || /=>/.test(a))) continue;
            add({ ruleId: 29630, code: 'BUG-30', severity: 'HIGH', lineIdx: at(sp),
              title: `useEffect Updates Its Own Dependency ${st} (Infinite Loop)`,
              why: `The effect depends on ${st} and always sets ${st} to a new value, so every run triggers a render that runs the effect again: the component loops forever, freezing the tab (and hammering the API if the effect fetches).`,
              fix: `Remove ${st} from the dependency array and use a functional update (${s[2]}(prev => ...)), or only set it when the value actually changes (if (next !== ${st}) ${s[2]}(next)).` });
          }
        }

        if (isEffect && deps === '[]' && /\b(?:setInterval|addEventListener|\.on\s*\(|\.subscribe\s*\(|onmessage\s*=)/.test(cb.text)) {
          const inner = fnRegions(m, cb.at, cb.at + cb.text.length).filter((r) => r.start > cb.at + 2);
          for (const s of cb.text.matchAll(/\b(set[A-Z]\w*)\s*\(/g)) {
            const st = localStateOf.get(s[1]);
            if (!st) continue;
            const sp = cb.at + s.index!;
            if (!inner.some((r) => r.start <= sp && sp < r.end)) continue;
            const a = argsOf(m, sp + s[0].length - 1).args[0]?.text.trim() || '';
            if (/=>/.test(a) || !new RegExp(`(?<![\\w.])${esc(st)}\\b`).test(a)) continue;
            if (new RegExp(`\\b(?:const|let)\\s+${esc(st)}\\b|\\(\\s*${esc(st)}\\s*[,)]`).test(cb.text)) continue;
            add({ ruleId: 29626, code: 'BUG-26', severity: 'HIGH', lineIdx: at(sp),
              title: `Stale State: Callback Registered Once Reads ${st} From the First Render`,
              why: `The effect runs once ([] deps), so the interval / listener keeps the ${st} value from the first render forever. ${s[1]}(${a.slice(0, 40)}) always computes from that initial value: counters stop at 1, chat messages overwrite each other.`,
              fix: `Use a functional update: ${s[1]}(prev => ...) instead of reading ${st}, or keep the latest value in a ref.` });
          }
        }

        // BUG-28: literal or render-scoped object / array / function in an effect's dependency array
        // (for useMemo / useCallback it only wastes the memo, so it is not reported)
        for (const d of isEffect ? depItems : []) {
          let fresh = /^(?:\{|\[|new\s|function\b|(?:async\s*)?(?:\([^()]*\)|\w+)\s*=>)/.test(d) ? d : '';
          if (!fresh && /^\w+$/.test(d)) {
            const decl = new RegExp(`\\b(?:const|let)\\s+${esc(d)}\\s*(?::[^=]+)?=\\s*(?:\\{|\\[|(?:async\\s*)?\\([^()]*\\)\\s*(?::[^=]+)?=>|(?:async\\s+)?\\w+\\s*=>|function\\b|new\\s+(?:Date|Map|Set|URLSearchParams|Object|Array)\\b)`).exec(rs.slice(k.open, callAt));
            if (decl) {
              const dp = k.open + decl.index;
              if (inRender(dp) && depthAt(m, k.open, dp) === 1 && compAt(dp) === k) fresh = d;
            }
          }
          if (!fresh) continue;
          const loops = isEffect && [...cb.text.matchAll(/(?<![\w.$])(set[A-Z]\w*)\b/g)].some((z) => localStateOf.has(z[1]));
          add({ ruleId: 29628, code: 'BUG-28', severity: loops ? 'HIGH' : 'MEDIUM', lineIdx: at(args[1].at),
            title: `${x[1]} Dependency ${fresh.length > 30 ? 'Literal' : fresh} Is Recreated Every Render`,
            why: `${fresh.length > 30 ? 'This object / array / function' : fresh} is a new reference on every render, so React sees a changed dependency each time and ${isEffect ? 'reruns the effect after every render' : 'never reuses the memoized value'}.${loops ? ' The effect sets state, so it renders again and loops forever.' : ''}`,
            fix: 'Depend on primitive values (user.id instead of user / options), move the constant outside the component, or wrap it in useMemo / useCallback.' });
          break;
        }

        // BUG-29: useCallback / useMemo with [] that reads state, so it keeps the first render's value
        if (!isEffect && deps === '[]') {
          // Names the callback declares itself: parameters of any nested function and local variables
          const own = new Set<string>();
          for (const z of cb.text.matchAll(/\b(?:const|let|var)\s+(\w+)|\b(\w+)\s*=>|\(([^()]*)\)\s*(?::[^=]+)?=>|\bfunction\s*\w*\s*\(([^()]*)\)/g)) {
            if (z[1] || z[2]) own.add(z[1] || z[2]);
            for (const p of (z[3] ?? z[4] ?? '').split(',')) { const n = /^\s*(?:\.\.\.)?(\w+)/.exec(p); if (n) own.add(n[1]); }
          }
          for (const z of cb.text.matchAll(/\b(?:const|let|var)\s*[{[]([^}\]=]*)[}\]]\s*=/g)) for (const p of z[1].split(',')) { const n = /(\w+)\s*$/.exec(p.trim()); if (n) own.add(n[1]); }
          for (const [st, setter] of localSetterOf) {
            if (own.has(st)) continue;
            const r = new RegExp(`(?<![\\w$.'"])${esc(st)}\\b(?!\\s*\\??:)`).exec(cb.text);
            if (!r) continue;
            add({ ruleId: 29629, code: 'BUG-29', severity: 'MEDIUM', lineIdx: at(cb.at + r.index),
              title: `${x[1]} With [] Reads ${st} (Frozen at the First Render)`,
              why: `The empty dependency array makes React keep the ${x[1] === 'useCallback' ? 'function' : 'value'} from the first render, so it always sees the initial ${st}, never the current one: handlers submit stale data and derived values never update.`,
              fix: `Add ${st} to the dependency array, or use a functional update (${setter}(prev => ...)) when it only needs the previous value.` });
            break;
          }
        }
      }

      // BUG-27: prop copied into state that is never updated
      if (!k.hook) {
        const props = new Set<string>();
        const pm = /^\s*\{([^}]*)\}/.exec(k.params);
        if (pm) for (const p of pm[1].split(',')) { const n = /(?:\w+\s*:\s*)?(\w+)\s*(?:=.*)?$/.exec(p.trim()); if (n) props.add(n[1]); }
        const single = /^\s*(\w+)\s*(?::|$)/.exec(k.params)?.[1];
        for (const x of body.matchAll(/\b(?:const|let)\s*\[\s*(\w+)\s*(?:,\s*(set\w+)\s*)?\]\s*=\s*(?:React\.)?useState(?:<[^>()]*>)?\s*\(\s*([\w.?]+)\s*(?:\?\?\s*[^)]{0,20}|\|\|\s*[^)]{0,20})?\)/g)) {
          const src = x[3];
          const fromProp = props.has(src) || (single && new RegExp(`^${esc(single)}\\??\\.\\w+$`).test(src));
          if (!fromProp || /^(?:initial|default|original|start|seed)/i.test(x[1]) || /(?:^|\.)(?:initial|default|original|seed)\w*$/i.test(src)) continue;
          if (x[2] && new RegExp(`\\b${esc(x[2])}\\b`).test(m.slice(0, k.open + x.index!) + m.slice(k.open + x.index! + x[0].length))) continue;
          add({ ruleId: 29627, code: 'BUG-27', severity: 'MEDIUM', lineIdx: at(k.open + x.index!),
            title: `Prop ${src} Copied Into State ${x[1]} That Never Updates`,
            why: `useState only uses ${src} on the first render and nothing ever sets ${x[1]}, so when the parent passes a new ${src} (another record, refreshed data) this component keeps showing the old value.`,
            fix: `Use ${src} directly (const ${x[1]} = ${src}), or derive it with useMemo; if the state must reset per item, give the component key={item.id}.` });
        }
      }

      // BUG-59: hook called after an early return or inside a condition
      const strict = rsStrict.slice(k.open, k.close);
      let earlyReturn = -1;
      for (const x of strict.matchAll(/\bif\s*\(/g)) {
        const ip = k.open + x.index!;
        if (depthAt(m, k.open, ip) !== 1) continue;
        const pc = matchFwd(m, ip + x[0].length - 1);
        const after = rsStrict.slice(pc + 1, pc + 400);
        const blk = /^\s*\{/.exec(after);
        const thenText = blk ? rsStrict.slice(pc + 1 + blk[0].length - 1, matchFwd(m, pc + 1 + blk[0].length - 1) + 1) : after.split(/[;\n]/)[0];
        if (/\breturn\b/.test(thenText)) { earlyReturn = ip; break; }
      }
      for (const x of strict.matchAll(/\b(use[A-Z]\w*)\s*\(/g)) {
        const hp = k.open + x.index!;
        if (m[hp - 1] === '.' && !/React\.$/.test(m.slice(hp - 6, hp))) continue;
        const d = depthAt(m, k.open, hp);
        let why = '';
        if (earlyReturn !== -1 && hp > earlyReturn && d === 1) why = 'after an early return';
        else if (d > 1) {
          let ob = hp;
          for (let depth = 0; ob > k.open; ob--) {
            const ch = m[ob - 1];
            if (CLOSE.includes(ch)) depth++;
            else if (OPEN.includes(ch)) { if (depth === 0) break; depth--; }
          }
          ob--;
          if (m[ob] === '{') {
            let j = ob - 1;
            while (j > k.open && /\s/.test(m[j])) j--;
            const pb = m[j] === ')' ? matchBack(m, j) : -1;
            if (pb !== -1 ? /\b(?:if|for|while)\s*$/.test(m.slice(Math.max(k.open, pb - 12), pb)) : /\belse$/.test(m.slice(Math.max(k.open, j - 5), j + 1))) why = 'inside a condition or loop';
          }
        }
        if (!why) continue;
        add({ ruleId: 29659, code: 'BUG-59', severity: 'HIGH', lineIdx: at(hp),
          title: `${x[1]}() Called ${why === 'after an early return' ? 'After an Early Return' : 'Conditionally'} (Rules of Hooks)`,
          why: `React matches hooks by call order. ${x[1]}() runs ${why}, so when the condition changes React sees a different number of hooks and crashes with "Rendered more hooks than during the previous render" (or hands state to the wrong hook).`,
          fix: 'Call every hook unconditionally at the top of the component, before any early return; put the condition inside the hook (useEffect(() => { if (!user) return; ... }, [user])).' });
        break;
      }
    }

    // BUG-25: event prop given the result of calling a setter instead of a function
    for (const x of m.matchAll(/\b(on[A-Z]\w*)\s*=\s*\{\s*(set[A-Z]\w*)\s*\(/g)) {
      if (!stateOfSetter.has(x[2])) continue;
      add({ ruleId: 29625, code: 'BUG-25', severity: 'HIGH', lineIdx: at(x.index!),
        title: `${x[1]}={${x[2]}(...)} Calls the Setter During Render`,
        why: `${x[2]}(...) runs while rendering (its return value, undefined, becomes the ${x[1]} handler), so it sets state on every render: React aborts with "Too many re-renders" and the ${x[1]} never works.`,
        fix: `Pass a function: ${x[1]}={() => ${x[2]}(...)}.` });
    }

    // BUG-53: state mutated in place, then set with the same reference (no re-render)
    for (const [st, setter] of setterOf) {
      const mut = new RegExp(`(?<![\\w$.])${esc(st)}(?:\\.(?:push|pop|shift|unshift|splice)\\s*\\(|(?:\\[[^\\]\\n]+\\]|\\.\\w+)\\s*=(?!=))`, 'g');
      for (const x of m.matchAll(mut)) {
        const next = m.slice(x.index!, x.index! + 300).split('\n').slice(0, 5).join('\n');
        if (!new RegExp(`\\b${esc(setter)}\\s*\\(\\s*${esc(st)}\\s*\\)`).test(next)) continue;
        if (new RegExp(`\\b(?:const|let)\\s+${esc(st)}\\b`).test(m.slice(Math.max(0, x.index! - 400), x.index!))) continue; // shadowed copy
        add({ ruleId: 29653, code: 'BUG-53', severity: 'HIGH', lineIdx: at(x.index!),
          title: `State ${st} Mutated In Place, Then Set With the Same Reference`,
          why: `${setter}(${st}) passes the same array / object it just mutated. React compares with Object.is, sees no change and skips the re-render, so the UI does not update (and other components see the mutation unexpectedly).`,
          fix: `Create a new value: ${setter}(prev => [...prev, item]) / ${setter}(prev => ({ ...prev, field: value })).` });
        break;
      }
    }
  }

  /* ---------------------------------------------------------------------------------------------------------- */
  /* JSX: keys, forms, inputs, next/image, className                                                             */
  /* ---------------------------------------------------------------------------------------------------------- */
  const hasJsx = usesReact && /\.[jt]sx$|\.js$/.test(path) && /<[A-Za-z][\w.]*[\s>/]/.test(m);
  if (hasJsx) {
    // BUG-31: random key
    for (const x of m.matchAll(/\bkey\s*=\s*\{/g)) {
      const o = x.index! + x[0].length - 1;
      const e = matchFwd(m, o);
      if (e === -1) continue;
      const v = c.slice(o + 1, e);
      const r = /\b(Math\.random|crypto\.randomUUID|randomUUID|Date\.now|nanoid|uuidv4|uuid|v4|cuid|createId)\s*\(/.exec(v);
      if (!r) continue;
      add({ ruleId: 29631, code: 'BUG-31', severity: 'MEDIUM', lineIdx: at(x.index!),
        title: `Random key (${r[1]}()) Remounts the Element on Every Render`,
        why: 'A new key on each render tells React this is a different element, so it unmounts and recreates it every time: inputs lose focus and typed text after each keystroke, animations restart and component state resets.',
        fix: 'Use a stable id from the data (key={item.id}); if items have none, assign an id once when the item is created.' });
    }

    // BUG-32: index key on a list the user deletes from, rendering uncontrolled inputs
    for (const x of m.matchAll(/\b(\w+)\??\.map\s*\(\s*\(\s*(\w+)\s*(?::[^,()]+)?,\s*(\w+)\s*(?::[^,()]+)?\)\s*=>/g)) {
      const [, arr, , idx] = x;
      const setter = setterOf.get(arr);
      if (!setter) continue;
      const open = x.index! + x[0].indexOf('(', arr.length);
      const end = matchFwd(m, open);
      if (end === -1) continue;
      const cbText = c.slice(open, end);
      const key = new RegExp(`\\bkey\\s*=\\s*\\{\\s*${esc(idx)}\\s*\\}`).exec(m.slice(open, end));
      if (!key) continue;
      const deletes = new RegExp(`\\b${esc(setter)}\\s*\\(\\s*(?:\\(?\\s*(\\w+)\\s*(?::[^)]*)?\\)?\\s*=>\\s*(?:\\1|\\w+)|${esc(arr)})\\s*\\.(?:filter|splice|toSpliced)\\s*\\(`).test(m);
      const uncontrolled = /\bdefaultValue\s*=|\bdefaultChecked\s*=/.test(cbText) ||
        [...m.slice(open, end).matchAll(/<(?:input|textarea)\b/g)].some((t) => { const tg = jsxTag(m, open + t.index!); return !!tg && !/(?:^|\s)(?:value|checked)\s*=|\{\s*\}/.test(tg.flat); });
      if (!deletes || !uncontrolled) continue;
      add({ ruleId: 29632, code: 'BUG-32', severity: 'MEDIUM', lineIdx: at(open + key.index),
        title: `Index key on ${arr}, Which Is Deleted From: Inputs Show the Wrong Row's Value`,
        why: `Rows are keyed by position while ${setter}(...filter/splice) removes items. After a delete React reuses the DOM of the removed index for the next item, so uncontrolled inputs (defaultValue / no value) keep the deleted row's text and edits land on the wrong item.`,
        fix: `Key by a stable id (key={${x[2]}.id}); give new items an id when they are created (crypto.randomUUID()).` });
    }

    // Walk every JSX opening tag once
    const formRanges: { lt: number; end: number; close: number }[] = [];
    const tags: { lt: number; end: number; name: string; flat: string }[] = [];
    for (const x of m.matchAll(/<[A-Za-z]/g)) {
      const t = jsxTag(m, x.index!);
      if (t) tags.push({ lt: x.index!, end: t.end, name: t.name, flat: t.flat });
    }
    const nextImage = /from\s+['"]next\/(?:legacy\/)?image['"]/.test(c);

    for (const t of tags) {
      const has = (a: string) => attrRe(a).test(t.flat);
      const spread = /\{\s*\}/.test(t.flat.replace(/\b[\w-]+\s*=\s*\{\s*\}/g, ''));
      const val = (a: string) => attrValue(c, m, t.lt, t.end, a);

      // BUG-33: controlled input without onChange (cannot be typed in)
      if (/^(?:input|textarea|select|Input|Textarea)$/.test(t.name) && !spread) {
        const type = (val('type') || '').trim();
        const valueAttr = has('value') && !/^(?:hidden|submit|button|reset|checkbox|radio|image)$/.test(type);
        const checkedAttr = has('checked') && /^(?:checkbox|radio)$/.test(type);
        if ((valueAttr || checkedAttr) && !/(?:^|\s)(?:onChange|onInput|onValueChange|onCheckedChange|readOnly|readonly|disabled)\b/.test(t.flat)) {
          const v = (val(valueAttr ? 'value' : 'checked') || '').trim();
          // Only state the component owns (with a setter) is meant to be edited; a prop / constant is a display field
          const base = /^(\w+)(?:\??\.\w+)?$/.exec(v)?.[1];
          if (base && setterOf.has(base)) {
            add({ ruleId: 29633, code: 'BUG-33', severity: 'HIGH', lineIdx: at(t.lt + t.flat.search(/\s(?:value|checked)\s*=/) + t.name.length + 1),
              title: `<${t.name}> Has ${valueAttr ? 'value' : 'checked'} but No onChange (Read-Only Field)`,
              why: `A ${valueAttr ? 'value' : 'checked'} prop makes the field controlled: React resets it to {${v.slice(0, 40)}} on every render, and with no onChange nothing updates it, so the user cannot type in / toggle it (React also warns about it in the console).`,
              fix: `Add onChange={(e) => set...(e.target.${valueAttr ? 'value' : 'checked'})}, use default${valueAttr ? 'Value' : 'Checked'} for an uncontrolled field, or mark it readOnly if it is display-only.` });
          }
        }
      }

      if (t.name === 'form') {
        const close = m.indexOf('</form>', t.end);
        formRanges.push({ lt: t.lt, end: t.end, close: close === -1 ? t.end : close });

        // BUG-34: onSubmit handler that sends a request without preventDefault (page reloads mid-request)
        const os = attrSpan(c, m, t.lt, t.end, 'onSubmit');
        if (os !== null && !has('action')) {
          let hb: { body: string } | null = null;
          if (/^\s*\w+\s*$/.test(os.text)) hb = handlerBody(m, os.text.trim());
          else if (/^\s*(?:async\s*)?(?:\([^()]*\)|\w+)\s*(?::[^=]+)?=>/.test(os.text)) hb = { body: m.slice(os.s, os.e) };
          if (hb && /\bfetch\s*\(|\baxios\b|\.(?:post|put|patch)\s*\(|\bsupabase\b[\s\S]*\.(?:insert|update|upsert)\s*\(/.test(hb.body) && !/preventDefault/.test(hb.body)) {
            add({ ruleId: 29634, code: 'BUG-34', severity: 'HIGH', lineIdx: at(t.lt + t.flat.indexOf('onSubmit') + 1 + t.name.length),
              title: 'Form onSubmit Sends a Request Without preventDefault (Page Reloads)',
              why: 'The browser still performs its default form submission: it reloads the page (GET with the fields in the URL) while the request is in flight, aborting the fetch, wiping component state and any error message, and leaking form values into the URL / history.',
              fix: 'Call e.preventDefault() first in the handler (const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => { e.preventDefault(); ... }), or use a Server Action via <form action={...}>.' });
          }
        }

        // BUG-58: form action given a client function that calls preventDefault (it receives FormData)
        const ac = attrSpan(c, m, t.lt, t.end, 'action');
        if (ac !== null) {
          let hb: { at: number; body: string; params: string } | null = null;
          if (/^\s*\w+\s*$/.test(ac.text)) hb = handlerBody(m, ac.text.trim());
          else if (/^\s*(?:async\s*)?\(\s*\w+/.test(ac.text)) hb = { at: ac.s, body: m.slice(ac.s, ac.e), params: (/\(([^()]*)\)/.exec(ac.text) || ['', ''])[1] };
          const p = hb ? /^\s*(\w+)/.exec(hb.params)?.[1] : undefined;
          if (hb && p && new RegExp(`\\b${esc(p)}\\s*\\.\\s*(?:preventDefault|currentTarget|target)\\b`).test(hb.body) && !/['"]use server['"]/.test(c.slice(hb.at, hb.at + 400))) {
            add({ ruleId: 29658, code: 'BUG-58', severity: 'HIGH', lineIdx: at(t.lt + t.flat.indexOf('action') + 1 + t.name.length),
              title: 'Form action Handler Treats Its Argument as an Event',
              why: `A function passed to <form action> is called with the FormData, not a submit event, so ${p}.preventDefault() / ${p}.target throws "is not a function" / reads undefined and the submit fails every time.`,
              fix: `Either keep the event API and use onSubmit={...}, or accept FormData: async function submit(formData: FormData) { const email = formData.get("email"); ... } with <form action={submit}>.` });
          }
        }
      }

      if (nextImage && t.name === 'Image' && !spread) {
        const fill = /(?:^|\s)fill(?=\s|\/|$|=\{\s*true\s*\})/.test(t.flat) || /\sfill\s*=\s*\{\s*true\s*\}/.test(c.slice(t.lt, t.end));
        // BUG-48: fill without sizes
        if (fill && !has('sizes')) {
          add({ ruleId: 29648, code: 'BUG-48', severity: 'LOW', lineIdx: at(t.lt),
            title: '<Image fill> Without sizes Downloads a Full-Viewport-Width Image',
            why: 'Without sizes, next/image assumes the image is 100vw wide and the browser picks the largest srcset candidate, so a 300px thumbnail downloads a 1920px+ file on every device (slow LCP, wasted mobile data).',
            fix: 'Describe the rendered width: sizes="(max-width: 768px) 100vw, 33vw" (match the CSS of the parent).' });
        }
        // BUG-49: fill together with width/height, or a string src without width/height
        const src = val('src');
        const literalSrc = src !== null && (/^\s*['"`]/.test(src) || /\ssrc\s*=\s*["']/.test(c.slice(t.lt, t.end)));
        if ((fill && (has('width') || has('height'))) || (!fill && literalSrc && (!has('width') || !has('height')))) {
          add({ ruleId: 29649, code: 'BUG-49', severity: 'HIGH', lineIdx: at(t.lt),
            title: fill ? '<Image> Has Both fill and width/height' : '<Image> With a URL src Is Missing width/height',
            why: fill
              ? 'next/image throws "Image has both width and fill properties": the component errors and the image (or the whole page, without an error boundary) fails to render.'
              : 'For a string src next/image cannot read the intrinsic size, so it throws "Image is missing required width property" and the page errors.',
            fix: fill ? 'Use either fill (with a positioned parent and sizes) or width + height, not both.' : 'Pass width and height (the intrinsic size, CSS can still resize it), import the image statically, or use fill inside a sized, position:relative parent.' });
        }
      }
    }

    // BUG-35: button without type, with its own onClick, inside a form that already has a submit button
    for (const f of formRanges) {
      const inForm = tags.filter((t) => t.lt > f.end && t.lt < f.close && t.name === 'button');
      const hasSubmit = inForm.some((t) => /\stype\s*=\s*["{']?\s*submit/.test(c.slice(t.lt, t.end + 1)));
      if (!hasSubmit) continue;
      for (const t of inForm) {
        if (attrRe('type').test(t.flat) || !attrRe('onClick').test(t.flat) || /\{\s*\}/.test(t.flat.replace(/\b[\w-]+\s*=\s*\{\s*\}/g, ''))) continue;
        const oc = attrValue(c, m, t.lt, t.end, 'onClick') || '';
        if (/submit/i.test(oc)) continue;
        add({ ruleId: 29635, code: 'BUG-35', severity: 'MEDIUM', lineIdx: at(t.lt),
          title: '<button> Without type Inside a Form Also Submits It',
          why: 'Buttons default to type="submit", so clicking this one (cancel, add row, show password, next step) runs its onClick and then submits the form: data is saved or the page reloads when the user only wanted the secondary action.',
          fix: 'Add type="button" to every button in a form that is not the submit button.' });
      }
    }

    // BUG-36: payment / checkout request fired from a button that can be clicked again while it is pending
    for (const t of tags.filter((x) => /^(?:button|Button)$/.test(x.name))) {
      const oc = attrValue(c, m, t.lt, t.end, 'onClick');
      if (!oc || attrRe('disabled').test(t.flat) || /\{\s*\}/.test(t.flat.replace(/\b[\w-]+\s*=\s*\{\s*\}/g, ''))) continue;
      let body = '';
      const named = /^\s*(?:\(\s*\)\s*=>\s*)?(\w+)\s*(?:\([^)]*\))?\s*$/.exec(oc);
      if (named) { const hb = handlerBody(m, named[1]); body = hb ? c.slice(hb.s, hb.e) : ''; }
      else if (/=>/.test(oc)) body = oc;
      if (!body) continue;
      const pay = /\b(?:fetch\s*\(\s*[`'"][^`'"]*|axios\.post\s*\(\s*[`'"][^`'"]*)\/(?:api\/)?(?:[\w-]+\/)*(?:charge|checkout|pay|payment|payments|purchase|order|orders|subscribe|subscription|subscriptions|donate|tip)(?:[/?`'"]|-session)/i.exec(body);
      if (!pay || (/\bfetch\s*\(/.test(pay[0]) && !/method\s*:\s*['"`]POST/i.test(body))) continue;
      if (/\bif\s*\(\s*!?\s*[\w.]*(?:loading|pending|submitting|processing|busy|inFlight|disabled)\w*\s*\)\s*(?:\{\s*)?return|set\w*(?:Loading|Pending|Submitting|Processing|Busy)\w*\s*\(\s*true|\.current\s*\)\s*return|startTransition/i.test(body)) continue;
      add({ ruleId: 29636, code: 'BUG-36', severity: 'HIGH', lineIdx: at(t.lt),
        title: 'Payment Button Can Be Clicked Again While the Charge Is Pending',
        why: 'The button stays enabled while the payment / order request is in flight and the handler has no in-progress guard, so a double click (or an impatient second click on a slow network) sends the request twice: duplicate orders, double charges or two subscriptions.',
        fix: 'Track pending state and block re-entry: const [pending, setPending] = useState(false); if (pending) return; setPending(true); try { ... } finally { setPending(false) } with <button disabled={pending}>; also send an idempotency key to the payment API.' });
    }

    // BUG-52: {list.length && <JSX>} renders a literal 0
    for (const x of m.matchAll(/\{\s*!?\s*([\w$]+(?:\??\.[\w$]+)*)\??\.length\s*&&\s*(?:\(\s*)?</g)) {
      if (/^\{\s*!/.test(x[0])) continue;
      add({ ruleId: 29652, code: 'BUG-52', severity: 'MEDIUM', lineIdx: at(x.index!),
        title: `{${x[1]}.length && ...} Renders "0" When the List Is Empty`,
        why: `When ${x[1]} is empty the expression evaluates to the number 0, which React renders as text: a stray "0" appears in the UI (and in React Native it crashes with "Text strings must be rendered within a <Text>").`,
        fix: `Compare explicitly: {${x[1]}.length > 0 && ...} or use a ternary that returns null.` });
    }

    // BUG-50 / BUG-51: className contradictions and fixed desktop widths
    const pageFile = /\.[jt]sx$/.test(path) && ((inApp && /(?:^|\/)(?:page|layout|template|loading|not-found)\.[jt]sx$/.test(path)) || (nextPages && !/(?:^|\/)pages\/(?:api|_)/.test(path)));
    for (const x of c.matchAll(/\bclassName\s*=\s*(?:\{\s*)?(?:cn\(|clsx\(|twMerge\()?\s*(["'`])([^"'`\n]*)\1/g)) {
      const tokens = x[2].split(/\s+/).filter(Boolean);
      const off = x.index!;
      for (const col of ['white', 'black']) {
        if (tokens.includes(`text-${col}`) && tokens.includes(`bg-${col}`)) {
          add({ ruleId: 29650, code: 'BUG-50', severity: 'MEDIUM', lineIdx: at(off),
            title: `text-${col} on bg-${col}: Invisible Text`,
            why: `The same element sets text-${col} and bg-${col} with no variant prefix, so its text is drawn in the background color and cannot be read.`,
            fix: `Use a contrasting text color (e.g. text-${col === 'white' ? 'gray-900' : 'white'}), or apply the colors under different variants (dark:, hover:).` });
        }
      }
      const wide = tokens.map((tk) => /^(?:min-)?w-\[(\d+)px\]$/.exec(tk)).find((r) => r && +r[1] >= 768);
      // Page-level containers only (route entries): absolutely positioned decoration and clipped parents do not scroll
      if (wide && pageFile && !tokens.some((tk) => /^max-w-|^hidden$|^overflow-|^absolute$|^fixed$|^inset-|translate-x/.test(tk))) {
        const before = c.slice(Math.max(0, c.lastIndexOf('\n', off - 1) - 600), off);
        if (!/overflow-(?:x-)?(?:auto|scroll|hidden|clip)|ScrollArea|\bhidden\s+(?:sm|md|lg|xl|2xl):(?:block|flex|grid|inline)|overflowX/.test(before)) {
          add({ ruleId: 29651, code: 'BUG-51', severity: 'MEDIUM', lineIdx: at(off),
            title: `Fixed ${wide[0]} Width Overflows Phone Screens`,
            why: `${wide[0]} applies at every breakpoint and nothing caps it, so on a 375-430px phone the element is ${wide[1]}px wide: the page scrolls sideways and content is cut off.`,
            fix: `Make it fluid: w-full max-w-[${wide[1]}px] (or apply the fixed width from a breakpoint: md:${wide[0]}), or wrap it in overflow-x-auto if horizontal scrolling is intended.` });
        }
      }
    }
  }

  /* ---------------------------------------------------------------------------------------------------------- */
  /* Next.js App Router                                                                                          */
  /* ---------------------------------------------------------------------------------------------------------- */
  // BUG-37: cookies() / headers() / draftMode() used synchronously (removed in Next.js 16)
  if (context?.nextMajorVersion != null && context.nextMajorVersion >= 16 && /from\s+['"]next\/headers['"]/.test(c)) {
    for (const x of m.matchAll(/\b(cookies|headers|draftMode)\s*\(\s*\)\s*\.\s*(get|getAll|has|set|delete|isEnabled|enable|disable|entries|forEach|keys|values)\b/g)) {
      if (/\bawait\s*$/.test(m.slice(x.index! - 10, x.index!))) continue;
      add({ ruleId: 29637, code: 'BUG-37', severity: 'HIGH', lineIdx: at(x.index!),
        title: `Request API Used Without await: ${x[1]}() (Next.js 16)`,
        why: `Since Next.js 16 ${x[1]}() returns a Promise only; ${x[1]}().${x[2]} is undefined, so this line throws "${x[2]} is not a function" (or reads undefined) and the request fails.`,
        fix: `Await it first: const store = await ${x[1]}(); store.${x[2]}(...) (run npx @next/codemod@latest next-async-request-api .).` });
    }
    for (const x of m.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(cookies|headers|draftMode)\s*\(\s*\)/g)) {
      if (!new RegExp(`\\b${esc(x[1])}\\s*\\.\\s*(?:get|getAll|has|set|delete|isEnabled)\\b`).test(m.slice(x.index! + x[0].length))) continue;
      add({ ruleId: 29637, code: 'BUG-37', severity: 'HIGH', lineIdx: at(x.index!),
        title: `Request API Used Without await: ${x[2]}() (Next.js 16)`,
        why: `Since Next.js 16 ${x[2]}() returns a Promise only, so ${x[1]} is a Promise and ${x[1]}.get(...) throws "is not a function": the page or route fails.`,
        fix: `const ${x[1]} = await ${x[2]}();` });
    }
  }

  if (isClient) {
    // BUG-38: metadata exported from a client component
    for (const x of m.matchAll(/^export\s+(?:const\s+(metadata|viewport)\b|(?:async\s+)?function\s+(generateMetadata|generateViewport|generateStaticParams)\b)/gm)) {
      const name = x[1] || x[2];
      add({ ruleId: 29638, code: 'BUG-38', severity: 'HIGH', lineIdx: at(x.index!),
        title: `${name} Exported From a "use client" File`,
        why: `Next.js only reads ${name} from Server Components; exporting it from a "use client" module fails the build ("You are attempting to export \\"${name}\\" from a component marked with \\"use client\\", which is disallowed").`,
        fix: `Keep page.tsx / layout.tsx a Server Component that exports ${name}, and move the interactive part into a separate "use client" component it renders.` });
    }
    // BUG-39: async client component
    for (const k of comps.filter((x) => x.async && !x.hook)) {
      add({ ruleId: 29639, code: 'BUG-39', severity: 'HIGH', lineIdx: at(k.decl),
        title: `Async Client Component ${k.name}`,
        why: 'Client Components cannot be async functions: React errors with "async/await is not yet supported in Client Components" (or renders a Promise and loops), so the component never shows.',
        fix: 'Remove "use client" and keep it a Server Component that awaits data, or keep it client-side and load data in useEffect / a data hook (SWR, React Query) or with use(promise) passed from a server parent.' });
    }
    // BUG-40: server-only module imported into a client component
    for (const x of c.matchAll(/^\s*import\s+(?!type\b)(?:[^;'"]*?\s+from\s+)?['"](fs|fs\/promises|child_process|net|tls|dns|node:(?:fs|fs\/promises|child_process|net|tls|dns|worker_threads|cluster)|next\/headers|server-only)['"]/gm)) {
      add({ ruleId: 29640, code: 'BUG-40', severity: 'HIGH', lineIdx: at(x.index! + x[0].search(/\S/)),
        title: `Server-Only Import in a Client Component: "${x[1]}"`,
        why: `"${x[1]}" only exists on the server. Bundling it for the browser fails the build (Module not found / "You're importing a component that needs ${x[1]}. That only works in a Server Component") or throws at runtime.`,
        fix: 'Move the server code into a Server Component, Route Handler or Server Action ("use server") and pass the result to this component as props.' });
    }
    for (const x of c.matchAll(/^\s*import\s*\{([^}]*)\}\s*from\s*['"]next\/cache['"]/gm)) {
      const n = /\b(revalidatePath|revalidateTag|updateTag|unstable_cache|cacheTag|cacheLife)\b/.exec(x[1]);
      if (!n) continue;
      add({ ruleId: 29640, code: 'BUG-40', severity: 'HIGH', lineIdx: at(x.index! + x[0].search(/\S/)),
        title: `Server-Only Import in a Client Component: ${n[1]}`,
        why: `${n[1]} works only on the server (it needs the request's cache store); called from a client component it throws an invariant error and nothing is revalidated.`,
        fix: `Call ${n[1]} inside a Server Action ("use server") and invoke that action from the client.` });
    }
    // BUG-41: redirect() / notFound() inside a client event handler
    const navImport = /import\s*\{([^}]*)\}\s*from\s*['"]next\/navigation['"]/.exec(c);
    const navFns = navImport ? ['redirect', 'permanentRedirect', 'notFound'].filter((f) => new RegExp(`(?:^|[\\s,{])${f}\\b(?!\\s+as\\b)`).test(navImport[1])) : [];
    if (navFns.length) {
      for (const x of m.matchAll(new RegExp(`(?<![\\w$.])(${navFns.join('|')})\\s*\\(`, 'g'))) {
        const pos = x.index!;
        if (!compAt(pos)) continue;
        const r = regionsAll.filter((g) => g.kind === 'deferred' && g.start <= pos && pos < g.end && g.start > compAt(pos)!.open);
        if (!r.length) continue;
        const outer = r.sort((a, b) => a.start - b.start)[0];
        const head = m.slice(Math.max(0, outer.head - 60), outer.start);
        if (!/\bon[A-Z]\w*\s*=\s*\{[^{}]*$|\b(?:handle|on)[A-Z]\w*\s*(?:=|\(|:)|\bfunction\s+(?:handle|on)[A-Z]\w*/.test(head)) continue;
        add({ ruleId: 29641, code: 'BUG-41', severity: 'HIGH', lineIdx: at(pos),
          title: `${x[1]}() Called From a Client Event Handler`,
          why: `${x[1]}() works during rendering and in Server Actions, not in client event handlers: it throws a NEXT_REDIRECT / NEXT_NOT_FOUND error outside React's render, so the user is not navigated and an uncaught error is logged.`,
          fix: x[1] === 'notFound' ? 'Navigate with router.push("/404") or render a not-found state instead.' : 'Use const router = useRouter() (next/navigation) and router.push(url) / router.replace(url) in the handler, or redirect inside the Server Action the handler calls.' });
      }
    }
  }

  // BUG-42: Pages Router useRouter inside the app directory
  if (inApp && (isClient || appEntry)) {
    const x = /^\s*import\s+(?:\w+\s*,\s*)?(?:\{[^}]*\b(?:useRouter|withRouter)\b[^}]*\}|\w+)\s+from\s+['"]next\/router['"]/m.exec(c);
    if (x) {
      add({ ruleId: 29642, code: 'BUG-42', severity: 'HIGH', lineIdx: at(x.index! + x[0].search(/\S/)),
        title: 'next/router Imported in the App Router',
        why: 'The app directory has no Pages Router context: useRouter from next/router throws "NextRouter was not mounted" and the page crashes on load.',
        fix: 'Import from next/navigation: useRouter() for push/replace, usePathname() for the path and useSearchParams() for the query.' });
    }
  }

  // BUG-54: Pages Router API used on the next/navigation router
  if (/import\s*\{[^}]*\buseRouter\b[^}]*\}\s*from\s*['"]next\/navigation['"]/.test(c)) {
    for (const r of m.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*useRouter\s*\(\s*\)/g)) {
      const rv = esc(r[1]);
      for (const x of m.matchAll(new RegExp(`\\b${rv}\\s*\\.\\s*(?:(push|replace|prefetch)\\s*\\(\\s*\\{|(query|isReady|pathname|asPath|events|locale|basePath|route)\\b(?!\\s*\\())`, 'g'))) {
        const what = x[1] ? `${x[1]}({ ... })` : x[2];
        add({ ruleId: 29654, code: 'BUG-54', severity: 'HIGH', lineIdx: at(x.index!),
          title: `router.${what} Does Not Exist on the next/navigation Router`,
          why: x[1]
            ? `The App Router's router.${x[1]} takes a URL string; an object { pathname, query } is stringified, so the user is sent to "/[object Object]" (404).`
            : `The App Router's router has no ${x[2]} property (that was next/router), so it is undefined: query values, redirects and isReady checks built on it never work.`,
          fix: x[1] ? `Build the URL string: router.${x[1]}(\`/search?\${new URLSearchParams({ q }).toString()}\`).` : 'Use useSearchParams() for query values and usePathname() for the path.' });
      }
    }
  }

  // BUG-55: Pages Router data functions in the app directory
  if (appEntry) {
    for (const x of m.matchAll(/^export\s+(?:async\s+)?(?:function|const)\s+(getServerSideProps|getStaticProps|getStaticPaths|getInitialProps)\b/gm)) {
      add({ ruleId: 29655, code: 'BUG-55', severity: 'HIGH', lineIdx: at(x.index!),
        title: `${x[1]} in the App Router`,
        why: `The app directory does not call ${x[1]}: Next.js fails the build ("${x[1]}" is not supported in app/) and, even if it compiled, the page would never receive those props.`,
        fix: 'Fetch data directly in the async Server Component (const data = await getData()), and use generateStaticParams instead of getStaticPaths.' });
    }
  }

  // BUG-43 / BUG-56: route handler mistakes
  if (inApp && /(?:^|\/)route\.[jt]s$/.test(path)) {
    const dflt = /^export\s+default\s+(?:async\s+)?function\b/m.exec(m);
    const pagesSig = /^export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(\s*\w+\s*(?::\s*\w+)?\s*,\s*res\b/m.exec(m);
    const hit = dflt || pagesSig;
    if (hit) {
      add({ ruleId: 29656, code: 'BUG-56', severity: 'HIGH', lineIdx: at(hit.index),
        title: dflt ? 'Route Handler Uses a Default Export (Every Request Gets 405)' : 'Route Handler Uses the Pages API (req, res) Signature',
        why: dflt
          ? 'App Router route.ts files only call named exports GET / POST / PUT / PATCH / DELETE; a default export is ignored, so every request returns 405 Method Not Allowed.'
          : 'App Router handlers receive (request, { params }) and must return a Response; res is not a response object, so res.status(...) throws and the endpoint returns 500.',
        fix: 'export async function POST(request: Request) { const body = await request.json(); return Response.json({ ok: true }); }' });
    }
    if (/^export\s+const\s+dynamic\s*=\s*['"]force-static['"]/m.test(c)) {
      const g = /^export\s+(?:async\s+)?function\s+GET\s*\(\s*(\w*)/m.exec(m) || /^export\s+const\s+GET\s*=\s*(?:async\s*)?\(\s*(\w*)/m.exec(m);
      if (g) {
        const reads = new RegExp(`(?:${g[1] ? `\\b${esc(g[1])}\\s*\\.\\s*(?:headers|cookies|nextUrl|url)\\b|` : ''}\\b(?:cookies|headers)\\s*\\(\\s*\\)|\\bsearchParams\\b)`).exec(m.slice(g.index));
        if (reads) {
          add({ ruleId: 29643, code: 'BUG-43', severity: 'HIGH', lineIdx: at(g.index + reads.index),
            title: 'force-static Route Handler Reads the Request',
            why: 'With dynamic = "force-static" the GET handler runs once at build time: headers(), cookies() and search params are empty, so every caller receives the same build-time response and the per-request logic never runs.',
            fix: 'Remove dynamic = "force-static" (or use "force-dynamic") for handlers that depend on the request, or move request-specific values into the path with generateStaticParams.' });
        }
      }
    }
  }

  // BUG-57: middleware / proxy placed inside app/ or pages/ (Next.js never loads it)
  if (/(?:^|\/)(?:app|pages)\/(?:.*\/)?(?:middleware|proxy)\.[jt]s$/.test(path)) {
    const x = /^export\s+(?:default\s+)?(?:async\s+)?function\s*(?:middleware|proxy)?\b|^export\s+const\s+config\s*=\s*\{[^}]*\bmatcher\b/m.exec(m);
    if (x && /\b(?:NextResponse|NextRequest|matcher)\b/.test(c)) {
      add({ ruleId: 29657, code: 'BUG-57', severity: 'HIGH', lineIdx: at(x.index),
        title: `${/proxy\./.test(path) ? 'proxy' : 'middleware'} File Inside ${/(?:^|\/)app\//.test(path) ? 'app/' : 'pages/'} Never Runs`,
        why: 'Next.js only loads middleware.ts / proxy.ts from the project root (or src/). In this folder it is an ordinary module that nothing calls, so the auth redirects, rewrites and headers it defines are silently skipped for every request.',
        fix: 'Move the file to the project root (next to app/ or in src/ when using src/app) and keep the matcher config.' });
    }
  }

  // BUG-44: "use server" file exporting something other than an async function
  if (isServerFile) {
    for (const x of m.matchAll(/^export\s+(default\s+)?(?:(async\s+)?function\b\s*(\w*)|(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*([^\n;]{0,40})|class\s+(\w+)|enum\s+(\w+))/gm)) {
      const name = x[3] || x[4] || x[6] || x[7] || 'default';
      if (x[2]) continue;
      if (x[4] !== undefined) {
        const v = x[5].trim();
        if (/^async\b/.test(v) || /^\w[\w.]*\s*\(/.test(v) || /^\w+$/.test(v)) continue; // async fn, wrapper call result, alias
      }
      add({ ruleId: 29644, code: 'BUG-44', severity: 'HIGH', lineIdx: at(x.index!),
        title: `"use server" File Exports Non-Async ${name}`,
        why: `Every export of a "use server" module becomes a Server Action, so Next.js only allows async functions there: exporting ${name} fails the build / module load with "Only async functions are allowed to be exported in a \\"use server\\" file", taking every action in the file down with it.`,
        fix: `Make it an async function, or move ${name} (constants, schemas, types, sync helpers) into a separate module without "use server".` });
    }
  }

  // BUG-45: directive placed after imports is ignored
  {
    const firstCode = /^\s*(\S[^\n]*)/.exec(c)?.[1] || '';
    if (/^import\b/.test(firstCode)) {
      const d = /^(['"])use (client|server)\1;?[ \t]*$/m.exec(c);
      if (d) {
        add({ ruleId: 29645, code: 'BUG-45', severity: 'HIGH', lineIdx: at(d.index),
          title: `"use ${d[2]}" Is Not the First Statement, So It Is Ignored`,
          why: `Directives only work before any other statement. Below the imports this "use ${d[2]}" is a plain string expression, so the file stays a ${d[2] === 'client' ? 'Server Component: hooks and onClick handlers fail with "useState only works in Client Components" / "Event handlers cannot be passed"' : 'normal module: its functions are not Server Actions and calling them from the client fails'}.`,
          fix: `Move "use ${d[2]}" to the very first line of the file, above all imports.` });
      }
    }
  }

  // BUG-46: hooks or inline event handlers in a Server Component page / layout
  // Without Next.js in the repo (a Vite app, say) a page.tsx is a plain client file
  if (appEntry && !isClient && !isServerFile && !/(?:^|\/)loading\.[jt]sx?$/.test(path) && !(context && context.packageMajors.size > 0 && !context.packageMajors.has('next'))) {
    const h = /(?<![\w$.])(useState|useEffect|useLayoutEffect|useReducer|useRef|useContext|useRouter|usePathname|useSearchParams)\s*\(/.exec(m);
    if (h) {
      add({ ruleId: 29646, code: 'BUG-46', severity: 'HIGH', lineIdx: at(h.index),
        title: `Client-Only Code in a Server Component: ${h[1]}()`,
        why: `Files in app/ are Server Components unless they start with "use client"; ${h[1]} only works in Client Components, so the build fails ("You're importing a component that needs ${h[1]}").`,
        fix: 'Move the interactive part into its own "use client" component and render it from this page, or add "use client" as the first line if the whole page must be interactive.' });
    } else {
      for (const x of m.matchAll(/<([a-z][\w-]*)\b[^<>]*?\s(on[A-Z]\w*)\s*=\s*\{\s*(?:async\s*)?(?:\([^()]*\)|\w+)\s*=>/g)) {
        const o = x.index! + x[0].length;
        const region = c.slice(o, o + 200);
        if (/['"]use server['"]/.test(region)) continue;
        add({ ruleId: 29646, code: 'BUG-46', severity: 'HIGH', lineIdx: at(x.index! + x[0].indexOf(x[2])),
          title: `Client-Only Code in a Server Component: ${x[2]} on <${x[1]}>`,
          why: 'Server Components cannot send functions to the browser: rendering this page throws "Event handlers cannot be passed to Client Component props" and the page fails.',
          fix: 'Move the element into a "use client" component, or use a <form action={serverAction}> for mutations.' });
        break;
      }
    }
  }

  // BUG-47: error boundary file that is not a client component
  if (inApp && /(?:^|\/)(?:global-)?error\.[jt]sx?$/.test(path) && !isClient) {
    const x = /^export\s+default\b/m.exec(m);
    if (x) {
      add({ ruleId: 29647, code: 'BUG-47', severity: 'HIGH', lineIdx: at(x.index),
        title: `${/global-error/.test(path) ? 'global-error' : 'error'} File Without "use client"`,
        why: 'Error boundaries must be Client Components: Next.js fails the build with "error.tsx must be a Client Component", so the route has no error UI at all.',
        fix: 'Add "use client" as the first line of the file.' });
    }
  }

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `bug${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'VIBECARE',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'Logic Bug',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false
    });
    logs.push(`[${ts}] [BUG] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
