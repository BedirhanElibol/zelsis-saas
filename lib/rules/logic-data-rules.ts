/**
 * Data, async, money, time and auth-flow logic bugs in AI-written code (BUG-60.., Rule IDs 29660-29699).
 *
 * Reliability findings (type VIBECARE), like logic-bug-rules.ts: the code runs but silently loses data, charges the
 * wrong amount or breaks a flow. Every rule matches a specific, provable mistake on the reported line (MDN, Stripe,
 * Supabase, Prisma and Python docs); none fires on the mere absence of a call somewhere in the file.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }
interface Fn { start: number; end: number; isAsync: boolean }

const CAT = 'Logic Bug';

/** Index just past the bracket that closes the one at `open` ('(' '{' '['), skipping strings and template literals. */
function closeOf(src: string, open: number): number {
  const pair: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      for (i++; i < src.length && src[i] !== ch; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (pair[ch]) stack.push(pair[ch]);
    else if (ch === stack[stack.length - 1]) {
      stack.pop();
      if (!stack.length) return i + 1;
    }
  }
  return -1;
}

/** Splits the arguments of the call whose '(' is at `open` at top-level commas. */
function callArgs(src: string, open: number): { args: string[]; end: number } {
  const end = closeOf(src, open);
  if (end === -1) return { args: [], end: -1 };
  const inner = src.slice(open + 1, end - 1);
  const args: string[] = [];
  let depth = 0, start = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < inner.length && inner[i] !== ch; i++) if (inner[i] === '\\') i++; continue; }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) { args.push(inner.slice(start, i)); start = i + 1; }
  }
  if (inner.slice(start).trim()) args.push(inner.slice(start));
  return { args, end };
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const NOT_FN = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'return', 'typeof', 'await', 'new', 'else', 'do', 'try', 'finally', 'in', 'of']);

/** Bodies of function declarations, methods and arrow functions with a block body. */
function functionBodies(c: string): Fn[] {
  const out: Fn[] = [];
  for (let i = c.indexOf('{'); i !== -1; i = c.indexOf('{', i + 1)) {
    let j = i - 1;
    while (j >= 0 && /\s/.test(c[j])) j--;
    let isAsync: boolean;
    if (c[j] === '>' && c[j - 1] === '=') {
      const head = c.slice(Math.max(0, j - 400), j - 1);
      isAsync = /\basync\s*(?:\((?:[^()]|\([^()]*\))*\)|\w+)\s*(?::\s*[^=()]+)?\s*$/.test(head);
    } else {
      if (c[j] !== ')') {
        const m = /\)\s*:\s*[\w.<>[\]|,\s]+$/.exec(c.slice(Math.max(0, j - 120), j + 1));
        if (!m) continue;
        j = j + 1 - m[0].length;
      }
      let depth = 0, k = j;
      for (; k >= 0; k--) {
        if (c[k] === ')') depth++;
        else if (c[k] === '(' && --depth === 0) break;
      }
      if (k < 0) continue;
      const before = c.slice(Math.max(0, k - 80), k);
      const w = /(\w+)\s*$/.exec(before);
      if (!w || NOT_FN.has(w[1])) continue;
      isAsync = /\basync\s+(?:function\s*\*?\s*\w*|\*?\s*\w+)\s*$/.test(before);
    }
    const end = closeOf(c, i);
    if (end !== -1) out.push({ start: i, end, isAsync });
  }
  return out;
}

const SKIP_PATH = /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|fixtures?|__mocks__)\/|\.(?:test|spec|stories)\.[jt]sx?$|_test\.py$|(?:^|\/)test_\w+\.py$/i;

export function evaluateLogicDataRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const isJs = /\.[cm]?[jt]sx?$/i.test(path);
  const isPy = /\.py$/i.test(path);
  if ((!isJs && !isPy) || SKIP_PATH.test(path)) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };

  if (isJs) evaluateJs(path, cleanContent, add);
  else evaluatePy(lines, add);

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
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim(),
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

const MONEY_FIELD = /(?:balance|credit|stock|inventory|quantity|qty|token|coin|point|seat|wallet|funds|amount|remaining|quota|usage)/i;
const MONEY_NAME = /(?:price|tax|fee|shipping|total|amount|subtotal|cost|discount|tip|vat|charge)/i;
const DATE_FIELDS = 'current_period_end|current_period_start|trial_end|trial_start|cancel_at|canceled_at|ended_at|created|start_date|billing_cycle_anchor|period_end|period_start|due_date|expires_at';

function evaluateJs(path: string, c: string, add: (h: Hit) => void) {
  const cl = c.split('\n');
  const starts: number[] = [0];
  for (let i = 0; i < c.length; i++) if (c[i] === '\n') starts.push(i + 1);
  const lineAt = (off: number) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo;
  };
  let fnCache: Fn[] | null = null;
  const fns = () => (fnCache ??= functionBodies(c));
  const enclosing = (off: number): Fn | undefined => {
    let best: Fn | undefined;
    for (const f of fns()) if (f.start < off && off < f.end && (!best || f.start > best.start)) best = f;
    return best;
  };
  /** Text of the enclosing function from `off` to its end (or to the end of the file at top level). */
  const restOfFn = (off: number) => c.slice(off, enclosing(off)?.end ?? c.length);
  /** Variables holding a Date object: const x = new Date(...); with nothing chained after the call. */
  const pureDateVars = () => new Set([...c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*new Date\(/g)]
    .filter((m) => { const end = closeOf(c, m.index! + m[0].length - 1); return end !== -1 && /^\s*(?:;|,|\n|\r|$)/.test(c.slice(end, end + 2)); })
    .map((m) => m[1]));
  /** Names of the calls whose argument lists enclose `off` (innermost first), e.g. ['create'] for stripe.x.create({ amount }). */
  const callChain = (off: number) => {
    const names: string[] = [];
    let depth = 0;
    for (let k = off - 1; k >= 0 && k > off - 3000 && names.length < 6; k--) {
      const ch = c[k];
      if (ch === ')' || ch === '}' || ch === ']') depth++;
      else if (ch === '(' || ch === '{' || ch === '[') {
        if (depth) { depth--; continue; }
        if (ch === '(') names.push(/([\w$]+)\s*$/.exec(c.slice(Math.max(0, k - 60), k))?.[1] ?? '');
      }
    }
    return names;
  };
  const prevCode = (i: number) => cl.slice(0, i).reverse().find((x) => x.trim()) || '';

  const serverFile = /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]s$|(?:^|\/)pages\/api\/|(?:^|\/)(?:api|actions|webhooks?)\//i.test(path) || /^\s*['"]use server['"]/m.test(c);
  const clientFile = /^\s*['"]use client['"]/m.test(c) || (/\.[jt]sx$/i.test(path) && /\buse(?:State|Effect)\s*\(/.test(c));
  const paymentFile = /\bstripe\b|polar|lemon_?squeezy|razorpay|paddle|paypal/i.test(c);

  // BUG-60: email / payment SDK call or mutating fetch not awaited in a serverless handler
  if (serverFile) {
    const SDK = /^\s*((?:\w*[Rr]esend\w*)\.(?:emails|batch)\.send|stripe\.\w+(?:\.\w+)?\.(?:create|update|del|cancel|capture|confirm|pay|finalizeInvoice|voidInvoice|sendInvoice)|(?:transporter|mailer|mailTransport\w*)\.sendMail|sgMail\.send(?:Multiple)?|\w*[Tt]wilio\w*\.messages\.create|fetch)\s*\(/;
    cl.forEach((l, i) => {
      const m = SDK.exec(l);
      if (!m) return;
      if (/[[,(]\s*$|=>\s*$|=\s*$|\b(?:return|await|void)\s*$/.test(prevCode(i))) return;
      const off = starts[i] + l.indexOf(m[1]);
      const open = off + m[1].length + (l.slice(l.indexOf(m[1]) + m[1].length).indexOf('('));
      const { args, end } = callArgs(c, open);
      if (end === -1) return;
      if (m[1] === 'fetch' && !/\bmethod\s*:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/i.test(args.slice(1).join(','))) return;
      if (/^\s*\.(?:then|catch|finally)\b/.test(c.slice(end, end + 50))) return;
      const fn = enclosing(off);
      if (!fn?.isAsync) return;
      add({ ruleId: 29660, code: 'BUG-60', severity: 'HIGH', category: CAT, lineIdx: i,
        title: `${m[1]}() Is Not Awaited in a Serverless Handler`,
        why: `On Vercel / serverless runtimes the function is frozen as soon as the response is returned. ${m[1]}() is started but never awaited, so the email, charge or request is often never sent, and if it fails the error is an unhandled rejection nobody sees.`,
        fix: `Await it and handle the error: const { error } = await ${m[1]}(...); or, to run it after the response, wrap it in after(() => ...) (next/server) / waitUntil(...).` });
    });
  }

  // Local async function names (used by BUG-61 and BUG-65)
  const asyncNames = new Set<string>();
  for (const m of c.matchAll(/\basync\s+function\s*\*?\s*(\w+)|\b(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*async\b/g)) asyncNames.add(m[1] || m[2]);
  for (const n of [...asyncNames]) {
    if (new RegExp(String.raw`(?<!async\s+)function\s+${n}\s*\(|\b(?:const|let|var)\s+${n}\s*=\s*(?!async\b)(?:\(|function)`).test(c)) asyncNames.delete(n);
  }

  // BUG-61: return of an un-awaited promise inside try: the catch never sees its rejection
  for (const m of c.matchAll(/\btry\s*\{/g)) {
    const open = m.index! + m[0].length - 1;
    const end = closeOf(c, open);
    if (end === -1) continue;
    if (!/^\s*catch\s*(?:\([^)]*\))?\s*\{\s*[^\s}]/.test(c.slice(end, end + 200))) continue;
    const tryFn = enclosing(open);
    if (!tryFn?.isAsync) continue;
    const body = c.slice(open, end);
    const local = [...asyncNames].map(esc).join('|');
    const re = new RegExp(String.raw`\breturn\s+((?:fetch|axios(?:\.\w+)?|prisma\.\w+\.\w+|stripe\.\w+(?:\.\w+)?\.\w+|\w*[Rr]esend\w*\.emails\.send${local ? `|${local}` : ''}))\s*\(`, 'g');
    for (const r of body.matchAll(re)) {
      const off = open + r.index!;
      if (enclosing(off) !== tryFn) continue;
      // A recursive retry has the same try/catch inside it
      if (new RegExp(String.raw`\b${esc(r[1])}\b[^{]*$`).test(c.slice(Math.max(0, tryFn.start - 200), tryFn.start))) continue;
      add({ ruleId: 29661, code: 'BUG-61', severity: 'MEDIUM', category: CAT, lineIdx: lineAt(off),
        title: 'Promise Returned Without await Inside try: catch Never Runs',
        why: `return ${r[1]}(...) hands the pending promise to the caller and leaves the try block immediately, so if it rejects the catch block (logging, fallback, error response) is skipped and the error escapes to the caller.`,
        fix: `Await it inside the try: return await ${r[1]}(...);` });
    }
  }

  // BUG-62: array of promises from .map(async) used as data
  for (const m of c.matchAll(/\b(?:NextResponse|Response)\.json\(\s*[\w.?]+\.map\(\s*async\b|\bres\.(?:json|send)\(\s*[\w.?]+\.map\(\s*async\b|\bset[A-Z]\w*\(\s*[\w.?]+\.map\(\s*async\b/g)) {
    add({ ruleId: 29662, code: 'BUG-62', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
      title: '.map(async ...) Result Used as Data Without Promise.all',
      why: 'An async callback makes .map() return an array of pending Promises. That array is serialized or stored as is, so the client receives [{}, {}] (or Promise objects) instead of the values.',
      fix: 'Wait for the values first: const items = await Promise.all(list.map(async (x) => ...));' });
  }
  for (const m of c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(?!await\b)[\w.?]+\.map\(\s*async\b/g)) {
    const v = esc(m[1]);
    const rest = restOfFn(m.index!).slice(m[0].length);
    if (new RegExp(String.raw`Promise\.(?:all|allSettled|any|race)\(\s*(?:\[\s*\.\.\.)?${v}\b|for\s+await\s*\([^)]*\bof\s+${v}\b|\breturn\s+${v}\b|\bawait\s+${v}\b`).test(rest)) continue;
    const use = new RegExp(String.raw`\b(?:json|send|set[A-Z]\w*|JSON\.stringify)\(\s*(?:\{[^}]*\b)?${v}\b|\b${v}\s*\.\s*(?:length|filter|find|some|every|reduce|join|sort)\b|\b${v}\s*\[\s*\d+\s*\]\s*\.`).exec(rest);
    if (!use) continue;
    add({ ruleId: 29662, code: 'BUG-62', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
      title: '.map(async ...) Result Used as Data Without Promise.all',
      why: `${m[1]} is an array of pending Promises because the .map callback is async; it is later used as data (${use[0].trim()}), so every element is a Promise object instead of the result.`,
      fix: `const ${m[1]} = await Promise.all(list.map(async (x) => ...));` });
  }

  // BUG-63: async predicate in filter / some / every / find: a Promise is always truthy
  cl.forEach((l, i) => {
    const m = /\.(filter|some|every|find|findIndex|findLast)\(\s*async\b/.exec(l);
    if (!m) return;
    const effect = { filter: 'keeps every item', some: 'is always true', every: 'is always true', find: 'always returns the first item', findIndex: 'always returns 0', findLast: 'always returns the last item' }[m[1]];
    add({ ruleId: 29663, code: 'BUG-63', severity: 'HIGH', category: CAT, lineIdx: i,
      title: `async Callback in .${m[1]}() Is Always Truthy`,
      why: `.${m[1]}() does not await its callback: an async callback returns a Promise, which is truthy, so the call ${effect} regardless of the awaited condition (e.g. a permission or availability check is skipped).`,
      fix: `Resolve the conditions first: const flags = await Promise.all(items.map(async (x) => check(x))); const result = items.${m[1]}((_, i) => flags[i]);` });
  });

  // BUG-64: async reducer whose accumulator is a Promise from the second iteration on
  for (const m of c.matchAll(/\.reduce\(\s*async\s*\(\s*(\w+)/g)) {
    const { args, end } = callArgs(c, m.index! + m[0].indexOf('('));
    if (end === -1 || !args.length) continue;
    const acc = esc(m[1]);
    if (new RegExp(String.raw`await\s+${acc}\b`).test(args[0])) continue;
    if (!new RegExp(String.raw`\b${acc}\s*(?:\.\s*\w+|\[)|\.\.\.${acc}\b`).test(args[0])) continue;
    add({ ruleId: 29664, code: 'BUG-64', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
      title: 'async reduce() Uses the Accumulator Without Awaiting It',
      why: `An async reducer returns a Promise, so from the second item on ${m[1]} is a Promise, not the object: properties set on it are lost and the final result is missing all but the last item.`,
      fix: `Await the accumulator first (const acc = await ${m[1]};) or use a for...of loop with await.` });
  }

  // BUG-65: async function called in a condition without await (Promise is always truthy)
  if (asyncNames.size) {
    const names = [...asyncNames].map(esc).join('|');
    const re = new RegExp(String.raw`(?:[(&|]\s*|!\s*)(${names})\s*\(`);
    cl.forEach((l, i) => {
      if (!/\b(?:if|while)\s*\(/.test(l)) return;
      const cond = l.slice(l.search(/\b(?:if|while)\s*\(/));
      const m = re.exec(cond);
      if (!m || /\bawait\s*$/.test(cond.slice(0, m.index + m[0].indexOf(m[1])))) return;
      add({ ruleId: 29665, code: 'BUG-65', severity: 'HIGH', category: CAT, lineIdx: i,
        title: `async ${m[1]}() Used in a Condition Without await`,
        why: `${m[1]} is declared async, so ${m[1]}(...) returns a Promise, which is always truthy: the condition never depends on the real answer (a !${m[1]}(...) guard never blocks, a positive check always passes).`,
        fix: `Await it: if (await ${m[1]}(...)) / if (!(await ${m[1]}(...))).` });
    });
  }

  // BUG-66: read-modify-write on a counter / balance in two queries (lost update under concurrency)
  {
    const READ = /\bconst\s*\{\s*data\s*:\s*(\w+)[^}]*\}\s*=\s*await\s+[\w.]+\s*\.from\([^)]*\)\s*\.select\(|\bconst\s+(\w+)\s*=\s*await\s+(?:prisma|db|tx|ctx\.db|ctx\.prisma)\.\w+\.find(?:Unique|First)(?:OrThrow)?\(|\bconst\s*\[\s*(\w+)\s*\]\s*=\s*await\s+(?:db|tx)\s*\.select\(/g;
    for (const m of c.matchAll(READ)) {
      const v = esc(m[1] || m[2] || m[3]);
      const rest = restOfFn(m.index!);
      const fnText = c.slice(enclosing(m.index!)?.start ?? 0, enclosing(m.index!)?.end ?? c.length);
      if (/FOR\s+UPDATE|isolationLevel\s*:\s*[\w.]*Serializable/i.test(fnText)) continue;
      const W = new RegExp(String.raw`\b(\w+)\s*:\s*(?:\(\s*)?${v}[?!]?\.(\w+)(?:\s*(?:\?\?|\|\|)\s*0\s*\))?\s*([-+])\s*(?![-+=])[\w.(]`, 'g');
      for (const w of rest.matchAll(W)) {
        if (w[1] !== w[2]) continue;
        const before = rest.slice(Math.max(0, w.index! - 300), w.index!);
        const call = Math.max(before.lastIndexOf('.update('), before.lastIndexOf('.upsert('), before.lastIndexOf('.set('));
        if (call === -1 || before.slice(call).includes(';')) continue;
        const after = rest.slice(w.index!, w.index! + 400);
        const f = esc(w[1]);
        if (new RegExp(String.raw`\.eq\(\s*['"]${f}['"]|where\s*:\s*\{[^}]*\b${f}\b`).test(after) || new RegExp(String.raw`where\s*:\s*\{[^}]*\b${f}\b`).test(before.slice(call))) continue;
        const money = MONEY_FIELD.test(w[1]);
        add({ ruleId: 29666, code: 'BUG-66', severity: money ? 'HIGH' : 'MEDIUM', category: CAT, lineIdx: lineAt(m.index! + w.index!),
          title: `${w[1]} Updated From a Stale Read (Lost Update Race)`,
          why: `${w[1]} is read in one query and written back as ${v}.${w[1]} ${w[3]} x in a second one. Two concurrent requests read the same value and the second write overwrites the first, so ${money ? 'credits are spent twice / stock is oversold' : 'increments are lost'}.`,
          fix: money
            ? `Do it atomically in the database: Prisma { ${w[1]}: { ${w[3] === '-' ? 'decrement' : 'increment'}: x } } with a where guard (${w[1]}: { gte: x }), or a Postgres function called via supabase.rpc() that runs UPDATE ... SET ${w[1]} = ${w[1]} ${w[3]} x WHERE ${w[1]} >= x.`
            : `Use an atomic update: Prisma { ${w[1]}: { increment: 1 } }, or supabase.rpc('increment_${w[1]}', ...) running UPDATE ... SET ${w[1]} = ${w[1]} + 1.` });
      }
    }
  }

  // BUG-67: .single() error path returns/throws before the "row not found" branch, which can never run
  for (const m of c.matchAll(/\bconst\s*\{([^}]*)\}\s*=\s*await\b[^;]*?\.single\(\s*\)/g)) {
    const d = /\bdata\s*:\s*(\w+)/.exec(m[1])?.[1] ?? (/\bdata\b/.test(m[1]) ? 'data' : '');
    const e = /\berror\s*:\s*(\w+)/.exec(m[1])?.[1] ?? (/\berror\b/.test(m[1]) ? 'error' : '');
    if (!d || !e) continue;
    const endOff = m.index! + m[0].length;
    const after = c.slice(endOff, starts[Math.min(starts.length - 1, lineAt(endOff) + 20)]);
    const errExit = new RegExp(String.raw`if\s*\(\s*${esc(e)}\s*\)\s*(?:\{[^}]*?\b(?:throw|return)\b|(?:throw|return)\b)`).exec(after);
    if (!errExit) continue;
    const nullBr = new RegExp(String.raw`if\s*\(\s*!\s*${esc(d)}\s*\)\s*`).exec(after);
    if (!nullBr || nullBr.index < errExit.index) continue;
    const bStart = nullBr.index + nullBr[0].length;
    const body = after[bStart] === '{' ? after.slice(bStart, closeOf(after, bStart)) : after.slice(bStart).split('\n')[0];
    if (!body || /\bthrow\b|notFound\(|error|status\s*:\s*4|\b40[134]\b|unauthori[sz]ed|forbidden/i.test(body)) continue;
    add({ ruleId: 29667, code: 'BUG-67', severity: 'MEDIUM', category: CAT, lineIdx: lineAt(m.index! + m[0].length - 1),
      title: '.single() Errors on 0 Rows, So the "Not Found" Branch Never Runs',
      why: `.single() returns an error (PGRST116) when no row matches, and the error check above exits first, so the if (!${d}) branch that handles a missing row (first visit, new user, empty state) is unreachable and those users get the error path instead.`,
      fix: 'Use .maybeSingle(), which returns data: null without an error when there is no row, and keep the error check for real failures.' });
  }

  // BUG-68: Supabase write where only data is destructured (error dropped) and data is then used
  for (const m of c.matchAll(/\bconst\s*\{\s*data\s*(?::\s*(\w+))?\s*\}\s*=\s*await\s+[\w.]+(?:\s*\.\s*schema\([^)]*\))?\s*\.from\(\s*['"`][\w.-]+['"`]\s*\)\s*\.(insert|update|upsert|delete)\s*\(/g)) {
    const v = esc(m[1] || 'data');
    const rest = restOfFn(m.index!).slice(m[0].length);
    if (new RegExp(String.raw`!\s*${v}\b|\b${v}\s*(?:===?|!==?)\s*(?:null|undefined)|\b${v}\s*\?\?`).test(rest)) continue;
    const use = new RegExp(String.raw`\b${v}\s*!?\s*(?:\.|\[)\s*\w|\b(?:json|send)\(\s*${v}\b|\breturn\s+${v}\b`).exec(rest);
    if (!use) continue;
    add({ ruleId: 29668, code: 'BUG-68', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
      title: `Supabase ${m[2]}() Error Is Discarded but Its data Is Used`,
      why: `Only data is destructured from the ${m[2]}, so a failed write (RLS denial, constraint violation, network error) is invisible: data is null and the code continues as if the row was written (${use[0].trim()}), reporting success or crashing later with a misleading TypeError.`,
      fix: `Destructure and check the error: const { data, error } = await supabase.from(...).${m[2]}(...).select(); if (error) throw error;` });
  }

  // BUG-69 / BUG-70: dollar amount converted to cents unsafely for a payment API
  if (paymentFile) {
    cl.forEach((l, i) => {
      const m = /\b(unit_amount|unitAmount|amount|amount_cents|price_cents|priceAmount)\s*:\s*([^,\n}]*?)\s*\*\s*100\b(?!\s*\))/.exec(l);
      if (!m) return;
      // Only where the object goes to a create / charge call, not to a display formatter
      const chain = callChain(starts[i] + m.index);
      if (chain.some((n) => /format|construct|display|render|preview|label|text/i.test(n))) return;
      if (!chain.some((n) => /create|update|insert|upsert|charge|checkout|session|payment|price|coupon|invoice|subscri|post|fetch|send|mutate|execute|refund|transfer|payout|retrieve/i.test(n))) return;
      const expr = m[2].trim();
      const rounded = /^(?:Math\.(round|floor|ceil|trunc)|parseInt|Number\.parseInt)\s*\(\s*([^()]*(?:\([^()]*\)[^()]*)*)\)$/.exec(expr);
      if (rounded) {
        if (/\*/.test(rounded[2])) return;
        add({ ruleId: 29670, code: 'BUG-70', severity: 'HIGH', category: CAT, lineIdx: i,
          title: `${m[1]} Rounds to Whole Dollars Before Converting to Cents`,
          why: `${rounded[1] || 'parseInt'}(${rounded[2].trim()}) drops the cents before multiplying by 100, so $19.99 is charged as $${rounded[1] === 'ceil' ? '20.00' : rounded[1] === 'round' ? '20.00' : '19.00'}: every price with cents is charged wrong.`,
          fix: `Multiply first, then round: ${m[1]}: Math.round(${rounded[2].trim()} * 100).` });
        return;
      }
      if (/^Math\.(?:round|floor|ceil|trunc)\(|^\(?\s*\d+\s*\)?$/.test(expr)) return;
      // The operand right before "* 100" (a ternary or sum keeps only its last term)
      const op = /((?:[\w$.]+|\()(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?)\s*$/.exec(expr)?.[1] ?? expr;
      if (!/(?:price|amount|total|cost|fee|subtotal|dollars|parseFloat|toFixed|Number\()/i.test(op)) return;
      add({ ruleId: 29669, code: 'BUG-69', severity: 'HIGH', category: CAT, lineIdx: i,
        title: `${m[1]}: ${op} * 100 Is Not Rounded to an Integer`,
        why: `Floating point makes ${op} * 100 non-integer for many prices (19.99 * 100 = 1998.9999999999998, 0.29 * 100 = 28.999999999999996). Stripe and other payment APIs reject non-integer amounts ("Invalid integer"), so checkout fails for those prices, or truncation charges one cent less.`,
        fix: `Round after scaling: Math.round(${op} * 100), or store prices in cents as integers.` });
    });
  }

  // BUG-71: toFixed() string added to a number: + concatenates instead of adding
  cl.forEach((l, i) => {
    const a = /\.toFixed\(\s*\d?\s*\)\s*\+\s*(?![\s'"`])([\w.]+)/.exec(l);
    const b = /(?:^|[=,:?]\s*)([\w.]+)\s*\+\s*[\w.]+\.toFixed\(/.exec(l);
    const operand = a?.[1] ?? b?.[1];
    if (!operand || !MONEY_NAME.test(operand.split('.').pop() || '') || /['"`]/.test(l.slice(0, (a ?? b)!.index))) return;
    add({ ruleId: 29671, code: 'BUG-71', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: 'toFixed() String Added to a Number (Concatenation, Not Addition)',
      why: `toFixed() returns a string, so + ${operand} concatenates: 10.50 + 2 becomes "10.502". The total shown, stored or charged is wrong.`,
      fix: 'Add the numbers first and format once at the end: (subtotal + tax).toFixed(2); keep money in integer cents for arithmetic.' });
  });

  // BUG-72: string from an input / URL added to a number literal ("1" + 1 === "11")
  {
    const SRC = String.raw`(?:(?:e|ev|evt|event)\.(?:target|currentTarget)\.value|\w+Ref\.current\??\.value|document\.getElementById\([^)]*\)\.value|searchParams\??\.get\([^)]*\)|(?:req|request)\.query\.\w+|formData\.get\([^)]*\)|localStorage\.getItem\([^)]*\))`;
    const re = new RegExp(String.raw`(?:(?<![+\-\w.])${SRC}|(?<![\w$])\(\s*${SRC}\s*(?:\|\||\?\?)\s*[^()]*\))\s*\+\s*\d+(?:\.\d+)?(?![\w.'"\`])|(?<![\w.'"\`])\d+(?:\.\d+)?\s*\+\s*${SRC}`);
    cl.forEach((l, i) => {
      const m = re.exec(l);
      if (!m) return;
      add({ ruleId: 29672, code: 'BUG-72', severity: 'MEDIUM', category: CAT, lineIdx: i,
        title: 'Input String Added to a Number (String Concatenation)',
        why: `${m[0].trim()}: form values, URL params and storage values are strings, so + concatenates ("2" + 1 is "21"): quantities, page numbers and totals jump to wrong values.`,
        fix: 'Convert first: Number(value) + 1 (or parseInt(value, 10)) and handle NaN.' });
    });
  }

  // BUG-73 / BUG-74: Stripe webhook grants access or fulfills without checking the payment / subscription status
  if (/\bstripe\b/i.test(c)) {
    const blockAt = (idx: number) => {
      const rest = c.slice(idx);
      const brace = /^[^\n{]*\{/.exec(rest);
      if (/^\s*case\b/.test(rest) || !brace) {
        const stop = rest.slice(10).search(/\bcase\s+['"`]|\bdefault\s*:/);
        return rest.slice(0, stop === -1 ? 1500 : stop + 10);
      }
      const end = closeOf(c, idx + brace[0].length - 1);
      return c.slice(idx, end === -1 ? idx + 1500 : end);
    };
    for (const m of c.matchAll(/(?:\bcase\s*|===?\s*)['"`]checkout\.session\.completed['"`]/g)) {
      if (/payment_status|async_payment_succeeded/.test(c)) break;
      const block = blockAt(m.index!);
      if (/subscriptions\.retrieve|mode\s*[!=]==?\s*['"]subscription|\.subscription\b/.test(block)) continue;
      const g = /(?:credits?|balance|tokens?)\s*(?::\s*\{\s*increment|:\s*[\w.]+\s*\+)|\b(?:is_?paid|isPaid|has_?paid|hasPaid|paid)\s*:\s*true|\bstatus\s*:\s*['"](?:paid|completed|fulfilled)['"]|\b(?:fulfill|grant|deliver)\w*\s*\(/i.exec(block);
      if (!g) continue;
      add({ ruleId: 29673, code: 'BUG-73', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index! + g.index),
        title: 'checkout.session.completed Fulfilled Without Checking payment_status',
        why: "checkout.session.completed also fires when the customer chose a delayed payment method (SEPA, ACH, Boleto, bank transfer): the session is complete but payment_status is 'unpaid' and the payment can still fail. This handler fulfills on the event alone, so it delivers goods/credits that may never be paid.",
        fix: "Fulfill only when session.payment_status === 'paid', and handle checkout.session.async_payment_succeeded / async_payment_failed for the delayed case." });
    }
    for (const m of c.matchAll(/(?:\bcase\s*|===?\s*)['"`]customer\.subscription\.(?:created|updated)['"`]/g)) {
      const block = blockAt(m.index!);
      if (/\.status\b|\bstatus\s*[!=]==?|\{\s*status\s*[,}]|\bstatus\s*:\s*\w+\.status|\bstatus\s*,/.test(block)) continue;
      const g = /\b(?:is_?pro|isPro|is_?premium|isPremium|is_?subscribed|isSubscribed|has_?access|hasAccess|is_?active|isActive|is_?paid|isPaid)\s*:\s*true|\b(?:subscription_?status|subscriptionStatus|plan_?status|status)\s*:\s*['"]active['"]/.exec(block);
      if (!g) continue;
      add({ ruleId: 29674, code: 'BUG-74', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index! + g.index),
        title: 'Subscription Access Granted Without Checking subscription.status',
        why: "customer.subscription.created/updated fire for subscriptions that are incomplete (first payment failed or needs 3-D Secure), past_due, unpaid or canceled. Hard-coding active/true grants paid access to every one of them.",
        fix: "Derive access from the event: const active = ['active', 'trialing'].includes(subscription.status); store subscription.status instead of a literal." });
    }
  }

  // BUG-75: Stripe Unix timestamps (seconds) used as JavaScript milliseconds
  if (/\bstripe\b/i.test(c)) {
    const vars = new Set<string>();
    for (const m of c.matchAll(/\b(?:const|let|var)\s+(\w+)\s*(?::\s*Stripe\.[\w.]+)?\s*=\s*(?:await\s+)?(?:stripe\.\w+(?:\.\w+)?\.\w+\(|\w+\.data\.object\b|[^;\n]*\bas\s+Stripe\.[\w.]+)|\b(\w+)\s*:\s*Stripe\.(?:Subscription|Invoice|Checkout\.Session|PaymentIntent|Charge|Customer|Event|SubscriptionItem)\b/g)) vars.add(m[1] || m[2]);
    if (vars.size) {
      const v = [...vars].map(esc).join('|');
      const path = String.raw`(?:${v})(?:\??\.(?:[\w]+|data\[\d+\])|\[\d+\])*\??\.(?:${DATE_FIELDS})`;
      const re = new RegExp(String.raw`\b(?:new\s+Date|dayjs|moment)\(\s*(${path})\s*\)|\b(${path})\s*[<>]=?\s*(?:Date\.now\(\)|new Date\(\))|(?:Date\.now\(\)|new Date\(\))\s*[<>]=?\s*(${path})\b(?!\s*\*)`);
      cl.forEach((l, i) => {
        const m = re.exec(l);
        if (!m) return;
        const f = (m[1] || m[2] || m[3]).trim();
        add({ ruleId: 29675, code: 'BUG-75', severity: 'HIGH', category: CAT, lineIdx: i,
          title: `Stripe Timestamp ${f.split('.').pop()} (Seconds) Used as Milliseconds`,
          why: `Stripe timestamps are Unix seconds; JavaScript dates use milliseconds. ${f} used directly is 1000x too small: new Date(...) lands in January 1970 and comparisons with Date.now() treat every subscription as long expired.`,
          fix: `Multiply by 1000: new Date(${f} * 1000), or compare ${f} * 1000 with Date.now().` });
      });
    }
  }

  // BUG-76: date-only string parsed as UTC midnight, then read with local-time getters (off by one day)
  {
    const SRC = String.raw`new Date\(\s*(?:(['"])\d{4}-\d{2}-\d{2}\1|(?:e|ev|evt|event)\.target\.value)\s*\)`;
    const LOCAL = String.raw`\.(?:getDate|getDay|getMonth|getFullYear)\(\)|\.toLocaleDateString\((?![^)]*timeZone)`;
    const direct = new RegExp(SRC + `(?:${LOCAL})`);
    const assign = new RegExp(String.raw`\b(?:const|let)\s+(\w+)\s*=\s*` + SRC + String.raw`\s*;?\s*$`);
    const dateInput = /type\s*=\s*['"{]?\s*['"]?date['"]/.test(c) || /\d{4}-\d{2}-\d{2}/.test(c);
    cl.forEach((l, i) => {
      let hit = direct.test(l);
      const a = assign.exec(l);
      if (!hit && a) hit = new RegExp(String.raw`\b${esc(a[1])}(?:${LOCAL})`).test(restOfFn(starts[i]).slice(l.length));
      if (!hit || !dateInput) return;
      add({ ruleId: 29676, code: 'BUG-76', severity: 'MEDIUM', category: CAT, lineIdx: i,
        title: 'Date-Only String Parsed as UTC, Then Read in Local Time (Off by One Day)',
        why: "new Date('2024-03-15') is parsed as midnight UTC. getDate()/getDay()/toLocaleDateString() then read it in the user's time zone, so everyone west of UTC (the Americas) sees March 14: birthdays, bookings and due dates are a day early.",
        fix: "Parse the parts as a local date: const [y, m, d] = s.split('-').map(Number); new Date(y, m - 1, d); or use UTC getters / toLocaleDateString(undefined, { timeZone: 'UTC' })." });
    });
  }

  // BUG-77: getMonth() is 0-based (formatted without + 1, compared with 12, month 12 passed to new Date)
  cl.forEach((l, i) => {
    const m = /\.getMonth\(\)\s*\}\s*[-/.]|[-/.]\$\{\s*[\w.()]+\.getMonth\(\)\s*\}|\.getMonth\(\)\s*\+\s*['"`][-/.]|['"`][-/.]['"`]\s*\+\s*[\w.()]+\.getMonth\(\)|\.getMonth\(\)\s*[!=]==?\s*12\b|\(\s*[\w.()]+\.getMonth\(\)\s*\)\.padStart|\.getMonth\(\)\.toString\(\)\.padStart|\bnew Date\(\s*[\w.]+\s*,\s*12\s*[,)]/.exec(l);
    if (!m) return;
    add({ ruleId: 29677, code: 'BUG-77', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: 'getMonth() Is 0-Based (Month Off by One)',
      why: `${m[0].trim()}: Date months run 0-11 (January is 0), so this shows/compares the previous month (03/15 for April 15) or, with new Date(y, 12, d), silently rolls over to January of the next year.`,
      fix: 'Add 1 when displaying (d.getMonth() + 1), compare with 0-11, and pass month - 1 to new Date(); or format with Intl.DateTimeFormat / date-fns format().' });
  });

  // BUG-78: getDay() (weekday) used as day of month, getYear() (years since 1900)
  cl.forEach((l, i) => {
    const day = /\.getDay\(\)/.test(l) && /\.get(?:Month|FullYear)\(\)/.test(l) && /\.getDay\(\)\s*(?:\}\s*[-/.,]|\+\s*['"`][-/.])|[-/.]['"`]?\s*(?:\+\s*|\$\{\s*)[\w.()]+\.getDay\(\)/.test(l);
    const year = /\bnew Date\([^)]*\)\.getYear\(\)|\b(?:date|d|dt|now|today|day)\.getYear\(\)/.test(l);
    if (!day && !year) return;
    add({ ruleId: 29678, code: 'BUG-78', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: day ? 'getDay() Returns the Weekday, Not the Day of the Month' : 'getYear() Returns Years Since 1900',
      why: day ? 'getDay() is the day of the week (0 = Sunday ... 6), so the formatted date shows 0-6 instead of 1-31.' : 'Date.prototype.getYear() is deprecated and returns the year minus 1900 (125 for 2025), so the displayed or compared year is wrong.',
      fix: day ? 'Use getDate() for the day of the month.' : 'Use getFullYear().' });
  });

  // BUG-79: Date objects compared with == / === (compares references, always false)
  {
    const dateVars = pureDateVars();
    const dv = [...dateVars].map(esc).join('|');
    const pair = dv ? new RegExp(String.raw`\b(${dv})\s*[!=]==?\s*(${dv})\b(?!\s*[.(\[])`) : null;
    cl.forEach((l, i) => {
      // new Date(...) itself (not .getTime() of it) on one side of == / ===
      const direct = [...l.matchAll(/\bnew Date\(/g)].some((d) => {
        const end = closeOf(l, d.index! + d[0].length - 1);
        if (end === -1) return false;
        const after = l.slice(end);
        if (/^\s*\??\./.test(after)) return false;
        return /^\s*[!=]==?(?!\s*(?:null|undefined)\b)/.test(after) || /[!=]==?\s*$/.test(l.slice(0, d.index));
      });
      const p = pair?.exec(l);
      if (!direct && !(p && p[1] !== p[2])) return;
      add({ ruleId: 29679, code: 'BUG-79', severity: 'MEDIUM', category: CAT, lineIdx: i,
        title: 'Date Objects Compared With == / ===',
        why: 'Equality on Date objects compares object identity, not the moment in time, so two equal dates are never ===. The "same date" branch never runs (or != is always true).',
        fix: 'Compare timestamps: a.getTime() === b.getTime(), or compare calendar days with isSameDay() from date-fns.' });
    });
  }

  // BUG-80: toISOString() date used as "today" in the browser (UTC date, wrong near midnight)
  if (clientFile) {
    cl.forEach((l, i) => {
      if (!/\bnew Date\(\)\.toISOString\(\)\.(?:split\(\s*['"]T['"]\s*\)\[0\]|slice\(\s*0\s*,\s*10\s*\)|substring\(\s*0\s*,\s*10\s*\))/.test(l)) return;
      // Only where it becomes the date the user picks or sees as "today" (not a file name or log stamp)
      if (!/useState\(|\b(?:min|max|defaultValue|value)\s*[=:]|\btoday\w*\s*[=:]|\b(?:date|startDate|endDate|selectedDate|dueDate|fromDate|toDate)\s*[=:]/i.test(l)) return;
      add({ ruleId: 29680, code: 'BUG-80', severity: 'MEDIUM', category: CAT, lineIdx: i,
        title: "toISOString() Used as the User's Local Date",
        why: "toISOString() is in UTC, so in the browser \"today\" is yesterday for users west of UTC in the evening and tomorrow for users east of UTC after midnight: date pickers default to the wrong day and min/max dates block valid choices.",
        fix: "Build the local date: const d = new Date(); `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}` (or date-fns format(d, 'yyyy-MM-dd'))." });
    });
  }

  // BUG-81: a Date is mutated in place through set*() and the original is used afterwards
  {
    const SET = '(?:setDate|setMonth|setFullYear|setHours|setMinutes|setTime|setUTCDate|setUTCHours)';
    for (const m of c.matchAll(new RegExp(String.raw`\bnew Date\(\s*(\w+)\.${SET}\(`, 'g'))) {
      const v = esc(m[1]);
      const lineEnd = c.indexOf('\n', m.index!);
      const rest = restOfFn(m.index!).slice(lineEnd === -1 ? 0 : lineEnd - m.index!);
      if (!new RegExp(String.raw`(?<![\w.])${v}\b(?!\s*=[^=])`).test(rest)) continue;
      add({ ruleId: 29681, code: 'BUG-81', severity: 'MEDIUM', category: CAT, lineIdx: lineAt(m.index!),
        title: 'Date Mutated In Place, Then Used Again',
        why: `set*() changes ${m[1]} itself and returns a timestamp, so new Date(${m[1]}.setX(...)) also moves ${m[1]}; the later uses of ${m[1]} see the shifted date (start and end of a range become equal, "today" becomes tomorrow).`,
        fix: `Copy first: const next = new Date(${m[1]}); next.setDate(next.getDate() + 1); (or date-fns addDays(${m[1]}, 1)).` });
    }
    const dateVars = pureDateVars();
    for (const m of c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(\w+)\s*;/g)) {
      if (!dateVars.has(m[2])) continue;
      const rest = restOfFn(m.index!).slice(m[0].length);
      const mut = new RegExp(String.raw`\b${esc(m[1])}\.${SET}\(`).exec(rest);
      if (!mut || !new RegExp(String.raw`(?<![\w.])${esc(m[2])}\b`).test(rest)) continue;
      add({ ruleId: 29681, code: 'BUG-81', severity: 'MEDIUM', category: CAT, lineIdx: lineAt(m.index! + m[0].length + mut.index),
        title: 'Date Mutated In Place, Then Used Again',
        why: `const ${m[1]} = ${m[2]} copies the reference, not the date, so ${m[1]}.${mut[0].slice(m[1].length + 1, -1)}() also changes ${m[2]}: both ends of the range move together.`,
        fix: `Copy the date: const ${m[1]} = new Date(${m[2]});` });
    }
  }

  // BUG-82: auth user / session used without a null check right after it is fetched
  for (const m of c.matchAll(/\bconst\s*\{\s*data\s*:\s*\{\s*(user|session)\s*\}[^=]*=\s*await\s+[\w.]+\.auth\.(?:getUser|getSession)\(\)|\bconst\s+(session)\s*=\s*await\s+getServerSession\(/g)) {
    const v = m[1] || m[3];
    const from = m.index! + m[0].length;
    const startLine = lineAt(from) + 1;
    const fnEnd = lineAt(enclosing(m.index!)?.end ?? c.length);
    for (let i = startLine; i <= fnEnd && i < cl.length; i++) {
      const l = cl[i];
      if (!new RegExp(String.raw`\b${v}\b`).test(l)) continue;
      const guard = new RegExp(String.raw`!\s*${v}\b|\b${v}\s*(?:\?\.|&&|\|\||\?\?|[!=]==?|\?\s)|\bif\s*\(\s*${v}\b|redirect|\breturn\s+${v}\b|\b(?:typeof)\s+${v}`).test(l);
      const use = new RegExp(String.raw`\b${v}\s*!?\.(?!\?)\s*\w`).exec(l);
      if (!guard && use) {
        add({ ruleId: 29682, code: 'BUG-82', severity: 'MEDIUM', category: CAT, lineIdx: i,
          title: `${v} Used Without a Null Check After Fetching It`,
          why: `${v === 'session' ? 'The session' : 'getUser()'} returns null for logged-out visitors and expired sessions. ${use[0].trim()} is read before any check, so those visitors get a 500 (TypeError: Cannot read properties of null) instead of a redirect to sign-in.`,
          fix: `Guard first: if (!${v}) redirect('/login'); (or return a 401 from API routes), then use ${v}.` });
      }
      break;
    }
  }

  // BUG-83: email lowercased when stored but looked up case-sensitively
  if (/\.toLowerCase\(\)/.test(c)) {
    const lowerWrite = /\bemail\s*:\s*[\w.]+\.(?:trim\(\)\.)?toLowerCase\(\)/.test(c);
    if (lowerWrite) {
      const LOOK = /\.eq\(\s*['"]email['"]\s*,\s*([\w.]+)\s*\)|\.(?:findUnique|findFirst)\(\s*\{\s*where\s*:\s*\{\s*email\s*(?::\s*([\w.]+))?\s*\}/g;
      for (const m of c.matchAll(LOOK)) {
        const expr = m[1] || m[2] || 'email';
        // Only raw form / request input (provider profiles like user.email are outside the app's control)
        if (!/^(?:email|(?:credentials|body|input|values|data|parsed|form|formData|payload|req\.body)\.email)$/.test(expr)) continue;
        const base = esc(expr.split('.')[0]);
        if (new RegExp(String.raw`\b${base}\s*=\s*[^;\n]*toLowerCase\(\)`).test(c) || /toLowerCase/.test(expr)) continue;
        add({ ruleId: 29683, code: 'BUG-83', severity: 'MEDIUM', category: CAT, lineIdx: lineAt(m.index!),
          title: 'Email Stored Lowercased but Looked Up Case-Sensitively',
          why: `This file saves emails with toLowerCase() but looks them up with the raw ${expr}. A user who types Jane@Example.com at login or password reset gets "user not found", and the same person can create duplicate accounts.`,
          fix: `Normalize the lookup the same way: .eq('email', ${expr}.trim().toLowerCase()) (or use a citext column / ilike).` });
      }
    }
  }

  // BUG-84: numeric array sorted with the default (string) comparator
  cl.forEach((l, i) => {
    const named = /\b(\w*(?:[pP]rices|[sS]cores|[aA]mounts|[nN]umbers|[nN]ums|[tT]otals|[aA]ges|[rR]atings|[qQ]uantities|[cC]osts|[sS]alaries|[dD]urations|[wW]eights|[cC]ounts|[pP]ercentages))\.(sort|toSorted)\(\s*\)/.exec(l);
    const mapped = /\.map\(\s*(?:Number|parseFloat|parseInt|\(?\w+\)?\s*=>\s*(?:Number\(|parseFloat\(|parseInt\()?\w+\.(?:price|amount|score|total|count|age|rating|quantity|qty|cost|duration|weight)\)?)\s*\)\.(sort|toSorted)\(\s*\)/.exec(l);
    const m = named ?? mapped;
    if (!m) return;
    add({ ruleId: 29684, code: 'BUG-84', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: 'Numbers Sorted With the Default .sort() (Compared as Strings)',
      why: 'Without a comparator .sort() converts numbers to strings, so [5, 25, 100] sorts as [100, 25, 5]: cheapest/highest-score/median calculations pick the wrong item.',
      fix: 'Pass a numeric comparator: .sort((a, b) => a - b) (or b - a for descending).' });
  });

  // BUG-85: comparison with a fresh [] / {} literal, includes({...}): always false
  cl.forEach((l, i) => {
    const m = /[!=]==?\s*(?:\[\s*\]|\{\s*\})(?!\s*[\w.([])|(?<![\w)\]])(?:\[\s*\]|\{\s*\})\s*[!=]==?|\.(?:includes|indexOf)\(\s*\{/.exec(l);
    if (!m || /^\s*(?:import|export\s+type|type)\b/.test(l)) return;
    const inc = m[0].startsWith('.');
    add({ ruleId: 29685, code: 'BUG-85', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: inc ? '.includes() / .indexOf() With an Object Literal Never Matches' : 'Comparison With [] or {} Is Always False',
      why: inc ? 'Arrays compare objects by reference; a new object literal is never in the array, so the check is always false and duplicates are added / selections never match.' : 'A new [] or {} literal is a different object from every other value, so x === [] is always false (and !== always true): the empty-state check never fires.',
      fix: inc ? 'Match by key: list.some((x) => x.id === item.id).' : 'Check emptiness explicitly: arr.length === 0, Object.keys(obj).length === 0.' });
  });

  // BUG-86: typeof compared with a string typeof never returns
  cl.forEach((l, i) => {
    const m = /(?<!keyof\s+)\btypeof\s+[\w$]+(?:\??\.[\w$]+|\[[^\]]*\])*\s*[!=]==?\s*['"](\w+)['"]|['"](\w+)['"]\s*[!=]==?\s*typeof\b/.exec(l);
    const t = m?.[1] ?? m?.[2];
    if (!t || /^(?:undefined|object|boolean|number|bigint|string|symbol|function)$/.test(t)) return;
    add({ ruleId: 29686, code: 'BUG-86', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: `typeof Never Returns '${t}'`,
      why: `typeof only returns "undefined", "object", "boolean", "number", "bigint", "string", "symbol" or "function", so comparing with '${t}' is always false and that branch never runs.`,
      fix: t === 'array' ? 'Use Array.isArray(x).' : t === 'null' ? 'Use x === null.' : t === 'date' ? 'Use x instanceof Date.' : "Compare with a real typeof result (e.g. 'number' plus Number.isInteger)." });
  });

  // BUG-87: assignment instead of comparison inside if (...)
  cl.forEach((l, i) => {
    const m = /\bif\s*\(\s*!?\s*([\w$]+(?:(?:\?\.|\.)[\w$]+|\[[^\]]+\])*)\s*=(?![=>])\s*(['"][^'"]*['"]|true|false|null|-?\d+)\s*\)/.exec(l);
    if (!m) return;
    add({ ruleId: 29687, code: 'BUG-87', severity: 'HIGH', category: CAT, lineIdx: i,
      title: `Assignment ${m[1]} = ${m[2]} Inside if (Should Be ===)`,
      why: `A single = assigns: ${m[1]} is overwritten with ${m[2]} and the condition is the assigned value, so the branch ${/^(?:false|null|0|''|"")$/.test(m[2]) ? 'never' : 'always'} runs (a role check grants everyone, a status is silently changed).`,
      fix: `Compare instead: if (${m[1]} === ${m[2]}).` });
  });

  // BUG-88: Math.round(x * 100 / 100) rounds nothing (parenthesis in the wrong place)
  cl.forEach((l, i) => {
    const m = /\bMath\.round\(\s*([^()]+?)\s*\*\s*(10+)\s*\/\s*\2\s*\)/.exec(l);
    if (!m) return;
    add({ ruleId: 29688, code: 'BUG-88', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: `Math.round(x * ${m[2]} / ${m[2]}) Does Not Round to Decimals`,
      why: `The division is inside Math.round, so it rounds ${m[1].trim()} to a whole number instead of ${m[2].length - 1} decimals (12.345 becomes 12, not 12.35).`,
      fix: `Divide after rounding: Math.round(${m[1].trim()} * ${m[2]}) / ${m[2]}.` });
  });

  // BUG-89: Promise.all runs a delete and an insert on the same table in parallel
  for (const m of c.matchAll(/\bPromise\.all(?:Settled)?\(\s*\[/g)) {
    const open = m.index! + m[0].length - 1;
    const end = closeOf(c, open);
    if (end === -1) continue;
    const arr = c.slice(open, end);
    const sbDel = [...arr.matchAll(/\.from\(\s*['"`]([\w.-]+)['"`]\s*\)\s*\.delete\(/g)].map((x) => x[1]);
    const sbIns = [...arr.matchAll(/\.from\(\s*['"`]([\w.-]+)['"`]\s*\)\s*\.(?:insert|upsert)\(/g)].map((x) => x[1]);
    const orDel = [...arr.matchAll(/\b(?:prisma|db)\.(\w+)\.delete(?:Many)?\(/g)].map((x) => x[1]);
    const orIns = [...arr.matchAll(/\b(?:prisma|db|tx)\.(\w+)\.(?:create|createMany|upsert)\(/g)].map((x) => x[1]);
    // A delete limited to an explicit id list (in / notIn) cannot remove the rows being inserted
    if (/\bin\s*:|\.in\(|\bnotIn\b|\.not\(/.test(arr)) continue;
    const t = sbDel.find((x) => sbIns.includes(x)) ?? orDel.find((x) => orIns.includes(x));
    if (!t) continue;
    add({ ruleId: 29689, code: 'BUG-89', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
      title: `Delete and Insert on ${t} Run in Parallel (Promise.all)`,
      why: `Promise.all starts both queries at once, so the order is not guaranteed: when the delete runs after the insert it removes the rows just written, and the "replace" leaves ${t} empty.`,
      fix: `Run them in order (await the delete, then the insert), or atomically in one transaction / Postgres function (prisma.$transaction([...]) runs sequentially).` });
  }

  // BUG-90: fetch response .json() not awaited, then read as data
  {
    const resVars = new Set([...c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*await\s+fetch\(/g)].map((m) => m[1]));
    if (resVars.size) {
      const rv = [...resVars].map(esc).join('|');
      for (const m of c.matchAll(new RegExp(String.raw`\b(?:const|let)\s+(\w+)\s*=\s*(?:${rv})\.json\(\)\s*(?:;|\n)`, 'g'))) {
        const rest = restOfFn(m.index!).slice(m[0].length);
        const v = esc(m[1]);
        if (new RegExp(String.raw`\bawait\s+${v}\b|\b${v}\.then\(`).test(rest)) continue;
        if (!new RegExp(String.raw`\b${v}\s*(?:\??\.|\[)\s*\w`).test(rest)) continue;
        add({ ruleId: 29690, code: 'BUG-90', severity: 'HIGH', category: CAT, lineIdx: lineAt(m.index!),
          title: 'response.json() Is Not Awaited',
          why: `response.json() returns a Promise, so ${m[1]} is a Promise and every property read from it is undefined: the UI renders nothing or the handler stores undefined.`,
          fix: `const ${m[1]} = await response.json();` });
      }
    }
  }
}

function evaluatePy(lines: string[], add: (h: Hit) => void) {
  // Mask docstrings and comments so prose never matches
  const code: string[] = [];
  let inDoc: string | null = null;
  for (const l of lines) {
    if (inDoc) { code.push(''); if (l.includes(inDoc)) inDoc = null; continue; }
    const t = /^\s*[rRbBuUfF]?("""|''')/.exec(l);
    if (t) { code.push(''); if (l.split(t[1]).length - 1 < 2) inDoc = t[1]; continue; }
    code.push(l.replace(/(^|\s)#.*$/, '$1'));
  }

  // BUG-91: mutable default argument that the function then mutates (state shared between calls)
  for (let i = 0; i < code.length; i++) {
    const d = /^(\s*)(?:async\s+)?def\s+\w+\s*\(/.exec(code[i]);
    if (!d) continue;
    let sig = code[i], j = i;
    while (!/\)\s*(?:->[^:]+)?:\s*$/.test(sig) && j < i + 15 && j < code.length - 1) sig += ' ' + code[++j];
    const indent = d[1].length;
    const body: string[] = [];
    for (let k = j + 1; k < code.length; k++) {
      const l = code[k];
      if (l.trim() && (l.length - l.trimStart().length) <= indent) break;
      body.push(l);
    }
    const text = body.join('\n');
    for (const p of sig.matchAll(/[(,]\s*(\w+)\s*(?::\s*[^=,()]+(?:\[[^\]]*\])?)?\s*=\s*(\[\s*\]|\{\s*\}|set\(\)|list\(\)|dict\(\))/g)) {
      const v = p[1];
      if (!new RegExp(String.raw`\b${v}\s*\.\s*(?:append|extend|insert|update|add|setdefault|pop|remove|clear)\(|\b${v}\s*\[[^\]]+\]\s*=(?!=)|\b${v}\s*\+=`).test(text)) continue;
      if (new RegExp(String.raw`\b${v}\s*=\s*(?:\[|\{|list\(|dict\(|set\(|${v}\.copy\()`).test(text.split(new RegExp(String.raw`\b${v}\s*\.\s*(?:append|extend|insert|update|add|setdefault|pop|remove|clear)\(|\b${v}\s*\[[^\]]+\]\s*=|\b${v}\s*\+=`))[0])) continue;
      add({ ruleId: 29691, code: 'BUG-91', severity: 'MEDIUM', category: CAT, lineIdx: i,
        title: `Mutable Default Argument ${v}=${p[2]} Is Shared Between Calls`,
        why: `Python evaluates the default ${p[2]} once, when the function is defined. Every call that relies on it mutates the same object, so items from earlier calls (other requests, other users) leak into later results.`,
        fix: `Default to None and create a new object inside: def f(${v}=None): ${v} = [] if ${v} is None else ${v}` });
    }
  }

  // BUG-92: `is` / `is not` with a str or int literal (identity, not equality)
  code.forEach((l, i) => {
    const m = /[\w\])]\s+is\s+(?:not\s+)?(['"][^'"]*['"]|-?\d+(?:\.\d+)?)(?=\s*(?:$|:|\)|,|\band\b|\bor\b|\belse\b))/.exec(l);
    if (!m || !/\b(?:if|elif|while|return|assert|and|or|not)\b|=\s*/.test(l)) return;
    const pre = l.slice(0, m.index);
    if ((pre.split('"').length - 1) % 2 || (pre.split("'").length - 1) % 2) return; // inside a string
    add({ ruleId: 29692, code: 'BUG-92', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: `\`is\` Used to Compare With the Literal ${m[1]}`,
      why: '`is` checks object identity. Equal strings/numbers built at runtime (from a request, a DB row, an int above 256) are different objects, so the comparison is False even when the values match (Python 3.8+ warns: SyntaxWarning "is" with a literal).',
      fix: `Use == (or != for is not): x == ${m[1]}.` });
  });

  // BUG-93: datetime.utcnow().timestamp() treats UTC as local time
  const utcVars = new Set<string>();
  code.forEach((l) => { const m = /^\s*(\w+)\s*=\s*datetime(?:\.datetime)?\.utcnow\(\)\s*$/.exec(l); if (m) utcVars.add(m[1]); });
  code.forEach((l, i) => {
    const m = /\bdatetime(?:\.datetime)?\.utc(?:now\(\)|fromtimestamp\([^)]*\))\.timestamp\(\)/.exec(l) || [...utcVars].map((v) => new RegExp(String.raw`\b${v}\.timestamp\(\)`).exec(l)).find(Boolean);
    if (!m) return;
    add({ ruleId: 29693, code: 'BUG-93', severity: 'MEDIUM', category: CAT, lineIdx: i,
      title: 'datetime.utcnow().timestamp() Is Off by the Server UTC Offset',
      why: 'utcnow() returns a naive datetime, and .timestamp() interprets naive datetimes as local time, so on any server not running in UTC the epoch value is shifted by the UTC offset: tokens expire early/late and scheduled jobs run at the wrong time.',
      fix: 'Use an aware datetime: datetime.now(timezone.utc).timestamp() (or time.time()).' });
  });
}
