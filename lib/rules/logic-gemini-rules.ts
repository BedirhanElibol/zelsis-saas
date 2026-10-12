/**
 * Runtime logic bugs from the Gemini rule report that no existing rule caught (BUG-149.., Rule IDs 29820-29899).
 * Every proposal was re-checked: the scanner missed its example, the mistake is provable from one file, and the
 * pattern is wrong in essentially every context (TypeError at runtime, silently wrong data, or a no-op).
 *
 * Reliability findings (type VIBECARE), reported on the line that contains the mistake.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }
type Add = (h: Hit) => void;

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|(?:^|\/)vendor\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?|testdata|seeds?)\/|\.(?:test|spec|stories)\.[jt]sx?$|_test\.(?:go|py)$|(?:^|\/)test_\w+\.py$|(?:^|\/)seed\.[jt]s$/i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };

/** Offset just past the bracket that closes the one at `open` (strings skipped), or -1. */
function closeOf(c: string, open: number): number {
  const pair: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  for (let i = open; i < c.length; i++) {
    const ch = c[i];
    if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < c.length && c[i] !== ch; i++) if (c[i] === '\\') i++; continue; }
    if (pair[ch]) stack.push(pair[ch]);
    else if (ch === stack[stack.length - 1]) { stack.pop(); if (!stack.length) return i + 1; }
  }
  return -1;
}

/** Text of the `{ ... }` block that starts at the first `{` at or after `from`. */
function blockAfter(c: string, from: number): { s: number; e: number } | null {
  const open = c.indexOf('{', from);
  if (open < 0) return null;
  const end = closeOf(c, open);
  return end < 0 ? null : { s: open + 1, e: end - 1 };
}

/** Number of top-level comma-separated arguments in the call whose `(` is at `open`. */
function argCount(c: string, open: number): number {
  const end = closeOf(c, open);
  if (end < 0) return 0;
  const inner = c.slice(open + 1, end - 1);
  if (!inner.trim()) return 0;
  let depth = 0; let n = 1;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < inner.length && inner[i] !== ch; i++) if (inner[i] === '\\') i++; continue; }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0 && inner.slice(i + 1).trim()) n++;
  }
  return n;
}

function evaluateJs(path: string, c: string, add: Add) {
  const at = (off: number) => lineAt(c, off);
  const isRoute = /(?:^|\/)route\.[cm]?[jt]s$/i.test(path);
  const isClient = /^\s*['"]use client['"]/m.test(c);
  const isServer = isRoute || /^\s*['"]use server['"]/m.test(c)
    || (!isClient && /(?:^|\/)app\/(?:.*\/)?(?:page|layout)\.[jt]sx?$/i.test(path) && /export\s+default\s+async\s+function/.test(c));

  // BUG-149: interactive transaction callback writes through the outer client, outside the transaction
  for (const m of c.matchAll(/\b(\w+)\.\$transaction\(\s*async\s*\(\s*(\w+)/g)) {
    const outer = m[1]; const tx = m[2];
    if (outer === tx) continue;
    const b = blockAfter(c, m.index! + m[0].length);
    if (!b) continue;
    const body = c.slice(b.s, b.e);
    const w = new RegExp(`\\b${outer}\\.(\\w+)\\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\\(`).exec(body);
    if (w) add({ ruleId: 29820, code: 'BUG-149', severity: 'HIGH', lineIdx: at(b.s + w.index),
      title: `Write Inside $transaction Uses ${outer} Instead of ${tx}`,
      why: `Queries on ${outer} run on a separate connection, outside the transaction: if a later step throws, this write is not rolled back and the data is left half-updated.`,
      fix: `Use the transaction client for every query in the callback: ${tx}.${w[1]}.…` });
  }

  // BUG-150: useActionState / useFormState given an action that takes only (formData)
  for (const m of c.matchAll(/\buse(?:ActionState|FormState)\(\s*(\w+)\s*,/g)) {
    const name = m[1];
    const decl = new RegExp(`(?:async\\s+function\\s+${name}\\s*\\(([^)]*)\\)|\\b${name}\\s*=\\s*async\\s*\\(([^)]*)\\))`).exec(c);
    if (!decl) continue;
    const params = (decl[1] ?? decl[2] ?? '').trim();
    const p = params.split(':')[0].trim();
    if (!params || params.includes(',') || !/^\w+$/.test(p)) continue;
    if (!new RegExp(`\\b${p}\\.get\\(`).test(c)) continue;
    add({ ruleId: 29821, code: 'BUG-150', severity: 'HIGH', lineIdx: at(decl.index),
      title: `Action ${name} for useActionState Takes Only (formData)`,
      why: 'useActionState calls the action with (previousState, formData). The single parameter receives the previous state, so formData.get() throws or reads nothing on every submit.',
      fix: `Declare the action as async function ${name}(prevState, formData) { … }.` });
  }

  // BUG-151: native fetch error handling that expects an axios-style err.response.status
  if (/\bfetch\(/.test(c) && !/\b(?:axios|ky|ofetch|got|superagent|redaxios|wretch)\b|\.response\s*=|\bresponse\s*:/.test(c)) {
    for (const m of c.matchAll(/\bcatch\s*\(\s*(\w+)[^)]*\)\s*\{/g)) {
      const b = blockAfter(c, m.index! + m[0].length - 1);
      if (!b) continue;
      const r = new RegExp(`\\b${m[1]}\\.response\\??\\.status\\b`).exec(c.slice(b.s, b.e));
      if (r) add({ ruleId: 29822, code: 'BUG-151', severity: 'MEDIUM', lineIdx: at(b.s + r.index),
        title: 'catch Reads err.response.status but fetch Does Not Reject on HTTP Errors',
        why: 'fetch resolves normally for 4xx/5xx responses and rejects only on network failure, where the error has no response. This branch never runs, so 401/404/500 handling is dead code.',
        fix: 'Check the response itself: const res = await fetch(…); if (!res.ok) { handle res.status }.' });
    }
  }

  // BUG-152: forEach given a named async function: nothing awaits the calls
  const asyncNames = new Set<string>();
  for (const m of c.matchAll(/\basync\s+function\s+(\w+)|\b(?:const|let)\s+(\w+)\s*=\s*async\b/g)) asyncNames.add(m[1] ?? m[2]);
  for (const m of c.matchAll(/\.forEach\(\s*(\w+)\s*\)/g)) {
    if (asyncNames.has(m[1])) add({ ruleId: 29823, code: 'BUG-152', severity: 'HIGH', lineIdx: at(m.index!),
      title: `forEach Calls Async ${m[1]} Without Awaiting It`,
      why: 'forEach ignores the Promises returned by the async function, so the code after the loop runs before the work finishes and any rejection is unhandled.',
      fix: `Use await Promise.all(items.map(${m[1]})) or a for…of loop with await.` });
  }

  // BUG-153: Array(n).fill({}) / fill([]) shares one object across every slot
  for (const m of c.matchAll(/\b(?:new\s+)?Array(?:\.from)?\([^()]*(?:\([^()]*\)[^()]*)*\)\.fill\(\s*(?:\{\s*\}|\[\s*\]|new\s+(?:Map|Set|Array)\(\s*\))\s*\)/g)) {
    add({ ruleId: 29824, code: 'BUG-153', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'Array.fill() With an Object Shares the Same Reference in Every Slot',
      why: 'fill() puts the same object or array in every position, so pushing to or editing one row changes all rows.',
      fix: 'Create a new value per slot: Array.from({ length: n }, () => ({})) or Array.from({ length: n }, () => []).' });
  }

  // BUG-154: App Router route handler destructures params from the request argument
  if (isRoute) {
    for (const m of c.matchAll(/export\s+(?:async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(|const\s+(GET|POST|PUT|PATCH|DELETE)\s*=\s*async\s*\()\s*\{\s*params\b/g)) {
      add({ ruleId: 29825, code: 'BUG-154', severity: 'HIGH', lineIdx: at(m.index!),
        title: `${m[1] ?? m[2]} Handler Reads params From the Request Argument`,
        why: 'The first argument of a route handler is the Request; params arrive in the second argument. Destructuring { params } from the Request always gives undefined.',
        fix: `Use export async function ${m[1] ?? m[2]}(request: Request, { params }: { params: Promise<{ id: string }> }) and await params.` });
    }
  }

  // BUG-155: ReadonlyURLSearchParams from next/navigation mutated in place
  if (/from\s+['"]next\/navigation['"]/.test(c)) {
    for (const m of c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*useSearchParams\(\)/g)) {
      const r = new RegExp(`\\b${m[1]}\\.(?:set|delete|append|sort)\\(`, 'g');
      for (const u of c.matchAll(r)) add({ ruleId: 29826, code: 'BUG-155', severity: 'HIGH', lineIdx: at(u.index!),
        title: 'useSearchParams() Result Mutated Directly',
        why: 'next/navigation returns a ReadonlyURLSearchParams; set/delete/append throw at runtime, so the filter or pagination change crashes instead of updating the URL.',
        fix: `Copy it first: const params = new URLSearchParams(${m[1]}.toString()); params.set(…); router.push(\`?\${params}\`).` });
    }
  }

  // BUG-156: `x in ['a', 'b']` checks array indexes, not values
  for (const m of c.matchAll(/(?<!\bfor\s*\(\s*(?:const|let|var)\s+\w+\s)\b([\w.]+)\s+in\s+\[\s*['"]/g)) {
    if (/\bfor\s*\([^)]*$/.test(c.slice(Math.max(0, m.index! - 40), m.index!))) continue;
    add({ ruleId: 29827, code: 'BUG-156', severity: 'HIGH', lineIdx: at(m.index!),
      title: `"in" Used to Check Whether ${m[1]} Is in an Array`,
      why: "The in operator tests property names (the indexes '0', '1', …), not values, so a role or status check like this is always false for real values.",
      fix: `Use ['…'].includes(${m[1]}).` });
  }

  // BUG-157: 1-based page multiplied by page size without subtracting 1
  for (const m of c.matchAll(/(?:\b(?:skip|offset)\s*[:=]\s*\(?\s*|\.(?:offset|skip|range)\(\s*)(page|currentPage|pageNumber|pageNum)\s*\*\s*(\w+)/g)) {
    const page = m[1];
    const oneBased = new RegExp(`\\b${page}\\s*=\\s*1\\b|\\b${page}\\s*=[^;\\n]*(?:\\|\\||\\?\\?)\\s*['"]?1['"]?(?![\\d.])|\\b${page}\\s*:\\s*\\w+\\s*=\\s*1\\b`).test(c);
    if (oneBased) add({ ruleId: 29828, code: 'BUG-157', severity: 'HIGH', lineIdx: at(m.index!),
      title: `Pagination Skips the First Page (${page} * ${m[2]} With 1-Based ${page})`,
      why: `${page} starts at 1, so page 1 skips ${m[2]} rows: the first page of results is never shown and the last page is empty.`,
      fix: `Use (${page} - 1) * ${m[2]}.` });
  }

  // BUG-158: NextResponse.redirect / Response.redirect with a relative path
  for (const m of c.matchAll(/\b(?:NextResponse|Response)\.redirect\(\s*['"`]\/(?!\/)/g)) {
    add({ ruleId: 29829, code: 'BUG-158', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'Response.redirect() Called With a Relative Path',
      why: 'Response.redirect and NextResponse.redirect need an absolute URL; a relative path throws "URL is malformed" (TypeError), so the request fails with a 500 instead of redirecting.',
      fix: "Build an absolute URL: NextResponse.redirect(new URL('/login', request.url))." });
  }

  // BUG-160: res.text() in catch after res.json() already consumed the body
  for (const m of c.matchAll(/\btry\s*\{/g)) {
    const b = blockAfter(c, m.index!);
    if (!b) continue;
    const j = /\bawait\s+(\w+)\.json\(\)/.exec(c.slice(b.s, b.e));
    if (!j) continue;
    const after = c.slice(b.e + 1, b.e + 60);
    const cm = /^\s*catch\s*(?:\([^)]*\))?\s*\{/.exec(after);
    if (!cm) continue;
    const cb = blockAfter(c, b.e + 1 + cm.index + cm[0].length - 1);
    if (!cb) continue;
    const t = new RegExp(`\\b${j[1]}\\.text\\(\\)`).exec(c.slice(cb.s, cb.e));
    if (t) add({ ruleId: 29831, code: 'BUG-160', severity: 'MEDIUM', lineIdx: at(cb.s + t.index),
      title: `${j[1]}.text() Read After ${j[1]}.json() Consumed the Body`,
      why: 'A response body can be read once. When json() fails on a non-JSON error page, text() throws "body used already", hiding the real error message.',
      fix: `Read the body once: const raw = await ${j[1]}.text(); then try JSON.parse(raw) and fall back to raw.` });
  }

  // BUG-161: matchAll / replaceAll with a non-global regex literal throws
  for (const m of c.matchAll(/\.(matchAll|replaceAll)\(\s*\/((?:\\.|\[(?:\\.|[^\]\n])*\]|[^/\\\n[])+)\/([a-z]*)/g)) {
    if (m[3].includes('g')) continue;
    add({ ruleId: 29832, code: 'BUG-161', severity: 'HIGH', lineIdx: at(m.index!),
      title: `${m[1]}() Called With a Regex Without the g Flag`,
      why: `${m[1]} throws "TypeError: ${m[1]} must be called with a global RegExp" when the regex lacks the g flag, so this line crashes every time it runs.`,
      fix: `Add the g flag: .${m[1]}(/${m[2].slice(0, 30)}/g${m[3]}…).` });
  }

  // BUG-162: Drizzle update/delete without .where() changes every row of the table
  if (/from\s+['"]drizzle-orm/.test(c)) {
    for (const m of c.matchAll(/\b(\w+)\.(delete|update)\(\s*(\w+)\s*\)/g)) {
      let end = m.index! + m[0].length;
      if (m[2] === 'update') {
        const set = /^\s*\.set\(/.exec(c.slice(end));
        if (!set) continue;
        end = closeOf(c, end + set[0].length - 1);
        if (end < 0) continue;
      }
      if (/^\s*\.where\(/.test(c.slice(end)) || !/^\s*(?:\.returning\([^)]*\)\s*)?[;)\n]/.test(c.slice(end))) continue;
      add({ ruleId: 29833, code: 'BUG-162', severity: 'HIGH', lineIdx: at(m.index!),
        title: `Drizzle ${m[2]}(${m[3]}) Without .where() Affects Every Row`,
        why: `Drizzle runs ${m[2] === 'delete' ? 'DELETE' : 'UPDATE'} without a WHERE clause when .where() is missing, so this ${m[2] === 'delete' ? 'deletes' : 'overwrites'} every row in ${m[3]}, not just the intended one.`,
        fix: `Add the filter: ${m[1]}.${m[2]}(${m[3]})${m[2] === 'update' ? '.set({…})' : ''}.where(eq(${m[3]}.id, id)).` });
    }
  }

  // BUG-163: Set.has / Map.get / includes with a fresh object or array literal: identity never matches
  for (const m of c.matchAll(/(?<![\w$])([\w$.]+)\.(has|includes|indexOf)\(\s*[[{]/g)) {
    if (/^(?:_|lodash|R|ramda|\$)$/.test(m[1].split('.')[0]) || /(?:searchParams|params|headers|formData|cookies|query|router|app)$/i.test(m[1])) continue;
    add({ ruleId: 29834, code: 'BUG-163', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: `${m[2]}() Compares a New Object/Array Literal by Reference`,
      why: `${m[2]}() compares objects by identity. A literal created in the call is a new object, so the lookup is always false / -1 even when an equal value is stored.`,
      fix: 'Look up by a primitive key (an id or a JSON/string key), or use some((x) => x.id === target.id).' });
  }

  // BUG-164: async Promise executor swallows thrown errors
  for (const m of c.matchAll(/\bnew\s+Promise\(\s*async\b/g)) {
    add({ ruleId: 29835, code: 'BUG-164', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'new Promise() With an async Executor',
      why: 'If the async executor throws or an awaited call rejects, the error is lost and the outer Promise never settles: callers hang forever instead of seeing the failure.',
      fix: 'Drop the wrapper and write an async function, or keep the executor synchronous and call reject() from a .catch().' });
  }

  // BUG-165: relative URL passed to fetch() on the server
  if (isServer) {
    for (const m of c.matchAll(/\bfetch\(\s*['"`]\/(?!\/)/g)) {
      add({ ruleId: 29836, code: 'BUG-165', severity: 'HIGH', lineIdx: at(m.index!),
        title: 'fetch() With a Relative URL in Server Code',
        why: 'On the server there is no page origin, so fetch("/api/…") throws "Failed to parse URL" (TypeError) and the page or action errors.',
        fix: 'Call the data function directly instead of your own API route, or build an absolute URL from an env base URL.' });
    }
  }

  // BUG-166: Supabase .eq(col, null) never matches NULL
  for (const m of c.matchAll(/\.(eq|neq)\(\s*['"][\w.]+['"]\s*,\s*null\s*\)/g)) {
    add({ ruleId: 29837, code: 'BUG-166', severity: 'HIGH', lineIdx: at(m.index!),
      title: `.${m[1]}(column, null) Never Matches NULL Rows`,
      why: `PostgREST turns .${m[1]}(col, null) into col ${m[1] === 'eq' ? '=' : '<>'} 'null', which is never true for SQL NULL, so the query silently returns no rows (or the wrong ones).`,
      fix: `Use .is(column, null)${m[1] === 'neq' ? " / .not(column, 'is', null)" : ''}.` });
  }

  // BUG-169: parseFloat / parseInt on a locale-formatted number
  for (const m of c.matchAll(/\b(?:parseFloat|parseInt|Number)\(\s*[^()]*\.toLocaleString\(/g)) {
    add({ ruleId: 29840, code: 'BUG-169', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'Number Parsed Back From toLocaleString() Output',
      why: 'Locale output contains group separators ("1,250.75"); parseFloat stops at the comma and returns 1, and Number() returns NaN, so totals are silently wrong.',
      fix: 'Keep the raw number for math and use toLocaleString() only for display.' });
  }

  // BUG-170: async function passed to useMemo / useState / useReducer stores a Promise
  for (const m of c.matchAll(/\buse(Memo|State|Reducer)\(\s*async\b/g)) {
    add({ ruleId: 29841, code: 'BUG-170', severity: 'HIGH', lineIdx: at(m.index!),
      title: `async Function Passed to use${m[1]}`,
      why: `use${m[1]} stores whatever the function returns; an async function returns a Promise, so the value is a pending Promise and the UI renders "[object Promise]" or crashes on property access.`,
      fix: 'Load the data in useEffect (or a data library / server component) and store the resolved value with setState.' });
  }

  // BUG-171: regex literal or non-global regex used in while (m = re.exec(s)) loops forever
  const nonGlobal = new Set<string>();
  for (const m of c.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*\/(?:\\.|\[(?:\\.|[^\]\n])*\]|[^/\\\n[])+\/([a-z]*)\s*[;\n]/g)) if (!/[gy]/.test(m[2])) nonGlobal.add(m[1]);
  for (const m of c.matchAll(/\bwhile\s*\(\s*\(?\s*\w+\s*=\s*(\/(?:\\.|\[(?:\\.|[^\]\n])*\]|[^/\\\n[])+\/[a-z]*|\w+)\.exec\(/g)) {
    if (!m[1].startsWith('/') && !nonGlobal.has(m[1])) continue;
    add({ ruleId: 29842, code: 'BUG-171', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'while (… .exec()) Loop Never Advances',
      why: m[1].startsWith('/')
        ? 'A regex literal inside the loop condition is a new RegExp on every iteration with lastIndex 0, so exec() returns the first match forever and the loop never ends.'
        : `${m[1]} has no g flag, so exec() always starts at index 0 and returns the same match: the loop never ends and freezes the page or server.`,
      fix: 'Declare the regex once with the g flag outside the loop, or use for (const m of str.matchAll(/…/g)).' });
  }

  // BUG-172: return / throw inside finally overrides the try/catch outcome
  for (const m of c.matchAll(/\bfinally\s*\{/g)) {
    const b = blockAfter(c, m.index!);
    if (!b) continue;
    const body = c.slice(b.s, b.e);
    if (/=>|\bfunction\b/.test(body)) continue;
    const r = /(?:^|[;{}\s])(return|throw)\b/.exec(body);
    if (r) add({ ruleId: 29843, code: 'BUG-172', severity: 'MEDIUM', lineIdx: at(b.s + r.index + r[0].indexOf(r[1])),
      title: `${r[1]} Inside finally Overrides the try/catch Result`,
      why: `A ${r[1]} in finally replaces whatever the try or catch returned or threw, so errors are silently swallowed and callers get the finally value instead.`,
      fix: 'Keep finally for cleanup only and move the return / throw into try or catch.' });
  }

  // BUG-173: Promise.all(p1, p2) instead of Promise.all([p1, p2])
  for (const m of c.matchAll(/\bPromise\.(all|race|allSettled|any)\(\s*(?!\[)/g)) {
    const open = m.index! + m[0].indexOf('(');
    if (argCount(c, open) >= 2) add({ ruleId: 29844, code: 'BUG-173', severity: 'HIGH', lineIdx: at(m.index!),
      title: `Promise.${m[1]}() Given Separate Arguments Instead of an Array`,
      why: `Promise.${m[1]} reads only its first argument as an iterable; the other promises are ignored (and a single Promise argument throws "is not iterable").`,
      fix: `Wrap them in an array: Promise.${m[1]}([p1, p2]).` });
  }

  // BUG-174: plain object passed as a Response body
  for (const m of c.matchAll(/\bnew\s+(?:Response|NextResponse)\(\s*\{/g)) {
    add({ ruleId: 29845, code: 'BUG-174', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'Plain Object Passed as a Response Body',
      why: 'The Response constructor converts a plain object to the string "[object Object]", so the client receives that text instead of JSON.',
      fix: 'Use Response.json({ … }) / NextResponse.json({ … }), or JSON.stringify the body and set Content-Type.' });
  }

  // BUG-175: new Map({...}) / new Set({...}) throws
  for (const m of c.matchAll(/\bnew\s+(Map|Set|WeakMap|WeakSet)\(\s*\{/g)) {
    add({ ruleId: 29846, code: 'BUG-175', severity: 'HIGH', lineIdx: at(m.index!),
      title: `Plain Object Passed to new ${m[1]}()`,
      why: `${m[1]} needs an iterable; a plain object throws "object is not iterable" (TypeError) when this line runs.`,
      fix: m[1].endsWith('Map') ? 'Use new Map(Object.entries({ … })).' : 'Pass an array: new Set([ … ]).' });
  }

  // BUG-176: dynamic route placeholder left in a link or navigation
  for (const m of c.matchAll(/(?:\bhref=\{?\s*|\brouter\.(?:push|replace)\(\s*|\bredirect\(\s*)(['"`])(\/[^'"`\n]*\[(?:\.\.\.)?\w+\][^'"`\n]*)\1(\s*[,)}]?)/g)) {
    if (m[0].startsWith('router') && m[3].trim() === ',') continue;
    if (!/\[(?:\.\.\.)?[A-Za-z_]\w*\]/.test(m[2].replace(/\$\{[^}]*\}/g, ''))) continue;
    add({ ruleId: 29847, code: 'BUG-176', severity: 'HIGH', lineIdx: at(m.index!),
      title: `Route Placeholder Left in URL ${m[2].slice(0, 40)}`,
      why: 'The [param] segment is the file-system pattern, not a URL. Navigating to it opens a literal "[id]" path, so the page 404s or loads the wrong record.',
      fix: 'Interpolate the value: `/users/${user.id}`.' });
  }

  // BUG-177: padStart / padEnd arguments swapped
  for (const m of c.matchAll(/\.(padStart|padEnd)\(\s*['"][^'"]*['"]\s*,\s*\d+\s*\)/g)) {
    add({ ruleId: 29848, code: 'BUG-177', severity: 'HIGH', lineIdx: at(m.index!),
      title: `${m[1]}() Arguments Swapped`,
      why: `${m[1]}(targetLength, padString) takes the length first; with the string first the length becomes NaN (0), so nothing is padded ("5" instead of "05").`,
      fix: `Swap them: .${m[1]}(2, '0').` });
  }

  // BUG-179: indexOf(NaN) is always -1 and case NaN never matches
  for (const m of c.matchAll(/\.(?:indexOf|lastIndexOf)\(\s*NaN\s*\)|\bcase\s+NaN\s*:/g)) {
    add({ ruleId: 29850, code: 'BUG-179', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'NaN Lookup That Can Never Match',
      why: 'indexOf and switch compare with ===, and NaN is never equal to anything, so this always returns -1 / skips the case.',
      fix: 'Use arr.findIndex(Number.isNaN), arr.includes(NaN), or an if (Number.isNaN(x)) branch.' });
  }

  // BUG-180: new URL() with a lone relative path
  for (const m of c.matchAll(/\bnew\s+URL\(\s*(['"`])\/(?!\/)[^'"`\n]*\1\s*\)/g)) {
    add({ ruleId: 29851, code: 'BUG-180', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'new URL() Called With Only a Relative Path',
      why: 'new URL("/path") has no base to resolve against and throws "Invalid URL" (TypeError) every time.',
      fix: 'Pass a base: new URL("/path", request.url) or new URL("/path", window.location.origin).' });
  }

  // BUG-181: AbortController aborted but its signal never passed anywhere
  for (const m of c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*new\s+AbortController\(\)/g)) {
    const n = m[1];
    if (new RegExp(`\\b${n}\\.abort\\(`).test(c) && !new RegExp(`\\b${n}\\.signal\\b|\\b${n}\\s*[,)}\\]]|signal\\s*:\\s*${n}\\b|return\\s+${n}\\b`).test(c)) {
      add({ ruleId: 29852, code: 'BUG-181', severity: 'MEDIUM', lineIdx: at(m.index!),
        title: `${n}.abort() Cancels Nothing (signal Never Passed)`,
        why: `${n}.signal is never given to fetch or any listener, so abort() has no effect: stale requests still finish and overwrite newer state.`,
        fix: `Pass it: fetch(url, { signal: ${n}.signal }).` });
    }
  }

  // BUG-182: arr.map(parseInt) passes the index as the radix
  for (const m of c.matchAll(/\.map\(\s*(?:Number\.)?parseInt\s*\)/g)) {
    add({ ruleId: 29853, code: 'BUG-182', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'map(parseInt) Uses the Index as the Radix',
      why: "map passes (value, index), so parseInt gets the index as the radix: ['1','2','3'].map(parseInt) is [1, NaN, NaN].",
      fix: 'Use .map(Number) or .map((s) => parseInt(s, 10)).' });
  }

  // BUG-183: sort comparator returning a boolean
  for (const m of c.matchAll(/\.sort\(\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>\s*[\w$.[\]'"]+\s*[<>]=?\s*[\w$.[\]'"]+\s*\)/g)) {
    add({ ruleId: 29854, code: 'BUG-183', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'sort() Comparator Returns a Boolean',
      why: 'sort expects a negative, zero or positive number. true/false become 1/0, so items never move "down" and the order is wrong or engine-dependent.',
      fix: `Return a number: (${m[1]}, ${m[2]}) => ${m[1]} - ${m[2]} (or a.localeCompare(b) for strings).` });
  }

  // BUG-185: Math.floor(amount * 100) loses a cent on float input
  for (const m of c.matchAll(/\b(?:Math\.(?:floor|trunc)|parseInt)\(\s*[\w.]*?(?:price|amount|total|cost|subtotal|balance)\w*\s*\*\s*100\s*\)/gi)) {
    add({ ruleId: 29856, code: 'BUG-185', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'Money Converted to Cents by Truncating amount * 100',
      why: 'Floats like 19.99 * 100 give 1998.9999…, and floor/trunc/parseInt cut it to 1998, so charges and totals are a cent short.',
      fix: 'Use Math.round(amount * 100).' });
  }

  // BUG-186: toFixed() results added together are string concatenation
  for (const m of c.matchAll(/\+=\s*[\w.()[\]]+\.toFixed\(\d?\)\s*;|\.toFixed\(\d?\)\s*\+\s*[\w.()[\]]+\.toFixed\(/g)) {
    add({ ruleId: 29857, code: 'BUG-186', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'Strings From toFixed() Concatenated Instead of Added',
      why: 'toFixed() returns a string, so + and += concatenate: 10 + "5.00" becomes "105.00" and totals are wrong.',
      fix: 'Do the math on numbers and call toFixed() once, for display.' });
  }

  // BUG-187: Number.isNaN / isFinite on a raw string input
  for (const m of c.matchAll(/\bNumber\.(isNaN|isFinite)\(\s*[\w.]*(?:searchParams\.get\([^)]*\)|\.target\.value\b|\.query\.\w+|formData\.get\([^)]*\))\s*\)/g)) {
    add({ ruleId: 29858, code: 'BUG-187', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: `Number.${m[1]}() Called on an Unparsed String`,
      why: `Number.${m[1]} does not convert strings: Number.isNaN("abc") is false and Number.isFinite("5") is false, so the validation ${m[1] === 'isNaN' ? 'never rejects bad input' : 'rejects every valid input'}.`,
      fix: `Convert first: Number.${m[1]}(Number(value)).` });
  }

  // BUG-188: several headers.set('Set-Cookie') calls keep only the last cookie
  const sc = [...c.matchAll(/\b([\w.]+)\.set\(\s*['"]set-cookie['"]/gi)];
  const seen = new Set<string>();
  for (const m of sc) {
    if (seen.has(m[1])) add({ ruleId: 29859, code: 'BUG-188', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'Set-Cookie Header Overwritten by a Second set()',
      why: 'headers.set replaces the previous value, so only the last cookie is sent: the session or CSRF cookie set earlier is lost.',
      fix: "Use headers.append('Set-Cookie', …) for each cookie (or the cookies() API)." });
    seen.add(m[1]);
  }

  // BUG-189: FileList appended to FormData as one value
  for (const m of c.matchAll(/\.append\(\s*['"][^'"]+['"]\s*,\s*[\w.]*\.files\s*\)/g)) {
    add({ ruleId: 29860, code: 'BUG-189', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'FileList Appended to FormData as a Single Value',
      why: 'FormData.append converts a FileList to the string "[object FileList]", so the server receives no files.',
      fix: "Append each file: for (const f of input.files) formData.append('files', f)." });
  }
}

/** Second batch from the report (BUG-190.., Rule IDs 29867-29899). */
function evaluateJs2(path: string, c: string, add: Add, nextMajor: number) {
  const at = (off: number) => lineAt(c, off);
  const isClient = /^\s*['"]use client['"]/m.test(c);
  const declared = (n: string, init: RegExp) => new RegExp(`\\b(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]+)?=\\s*(?:${init.source})`).test(c);

  // BUG-190: fetch() options with a body but no method (GET cannot have a body)
  for (const m of c.matchAll(/\bfetch\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*\{/g)) {
    const open = m.index! + m[0].length - 1;
    const end = closeOf(c, open);
    if (end < 0) continue;
    const opts = c.slice(open, end);
    if (/(?:^|[,{\s])body\s*[:,}]/.test(opts) && !/\bmethod\s*[:,}]|\.\.\./.test(opts)) add({ ruleId: 29867, code: 'BUG-190', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'fetch() Sends a body Without a method',
      why: 'Without method, fetch uses GET, and a GET request with a body throws "Request with GET/HEAD method cannot have body" (TypeError): the save never reaches the server.',
      fix: "Add the method: fetch(url, { method: 'POST', body, headers })." });
  }

  // BUG-191: manual multipart Content-Type on a FormData fetch strips the boundary
  for (const m of c.matchAll(/\bfetch\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*\{/g)) {
    const open = m.index! + m[0].length - 1;
    const end = closeOf(c, open);
    if (end < 0) continue;
    const opts = c.slice(open, end);
    const bodyVar = /\bbody\s*:\s*(\w+)/.exec(opts)?.[1] ?? (/(?:^|[,{\s])body\s*[,}]/.test(opts) ? 'body' : '');
    if (/['"]content-type['"]\s*:\s*['"]multipart\/form-data/i.test(opts) && (/\bbody\s*:\s*new\s+FormData\(/.test(opts) || (bodyVar && declared(bodyVar, /new\s+FormData\(/))))
      add({ ruleId: 29868, code: 'BUG-191', severity: 'HIGH', lineIdx: at(m.index!),
        title: 'multipart/form-data Content-Type Set by Hand on a FormData Upload',
        why: 'The browser must add the multipart boundary to Content-Type. Setting the header yourself drops it, so the server cannot parse the body and the upload fails.',
        fix: 'Remove the Content-Type header and let fetch set it from the FormData body.' });
  }

  // BUG-192: ref.current in a hook dependency array
  for (const m of c.matchAll(/\buse(?:Effect|LayoutEffect|Memo|Callback)\(/g)) {
    const end = closeOf(c, m.index! + m[0].length - 1);
    if (end < 0) continue;
    const deps = /,\s*\[([^\]]*)\]\s*\)$/.exec(c.slice(m.index!, end));
    const r = deps && /\b(\w+)\.current\b/.exec(deps[1]);
    if (r) add({ ruleId: 29869, code: 'BUG-192', severity: 'MEDIUM', lineIdx: at(end - deps[0].length),
      title: `${r[1]}.current Used as a Hook Dependency`,
      why: 'Changing ref.current does not re-render, so React never sees the new value when comparing dependencies: the effect does not re-run when the element or value changes.',
      fix: 'Use a callback ref (or state) for elements you need to react to, and drop ref.current from the dependency array.' });
  }

  // BUG-193: in-place sort / reverse of a useState value
  for (const m of c.matchAll(/\bconst\s+\[\s*(\w+)\s*,\s*set\w+\s*\]\s*=\s*useState\b/g)) {
    for (const s of c.matchAll(new RegExp(`(?<![.\\w])${m[1]}\\.(sort|reverse)\\(`, 'g'))) {
      add({ ruleId: 29870, code: 'BUG-193', severity: 'HIGH', lineIdx: at(s.index!),
        title: `State ${m[1]} Mutated With .${s[1]}()`,
        why: `.${s[1]}() changes the state array in place. React compares by reference, so setting it back does not re-render, and other components holding ${m[1]} see it change silently.`,
        fix: `Copy first: [...${m[1]}].${s[1]}(…) (or ${m[1]}.to${s[1] === 'sort' ? 'Sorted' : 'Reversed'}()).` });
    }
  }

  // BUG-194: dynamic request APIs inside unstable_cache
  for (const m of c.matchAll(/\bunstable_cache\(/g)) {
    const end = closeOf(c, m.index! + m[0].length - 1);
    if (end < 0) continue;
    const r = /\b(cookies|headers|draftMode)\(\)/.exec(c.slice(m.index!, end));
    if (r) add({ ruleId: 29871, code: 'BUG-194', severity: 'HIGH', lineIdx: at(m.index! + r.index),
      title: `${r[1]}() Called Inside unstable_cache`,
      why: `Cached functions run outside the request, so ${r[1]}() throws inside unstable_cache; and if it did work, one user's cookies would be cached and served to everyone.`,
      fix: `Read ${r[1]}() outside the cached function and pass the needed value in as an argument (it becomes part of the cache key).` });
  }

  // BUG-195: reduce with a block body that never returns the accumulator
  for (const m of c.matchAll(/\.reduce\(\s*(?:async\s*)?\(\s*(\w+)\s*(?::[^,]+)?,[^)]*\)\s*(?::[^=]+)?=>\s*\{/g)) {
    const open = m.index! + m[0].length - 1;
    const end = closeOf(c, open);
    if (end < 0) continue;
    const body = c.slice(open, end);
    if (!/\breturn\b/.test(body)) add({ ruleId: 29872, code: 'BUG-195', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'reduce() Callback Never Returns the Accumulator',
      why: `The block body has no return, so ${m[1]} becomes undefined after the first item and the next iteration throws or the result is undefined.`,
      fix: `End the callback with return ${m[1]};.` });
  }

  // BUG-196: Object.keys / entries / spread on URLSearchParams, Headers or FormData
  const opaque = new Map<string, number>();
  for (const m of c.matchAll(/\b(?:const|let)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:new\s+(?:URLSearchParams|Headers|FormData)\(|useSearchParams\(\)|\w+\.formData\(\))/g)) if (!opaque.has(m[1])) opaque.set(m[1], m.index!);
  for (const [n, declAt] of opaque) {
    // A name can be reused for a plain object elsewhere in the file: only uses after this declaration count
    if (new RegExp(`\\b(?:const|let|var)\\s+(?:\\{[^}]*\\.\\.\\.${n}\\b[^}]*\\}|${n}\\s*(?::[^=\\n]+)?=(?!\\s*(?:await\\s+)?(?:new\\s+(?:URLSearchParams|Headers|FormData)\\(|useSearchParams\\(\\)|\\w+\\.formData\\(\\))))`).test(c)) continue;
    for (const s of c.matchAll(new RegExp(`\\bObject\\.(?:keys|entries|values|assign\\(\\s*\\{\\s*\\}\\s*,)\\(?\\s*${n}\\s*\\)|\\{\\s*\\.\\.\\.${n}\\s*\\}`, 'g'))) {
      if (s.index! < declAt) continue;
      add({ ruleId: 29873, code: 'BUG-196', severity: 'HIGH', lineIdx: at(s.index!),
        title: `${n} Read With Object.keys / Spread`,
        why: `${n} keeps its entries internally, not as object properties, so Object.keys/entries and { ...${n} } return nothing: the filters, headers or form fields are silently empty.`,
        fix: `Use Object.fromEntries(${n}) or ${n}.entries() / ${n}.get(…).` });
    }
  }

  // BUG-197: use(fetch(...)) creates a new promise every render
  if (isClient) {
    for (const m of c.matchAll(/\buse\(\s*fetch\(/g)) add({ ruleId: 29874, code: 'BUG-197', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'use(fetch(…)) Called During Render',
      why: 'Each render creates a new fetch promise, so the component suspends, re-renders and fetches again forever (an infinite request loop).',
      fix: 'Create the promise outside render (a server component passing it down, or a cached / memoized promise) and pass it to use().' });
  }

  // BUG-198: env var or query string concatenated with a number
  for (const m of c.matchAll(/\b(process\.env\.\w+|import\.meta\.env\.\w+|searchParams\.get\([^)]*\))\s*\+\s*\d+\b(?!\s*['"`])/g)) {
    if (/\b(?:Number|parseInt|parseFloat)\(\s*$/.test(c.slice(Math.max(0, m.index! - 20), m.index!))) continue;
    add({ ruleId: 29875, code: 'BUG-198', severity: 'HIGH', lineIdx: at(m.index!),
      title: `String ${m[1].slice(0, 30)} + Number Is Concatenated`,
      why: 'Env vars and query params are strings, so + appends the digits ("3000" + 1 is "30001"): ports, page numbers and limits come out wrong.',
      fix: `Convert first: Number(${m[1].slice(0, 40)}) + …` });
  }

  // BUG-199: value encoded before URLSearchParams.set / append (double encoding)
  for (const m of c.matchAll(/\.(?:set|append)\(\s*[^,()]+,\s*encodeURIComponent\(/g)) {
    if (!/searchParams|params|query|URLSearchParams|qs\b/i.test(c.slice(Math.max(0, m.index! - 30), m.index!))) continue;
    add({ ruleId: 29876, code: 'BUG-199', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'Value Encoded Twice for URLSearchParams',
      why: 'URLSearchParams already encodes values, so encodeURIComponent first produces %2520 / %252F: the server receives the escaped text instead of the original value.',
      fix: 'Pass the raw value: params.set(key, value).' });
  }

  // BUG-200: btoa on JSON / text that may contain non-ASCII characters
  for (const m of c.matchAll(/\bbtoa\(\s*JSON\.stringify\(/g)) {
    add({ ruleId: 29877, code: 'BUG-200', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'btoa(JSON.stringify(…)) Breaks on Non-ASCII Text',
      why: 'btoa only accepts Latin-1 characters; any name or text with ğ, ş, é, emoji… throws "InvalidCharacterError" and the feature fails for those users.',
      fix: 'Encode to UTF-8 first: btoa(String.fromCharCode(...new TextEncoder().encode(json))), or use Buffer.from(json).toString("base64") on the server.' });
  }

  // BUG-201: Intl currency formatting without a currency code
  for (const m of c.matchAll(/\bstyle\s*:\s*['"]currency['"]/g)) {
    // Enclosing object literal: the nearest { before the match whose block extends past it
    let open = c.lastIndexOf('{', m.index!);
    while (open >= 0 && closeOf(c, open) <= m.index!) open = c.lastIndexOf('{', open - 1);
    const end = open < 0 ? -1 : closeOf(c, open);
    if (end < 0 || /\bcurrency\s*[:,}]|\.\.\./.test(c.slice(open, end).replace(m[0], ''))) continue;
    add({ ruleId: 29878, code: 'BUG-201', severity: 'HIGH', lineIdx: at(m.index!),
      title: "Intl Currency Format Without a currency Code",
      why: 'style: "currency" requires a currency option; without it Intl.NumberFormat throws "Currency code is required" (RangeError) and the price never renders.',
      fix: "Add the code: { style: 'currency', currency: 'USD' }." });
  }

  // BUG-202: flatMap with an async callback
  for (const m of c.matchAll(/\.flatMap\(\s*async\b/g)) add({ ruleId: 29879, code: 'BUG-202', severity: 'HIGH', lineIdx: at(m.index!),
    title: 'flatMap() With an async Callback',
    why: 'An async callback returns a Promise, which flatMap cannot flatten: the result is an array of pending Promises, not the items.',
    fix: 'Use (await Promise.all(items.map(async (x) => …))).flat().' });

  // BUG-203: useContext(SomeContext.Provider)
  for (const m of c.matchAll(/\buseContext\(\s*(\w+)\.Provider\s*\)/g)) add({ ruleId: 29880, code: 'BUG-203', severity: 'HIGH', lineIdx: at(m.index!),
    title: `useContext(${m[1]}.Provider) Instead of useContext(${m[1]})`,
    why: 'useContext needs the context object itself; passing the Provider component returns undefined (or warns), so every consumer reads no value.',
    fix: `Use useContext(${m[1]}).` });

  // BUG-204: SSE stream parser that JSON.parses the [DONE] sentinel
  if (/['"`]data: ?['"`]|startsWith\(\s*['"`]data:/.test(c) && /JSON\.parse\(/.test(c) && !/\[DONE\]/.test(c) && /openai|chat\/completions|choices\s*\[\s*0\s*\]\??\.delta|\.delta\??\.content/i.test(c)) {
    const m = /JSON\.parse\(/.exec(c)!;
    add({ ruleId: 29881, code: 'BUG-204', severity: 'HIGH', lineIdx: at(m.index),
      title: 'Stream Parser Does Not Handle the [DONE] Message',
      why: 'OpenAI-style streams end with "data: [DONE]". JSON.parse("[DONE]") throws, so every response ends with an error (or the last chunk is lost).',
      fix: "Skip it before parsing: if (data === '[DONE]') break;." });
  }

  // BUG-205: find / filter / some / every callback returning an object literal
  for (const m of c.matchAll(/\.(find|filter|some|every|findIndex)\(\s*\(?\s*\w+\s*\)?\s*=>\s*\(\s*\{/g)) add({ ruleId: 29882, code: 'BUG-205', severity: 'HIGH', lineIdx: at(m.index!),
    title: `${m[1]}() Callback Returns an Object Literal`,
    why: `=> ({ … }) returns an object, which is always truthy, so ${m[1]}() matches every item regardless of its fields.`,
    fix: 'Return a comparison: (x) => x.id === id.' });

  // BUG-206: generateMetadata calling React hooks
  for (const m of c.matchAll(/\bfunction\s+generateMetadata\s*\(/g)) {
    const b = blockAfter(c, closeOf(c, m.index! + m[0].length - 1));
    const r = b && /\b(use(?:Params|SearchParams|Pathname|Router|State|Effect|Context))\(/.exec(c.slice(b.s, b.e));
    if (r) add({ ruleId: 29883, code: 'BUG-206', severity: 'HIGH', lineIdx: at(b!.s + r.index),
      title: `generateMetadata Calls ${r[1]}()`,
      why: 'generateMetadata is a server function, not a component; hooks throw there, so the page fails to render.',
      fix: 'Read params / searchParams from the function arguments: generateMetadata({ params, searchParams }).' });
  }

  // BUG-207: Math.max / Math.min given an array
  for (const m of c.matchAll(/\bMath\.(max|min)\(\s*(\w+)\s*\)/g)) {
    if (!declared(m[2], /\[|\w+(?:\.\w+)*\.(?:map|filter|slice|concat)\(|Array\.from\(/)) continue;
    add({ ruleId: 29884, code: 'BUG-207', severity: 'HIGH', lineIdx: at(m.index!),
      title: `Math.${m[1]}(${m[2]}) Given an Array`,
      why: `Math.${m[1]} takes numbers, not an array, so Math.${m[1]}(${m[2]}) is NaN (or the single value for a one-item array).`,
      fix: `Spread it: Math.${m[1]}(...${m[2]}) (or reduce for very large arrays).` });
  }

  // BUG-208: new URL(req.url) in a Node http / Express server (req.url is a path)
  if (/\bfrom\s+['"](?:express|node:http|http|fastify|koa)['"]|require\(\s*['"](?:express|http|node:http)['"]\s*\)/.test(c) && !/from\s+['"]next/.test(c)) {
    for (const m of c.matchAll(/\bnew\s+URL\(\s*req\.url\s*\)/g)) add({ ruleId: 29885, code: 'BUG-208', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'new URL(req.url) Without a Base in a Node Server',
      why: 'In Node http / Express, req.url is only the path ("/users?id=1"), so new URL(req.url) throws "Invalid URL" on every request.',
      fix: 'Pass a base: new URL(req.url, `http://${req.headers.host}`).' });
  }

  // BUG-209: Error spread or serialized loses message and stack
  const catchBlocks: { n: string; s: number; e: number }[] = [];
  for (const m of c.matchAll(/\bcatch\s*\(\s*(\w+)[^)]*\)\s*\{/g)) { const b = blockAfter(c, m.index! + m[0].length - 1); if (b) catchBlocks.push({ n: m[1], ...b }); }
  for (const m of c.matchAll(/\{\s*\.\.\.(err|error|e)\s*\}|JSON\.stringify\(\s*(err|error)\s*\)/g)) {
    const n = m[1] ?? m[2];
    if (!catchBlocks.some((b) => b.n === n && m.index! > b.s && m.index! < b.e)) continue;
    add({ ruleId: 29886, code: 'BUG-209', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: `Caught ${n} Copied With Spread / JSON.stringify`,
      why: 'message and stack are not enumerable on Error objects, so the copy is {} : logs and API responses lose the actual error text.',
      fix: `Pick the fields: { message: ${n}.message, name: ${n}.name } (or log ${n} itself).` });
  }

  // BUG-210: setMonth(getMonth() + n) overflows on the 29th-31st
  for (const m of c.matchAll(/\b(\w+)\.setMonth\(\s*\1\.getMonth\(\)\s*[+-]\s*\w+\s*\)/g)) if (c.split('\n')[at(m.index!)].length < 400) add({ ruleId: 29887, code: 'BUG-210', severity: 'MEDIUM', lineIdx: at(m.index!),
    title: 'setMonth(getMonth() ± n) Skips Short Months',
    why: 'Jan 31 + 1 month becomes Mar 3 because February has no 31st: renewal, trial-end and billing dates jump a month for users who signed up late in the month.',
    fix: 'Clamp the day (set day to min(day, days in target month)) or use date-fns addMonths().' });

  // BUG-211: global regex reused with .test() keeps lastIndex between calls
  // Module-level only: a regex created inside the function is fresh on every call
  for (const m of c.matchAll(/^(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*\/(?:\\.|\[(?:\\.|[^\]\n])*\]|[^/\\\n[])+\/[a-z]*g[a-z]*\s*;?\s*$/gm)) {
    for (const t of c.matchAll(new RegExp(`\\b${m[1]}\\.test\\(`, 'g'))) add({ ruleId: 29888, code: 'BUG-211', severity: 'HIGH', lineIdx: at(t.index!),
      title: `${m[1]}.test() on a Global Regex Alternates Between true and false`,
      why: `With the g flag, test() remembers lastIndex, so calling ${m[1]}.test() on the next string starts mid-way: valid input is rejected every other time.`,
      fix: `Remove the g flag from ${m[1]} (or reset ${m[1]}.lastIndex = 0 before each test).` });
  }

  // BUG-212: BigInt mixed with a number literal
  for (const m of c.matchAll(/\bBigInt\([^()]*\)\s*[-+*/%]\s*\d+(?![\dn.])/g)) add({ ruleId: 29889, code: 'BUG-212', severity: 'HIGH', lineIdx: at(m.index!),
    title: 'BigInt Combined With a Number',
    why: 'Arithmetic between BigInt and Number throws "Cannot mix BigInt and other types" (TypeError).',
    fix: 'Use a BigInt literal (1n) or convert explicitly with Number(…) / BigInt(…).' });

  // BUG-213: JSON.stringify on a Map, Set or FormData gives {}
  for (const m of c.matchAll(/\bJSON\.stringify\(\s*(\w+)\s*[,)]/g)) {
    const kind = declared(m[1], /new\s+Map\b/) ? 'Map' : declared(m[1], /new\s+Set\b/) ? 'Set' : declared(m[1], /new\s+FormData\b/) ? 'FormData' : '';
    if (kind) add({ ruleId: 29890, code: 'BUG-213', severity: 'HIGH', lineIdx: at(m.index!),
      title: `JSON.stringify(${m[1]}) on a ${kind} Sends {}`,
      why: `A ${kind} has no enumerable properties, so JSON.stringify returns "{}": the request or cache entry is empty.`,
      fix: kind === 'Set' ? `Use JSON.stringify([...${m[1]}]).` : `Use JSON.stringify(Object.fromEntries(${m[1]})).` });
  }

  // BUG-214: Supabase .in() given a string instead of an array
  for (const m of c.matchAll(/\.in\(\s*['"][\w.]+['"]\s*,\s*(?:['"`]\(|[\w.]+\.join\()/g)) add({ ruleId: 29891, code: 'BUG-214', severity: 'HIGH', lineIdx: at(m.index!),
    title: '.in() Filter Given a String Instead of an Array',
    why: 'supabase-js builds the in.(…) list from an array; a pre-joined string is sent as one quoted value, so the filter matches nothing (or errors).',
    fix: "Pass the array: .in('id', ids)." });

  // BUG-215: Supabase textSearch on raw user input without the websearch type
  for (const m of c.matchAll(/\.textSearch\(\s*['"][\w.]+['"]\s*,\s*([\w.]+(?:\([^()]*\))?)\s*\)/g)) {
    if (/^['"]/.test(m[1])) continue;
    add({ ruleId: 29892, code: 'BUG-215', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'textSearch() on User Input Uses to_tsquery Syntax',
      why: 'Without a type, textSearch uses to_tsquery, which rejects plain phrases: searching "red shoes" or a word with an apostrophe returns a syntax error instead of results.',
      fix: "Pass the type: .textSearch('fts', query, { type: 'websearch' })." });
  }

  // BUG-216: JWT expiresIn given in milliseconds
  for (const m of c.matchAll(/\bexpiresIn\s*:\s*(\d{7,}|(?:\d+\s*\*\s*)+1000\b|1000\s*\*|Date\.now\(\))/g)) {
    if (!/\bjwt\b|jsonwebtoken|\.sign\(|SignJWT/.test(c)) continue;
    add({ ruleId: 29893, code: 'BUG-216', severity: 'HIGH', lineIdx: at(m.index!),
      title: 'JWT expiresIn Given in Milliseconds',
      why: 'A numeric expiresIn is read as seconds, so a value meant as 1 hour in ms lasts about 41 days (and Date.now() lasts 50,000 years): stolen tokens stay valid.',
      fix: "Use seconds or a string: expiresIn: 60 * 60 or expiresIn: '1h'." });
  }

  // BUG-217: timingSafeEqual on inputs that may differ in length
  for (const m of c.matchAll(/\btimingSafeEqual\(/g)) {
    const before = c.slice(Math.max(0, m.index! - 400), m.index!);
    if (/\.length\s*!==?|\.length\s*===?|byteLength/.test(before + c.slice(m.index!, m.index! + 120))) continue;
    add({ ruleId: 29894, code: 'BUG-217', severity: 'MEDIUM', lineIdx: at(m.index!),
      title: 'timingSafeEqual Without a Length Check',
      why: 'timingSafeEqual throws "Input buffers must have the same byte length" (RangeError) for a wrong-length signature or token, so a bad request returns 500 instead of 401.',
      fix: 'Compare lengths first: if (a.length !== b.length) return false; then timingSafeEqual(a, b).' });
  }

  // BUG-218: Next.js 15+ cookies() / headers() used without await
  if (nextMajor >= 15) {
    for (const m of c.matchAll(/(?<!await\s)(?<!await\s\()\b(cookies|headers|draftMode)\(\)\.(get|getAll|set|has|delete|isEnabled)\b/g)) add({ ruleId: 29895, code: 'BUG-218', severity: nextMajor >= 16 ? 'HIGH' : 'MEDIUM', lineIdx: at(m.index!),
      title: `${m[1]}().${m[2]} Without await (Next.js ${nextMajor})`,
      why: `Since Next.js 15, ${m[1]}() returns a Promise${nextMajor >= 16 ? ' and synchronous access was removed' : ''}: ${m[1]}().${m[2]} reads a property of the Promise, which is undefined or throws.`,
      fix: `Await it: (await ${m[1]}()).${m[2]}(…).` });
  }

  void path;
}

/** Indexes of the lines in the indented block under the header at `i`. */
function pyBody(lines: string[], i: number): number[] {
  const ind = (lines[i].match(/^\s*/)?.[0].length) ?? 0;
  const out: number[] = [];
  for (let j = i + 1; j < lines.length; j++) {
    if (!lines[j].trim()) continue;
    if ((lines[j].match(/^\s*/)?.[0].length ?? 0) <= ind) break;
    out.push(j);
  }
  return out;
}

function evaluatePy(lines: string[], add: Add) {
  const src = lines.join('\n');
  const isComment = (l: string) => /^\s*#/.test(l);

  lines.forEach((l, i) => {
    if (isComment(l)) return;
    // BUG-167: dict / set / list changed while iterating over it
    const f = /^\s*(?:async\s+)?for\s+[\w, ()]+\s+in\s+(?:self\.)?(\w+)(?:\.(?:keys|items|values)\(\))?\s*:/.exec(l);
    if (f) {
      const n = f[1].replace(/^self\./, '');
      const mut = new RegExp(`^\\s*(?:del\\s+(?:self\\.)?${n}\\[|(?:self\\.)?${n}\\.(?:pop|remove|discard|add|popitem|clear|update|setdefault)\\()`);
      const j = pyBody(lines, i).find((k) => mut.test(lines[k]));
      if (j !== undefined) add({ ruleId: 29838, code: 'BUG-167', severity: 'HIGH', lineIdx: j,
        title: `${n} Modified While Looping Over It`,
        why: `Changing ${n} inside "for … in ${n}" raises "RuntimeError: dictionary changed size during iteration" for dicts and sets, and silently skips items for lists.`,
        fix: `Iterate over a copy: for … in list(${n}${/\.items\(\)/.test(l) ? '.items()' : ''}):, or build a new collection with a comprehension.` });
    }
    // BUG-168: %M (minutes) used as the month in a date format
    const d = /(?:strftime|strptime)\([^)]*?['"]([^'"]*%[Yy][-/.]%M[-/.]%d[^'"]*|[^'"]*%d[-/.]%M[-/.]%[Yy][^'"]*)['"]/.exec(l);
    if (d) add({ ruleId: 29839, code: 'BUG-168', severity: 'HIGH', lineIdx: i,
      title: `Date Format "${d[1]}" Uses %M (Minutes) as the Month`,
      why: '%M is minutes and %m is the month, so dates are printed with the minute in the month slot ("2024-37-05") or parsed into the wrong month.',
      fix: `Use %m: "${d[1].replace('%M', '%m')}".` });
  });

  // BUG-178: timedelta.seconds drops whole days
  if (/\bimport\s+datetime\b|\bfrom\s+datetime\s+import\b/.test(src)) {
    const deltas = new Set<string>();
    for (const m of src.matchAll(/^\s*(\w+)\s*=\s*[^=\n#]+?\s-\s[^=\n#]+$/gm)) deltas.add(m[1]);
    lines.forEach((l, i) => {
      if (isComment(l)) return;
      const m = /\(([^()]*\s-\s[^()]*)\)\.seconds\b|\b(\w+)\.seconds\b/.exec(l);
      if (!m || (m[2] && !deltas.has(m[2]))) return;
      add({ ruleId: 29849, code: 'BUG-178', severity: 'MEDIUM', lineIdx: i,
        title: 'timedelta.seconds Used as the Total Duration',
        why: '.seconds is only the seconds part (0-86399) and ignores .days, so a 2-day difference reads as a few seconds: expiry and rate checks pass when they should fail.',
        fix: 'Use .total_seconds().' });
    });
  }

  // BUG-184: coroutine called without await inside an async function
  // Async generators (a yield in the body) are meant to be called without await
  const asyncDefs = new Set<string>();
  lines.forEach((l, i) => {
    const d = /^\s*async\s+def\s+(\w+)/.exec(l);
    if (d && !pyBody(lines, i).some((k) => /\byield\b/.test(lines[k]))) asyncDefs.add(d[1]);
  });
  if (asyncDefs.size) {
    lines.forEach((l, i) => {
      if (!/^\s*async\s+def\s/.test(l)) return;
      for (const k of pyBody(lines, i)) {
        const m = /^\s*(?:self\.)?(\w+)\(.*\)\s*$/.exec(lines[k]);
        // A line that continues an open expression (async with (…,  x = (…) is an argument, not a statement
        const prev = lines.slice(0, k).reverse().find((x) => x.trim())?.trim() ?? '';
        if (m && asyncDefs.has(m[1]) && !/[([{,\\=]$|\b(?:and|or|not|in)$/.test(prev)) add({ ruleId: 29855, code: 'BUG-184', severity: 'HIGH', lineIdx: k,
          title: `Coroutine ${m[1]}() Called Without await`,
          why: `${m[1]} is async, so calling it only creates a coroutine object; the body never runs (Python warns "coroutine was never awaited") and the work silently does not happen.`,
          fix: `await ${m[1]}(…), or schedule it with asyncio.create_task(${m[1]}(…)).` });
      }
    });
  }
}

function evaluatePy2(lines: string[], add: Add) {
  const src = lines.join('\n');
  const isComment = (l: string) => /^\s*#/.test(l);
  const moduleVars = new Set([...src.matchAll(/^([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)/gm)].map((m) => m[1]));

  lines.forEach((l, i) => {
    if (isComment(l)) return;
    // BUG-220: os.path.join with an absolute second part discards the base directory
    const j = /\bos\.path\.join\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(?:f?['"])\/(?!\/)/.exec(l);
    if (j) add({ ruleId: 29897, code: 'BUG-220', severity: 'HIGH', lineIdx: i,
      title: 'os.path.join() With an Absolute Second Path',
      why: 'When a later part starts with "/", os.path.join throws away everything before it, so the file is read from or written to the filesystem root instead of your base directory.',
      fix: 'Drop the leading slash ("uploads/…"), or use pathlib: base / "uploads" / name.' });

    // BUG-221: module-level variable updated in a function without `global`
    const d = /^(\s*)def\s+\w+\(/.exec(l);
    if (d && moduleVars.size) {
      const body = pyBody(lines, i);
      const declaredGlobal = new Set(body.flatMap((k) => /^\s*(?:global|nonlocal)\s+(.+)$/.exec(lines[k])?.[1].split(',').map((s) => s.trim()) ?? []));
      const assignedLocal = new Set(body.flatMap((k) => { const a = /^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)/.exec(lines[k]); return a ? [a[1]] : []; }));
      for (const k of body) {
        const a = /^\s*([A-Za-z_]\w*)\s*(?:\+|-|\*|\/|\/\/|%|\|)=/.exec(lines[k]);
        if (a && moduleVars.has(a[1]) && !declaredGlobal.has(a[1]) && !assignedLocal.has(a[1])) {
          add({ ruleId: 29898, code: 'BUG-221', severity: 'HIGH', lineIdx: k,
            title: `Module Variable ${a[1]} Updated Without "global"`,
            why: `Augmented assignment makes ${a[1]} local to the function, so reading it first raises "UnboundLocalError: local variable '${a[1]}' referenced before assignment" every time.`,
            fix: `Add "global ${a[1]}" at the top of the function (or keep the counter in an object / class attribute).` });
          break;
        }
      }
    }

    // BUG-222: UploadFile read twice without seek(0)
    const r = /^\s*(?:\w+\s*=\s*)?await\s+(\w+)\.read\(\)/.exec(l);
    if (r) {
      for (let k = i + 1; k < Math.min(lines.length, i + 40); k++) {
        if (new RegExp(`\\b${r[1]}\\.seek\\(`).test(lines[k]) || /^\s*(?:async\s+)?def\s/.test(lines[k])) break;
        if (new RegExp(`\\bawait\\s+${r[1]}\\.read\\(\\)`).test(lines[k])) {
          add({ ruleId: 29899, code: 'BUG-222', severity: 'MEDIUM', lineIdx: k,
            title: `${r[1]}.read() Called a Second Time Without seek(0)`,
            why: 'The first read() consumed the upload, so the second read returns b"" and the saved or parsed file is empty.',
            fix: `Keep the bytes from the first read, or call await ${r[1]}.seek(0) before reading again.` });
          break;
        }
      }
    }
  });
}

export function evaluateLogicGeminiRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  if (/\.[cm]?[jt]sx?$/i.test(path)) { evaluateJs(path, c, add); evaluateJs2(path, c, add, context?.packageMajors.get('next') ?? 0); }
  else if (/\.py$/i.test(path)) { const pl = c.replace(/\r/g, '').split('\n'); evaluatePy(pl, add); evaluatePy2(pl, add); }
  else return { findings, logs };

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
