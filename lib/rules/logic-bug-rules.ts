/**
 * Logic bugs that AI-written JS/TS code ships with (BUG-xx, Rule IDs 29601-29699).
 *
 * These are reliability findings (type VIBECARE): the code runs, but does the wrong thing — a write that never
 * executes, a redirect that is swallowed, an effect that loops forever. They cost score but never fail the gate.
 * Every rule matches a specific, provable mistake (React, Next.js, Supabase, Prisma, Stripe docs); none fires on
 * the mere absence of a call.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const lineAt = (content: string, offset: number) => content.slice(0, Math.max(0, offset)).split('\n').length - 1;
const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*)/.test(l);

/** Index just past the bracket that closes the one at `open` ('(' or '{'), skipping strings and template literals. */
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

const DB_WRITE = /\.(?:insert|update|upsert|delete)\s*\(/;

export function evaluateLogicBugRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.[cm]?[jt]sx?$/i.test(path) || /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e)\/|\.(?:test|spec)\.[jt]sx?$/i.test(path)) {
    return { findings, logs };
  }
  const c = cleanContent;
  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  const usesReact = /from\s+['"]react['"]|\buseEffect\b/.test(c);

  // BUG-01: Supabase / Prisma / Drizzle write that is never awaited. Their query builders are lazy thenables:
  // without await, .then() or return the request is never sent.
  lines.forEach((l, i) => {
    if (isComment(l)) return;
    const sb = /^\s*(\w*supabase\w*|\w*[Cc]lient|admin|sb)\s*\.from\(\s*['"`][^'"`]+['"`]\s*\)\s*\.(?:insert|update|upsert|delete)\s*\(/i.exec(l);
    const orm = /^\s*(prisma|db|tx)\s*\.\w+\s*\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/.exec(l);
    if (!sb && !orm) return;
    const prev = lines.slice(0, i).reverse().find((x) => x.trim() && !isComment(x)) || '';
    if (/[[,(]\s*$|=>\s*$|=\s*$|\breturn\s*$/.test(prev)) return; // element of $transaction([...]), argument, arrow body, assignment
    const stmt = c.slice(c.split('\n').slice(0, i).join('\n').length + (i ? 1 : 0));
    const open = stmt.indexOf('(', stmt.search(/\.(?:insert|update|upsert|delete|create|createMany|updateMany|deleteMany)\s*\(/));
    const end = closeOf(stmt, open);
    const rest = end === -1 ? '' : stmt.slice(end, end + 400);
    // A chained .eq()/.select() is still the same builder; it runs only if something awaits or thens it
    const tail = rest.replace(/^(?:\s*\.(?!then\b|catch\b|finally\b)\w+\s*\((?:[^()]|\([^()]*\))*\))*/, '');
    if (/^\s*\.(?:then|catch|finally)\b/.test(tail)) return;
    add({ ruleId: 29601, code: 'BUG-01', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
      title: `Database Write Is Never Awaited, So It Never Runs (${sb ? 'Supabase' : 'Prisma/ORM'})`,
      why: `${sb ? 'Supabase' : 'Prisma and Drizzle'} queries are lazy: the request is sent only when the builder is awaited or .then() is called. This line creates the query and drops it, so nothing is written and no error is ever reported.`,
      fix: 'Add await (and check the returned error): const { error } = await supabase.from(...).insert(...); if (error) throw error;' });
  });

  // BUG-02: next/navigation redirect() / notFound() inside try { } whose catch swallows it
  if (/from\s+['"]next\/navigation['"]/.test(c)) {
    for (const m of c.matchAll(/\btry\s*\{/g)) {
      const open = m.index! + m[0].length - 1;
      const end = closeOf(c, open);
      if (end === -1) continue;
      const body = c.slice(open, end);
      const r = body.search(/\b(?:redirect|permanentRedirect|notFound)\s*\(/);
      if (r === -1) continue;
      const after = c.slice(end);
      const cm = /^\s*catch\s*(?:\([^)]*\))?\s*\{/.exec(after);
      if (!cm) continue;
      const cOpen = end + cm[0].length - 1;
      const cBody = c.slice(cOpen, closeOf(c, cOpen));
      if (/\bthrow\b|unstable_rethrow|isRedirectError|isNotFoundError|NEXT_REDIRECT|digest/.test(cBody)) continue;
      add({ ruleId: 29602, code: 'BUG-02', severity: 'HIGH', category: 'Logic Bug', lineIdx: lineAt(c, open + r),
        title: 'redirect() Inside try/catch Is Swallowed by the catch Block',
        why: 'Next.js redirect() and notFound() work by throwing a special error. The surrounding catch catches it, so the user is never redirected and the error branch runs even when the action succeeded.',
        fix: 'Call redirect() after the try/catch (store the result in a variable), or call unstable_rethrow(error) first thing in the catch block.' });
    }
  }

  if (usesReact) {
    for (const m of c.matchAll(/\buse(?:Layout)?Effect\s*\(/g)) {
      const open = m.index! + m[0].length - 1;
      const { args, end } = callArgs(c, open);
      if (end === -1 || !args.length) continue;
      const cb = args[0].trim();
      const idx = lineAt(c, m.index!);

      // BUG-03: async function passed straight to useEffect
      if (/^async\b/.test(cb)) {
        add({ ruleId: 29603, code: 'BUG-03', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: idx,
          title: 'Async Function Passed Directly to useEffect',
          why: 'An async effect returns a Promise, which React treats as the cleanup function: cleanup never runs, React logs an error, and responses that arrive after unmount or a dependency change still update state (race conditions).',
          fix: 'Define the async function inside the effect and call it: useEffect(() => { let cancelled = false; (async () => { ... if (!cancelled) setX(data); })(); return () => { cancelled = true; }; }, [deps]);' });
        continue;
      }

      // BUG-04: effect without a dependency array that sets state, so every render schedules another render
      if (args.length === 1 && /\bset[A-Z]\w*\s*\(|\.then\(\s*set[A-Z]\w*\s*\)/.test(cb) && /^(?:\([^)]*\)|\w+)\s*=>|^function\b/.test(cb)) {
        add({ ruleId: 29604, code: 'BUG-04', severity: 'HIGH', category: 'Logic Bug', lineIdx: idx,
          title: 'useEffect Without a Dependency Array Sets State (Infinite Render Loop)',
          why: 'With no dependency array the effect runs after every render; it sets state, which renders again, which runs the effect again. With a fetch inside, this floods the API with requests.',
          fix: 'Pass the dependency array: [] to run once on mount, or the values the effect reads ([userId]).' });
      }

      // BUG-05: interval / listener / subscription started in an effect and never cleaned up
      const leak = /\b(setInterval|addEventListener|\.subscribe|\.on\(\s*['"`])\s*\(?/.exec(cb);
      if (leak && !/\breturn\b/.test(cb)) {
        const kind = leak[1] === 'setInterval' ? 'setInterval' : leak[1] === 'addEventListener' ? 'addEventListener' : 'subscription';
        add({ ruleId: 29605, code: 'BUG-05', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: idx + lineAt(cb, cb.indexOf(leak[0])),
          title: `${kind} Started in useEffect Without Cleanup`,
          why: `The effect never returns a cleanup, so the ${kind} keeps running after the component unmounts (and doubles in React Strict Mode), leaking memory and calling setState on an unmounted component.`,
          fix: kind === 'setInterval'
            ? 'Return a cleanup: const id = setInterval(...); return () => clearInterval(id);'
            : kind === 'addEventListener'
              ? 'Return a cleanup: window.addEventListener("resize", onResize); return () => window.removeEventListener("resize", onResize);'
              : 'Return a cleanup that unsubscribes: const channel = supabase.channel(...).subscribe(); return () => { supabase.removeChannel(channel); };' });
      }
    }

    // BUG-09: state array sorted / reversed in place inside its setter
    const stateVars = new Set([...c.matchAll(/const\s*\[\s*(\w+)\s*,\s*set\w+\s*\]\s*=\s*(?:React\.)?useState\b/g)].map((m) => m[1]));
    lines.forEach((l, i) => {
      const m = /\bset[A-Z]\w*\(\s*(\w+)\.(sort|reverse)\s*\(/.exec(l);
      if (m && stateVars.has(m[1]) && !isComment(l)) {
        add({ ruleId: 29609, code: 'BUG-09', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: i,
          title: `State Array ${m[1]} Mutated In Place With .${m[2]}()`,
          why: `.${m[2]}() changes the existing array and returns the same reference, so React sees no change and may skip the re-render; other code holding ${m[1]} sees it reordered too.`,
          fix: `Copy before reordering: set${m[1][0].toUpperCase()}${m[1].slice(1)}([...${m[1]}].${m[2]}(...)) or use ${m[1]}.to${m[2] === 'sort' ? 'Sorted' : 'Reversed'}().` });
      }
    });
  }

  // BUG-06: async callback in forEach: nothing awaits it, the function returns before the work is done
  lines.forEach((l, i) => {
    if (!isComment(l) && /\.forEach\(\s*async\b/.test(l)) {
      add({ ruleId: 29606, code: 'BUG-06', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
        title: 'async Callback in forEach Is Never Awaited',
        why: 'forEach ignores the Promises its callback returns, so the code after it (the response, a redirect, a success toast) runs before the work finishes, and any error becomes an unhandled rejection that is never reported.',
        fix: 'Use for (const item of items) { await work(item); } for sequential work, or await Promise.all(items.map(async (item) => work(item))); for parallel work.' });
    }
  });

  // BUG-07: Supabase .range() end is inclusive; from + pageSize returns one row too many
  if (/\.range\s*\(/.test(c) && /supabase|\.from\(/.test(c)) {
    for (const m of c.matchAll(/\.range\s*\(/g)) {
      const { args } = callArgs(c, m.index! + m[0].length - 1);
      if (args.length !== 2) continue;
      const [from, to] = args.map((a) => a.trim());
      if (!/[+*]/.test(to) || /-\s*1\b/.test(to) || /^\d+$/.test(to)) continue;
      // End built from the start plus the page size: (page + 1) * size, from + size, offset + limit
      if (!/(?:limit|size|per_?page|pageSize|count|take)/i.test(to) && !to.includes(from)) continue;
      add({ ruleId: 29607, code: 'BUG-07', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: lineAt(c, m.index!),
        title: 'Supabase .range() End Is Inclusive (Off-by-One Pagination)',
        why: `.range(from, to) returns rows from..to inclusive, so ${to} returns pageSize + 1 rows: every page repeats the first row of the next page.`,
        fix: `Subtract one from the end: .range(${from}, ${to} - 1).` });
    }
  }

  // BUG-08: comparison with NaN is always false
  lines.forEach((l, i) => {
    if (!isComment(l) && /[!=]==?\s*NaN\b|\bNaN\s*[!=]==?/.test(l)) {
      add({ ruleId: 29608, code: 'BUG-08', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: i,
        title: 'Comparison With NaN Is Always False',
        why: 'NaN is not equal to anything, including itself, so x === NaN is always false and x !== NaN always true: the validation never triggers.',
        fix: 'Use Number.isNaN(x) (or !Number.isFinite(x) to also reject Infinity).' });
    }
  });

  // BUG-10: Stripe amount given in dollars; Stripe expects the smallest currency unit (cents) as an integer
  if (/\bstripe\b/i.test(c)) {
    const decimals = new Set([...c.matchAll(/\bconst\s+(\w+)\s*(?::\s*number)?\s*=\s*\d+\.\d+\s*;/g)].map((m) => m[1]));
    lines.forEach((l, i) => {
      const m = /\b(unit_amount|amount)\s*:\s*(\d+\.\d+|\w+)\b/.exec(l);
      if (!m || isComment(l)) return;
      if (!(/^\d+\.\d+$/.test(m[2]) || decimals.has(m[2]))) return;
      add({ ruleId: 29610, code: 'BUG-10', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
        title: `Stripe ${m[1]} Given in Dollars Instead of Cents`,
        why: `Stripe amounts are integers in the smallest currency unit, so ${m[2]} is rejected (non-integer) or, once rounded, charges 100x less than intended ($0.20 instead of $19.99).`,
        fix: `Pass cents as an integer: ${m[1]}: Math.round(price * 100) (1999 for $19.99), or keep prices in cents everywhere.` });
    });
  }

  // BUG-11: localStorage / sessionStorage read at module top level crashes server rendering
  if (/\.[jt]sx$/i.test(path) || /^\s*['"]use client['"]/m.test(c)) {
    lines.forEach((l, i) => {
      if (/^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:JSON\.parse\(\s*)?(?:window\.)?(?:localStorage|sessionStorage)\.getItem\(/.test(l)) {
        add({ ruleId: 29611, code: 'BUG-11', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
          title: 'localStorage Read at Module Load Crashes Server Rendering',
          why: "Client components are also rendered on the server, where localStorage does not exist; this line runs when the module loads and throws ReferenceError: localStorage is not defined, breaking the page.",
          fix: 'Read it inside useEffect (or a lazy useState initializer guarded by typeof window !== "undefined") and render a default until it is loaded.' });
      }
    });
  }

  // BUG-13: empty catch followed by a success message: failures are reported to the user as success
  lines.forEach((l, i) => {
    if (isComment(l) || !/\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}/.test(l)) return;
    const next = lines.slice(i, i + 4).join('\n');
    if (/\b(?:alert|toast(?:\.success)?|setSuccess|setSaved|setDone|notify(?:Success)?)\s*\(\s*(?:['"`][^'"`]*(?:saved|success|done|sent|updated|created|deleted|complete)|true)/i.test(next)) {
      add({ ruleId: 29613, code: 'BUG-13', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: i,
        title: 'Error Swallowed, Then Success Shown to the User',
        why: 'The empty catch discards the failure and the code continues to the success message, so users are told their data was saved when it was not.',
        fix: 'Show success only on the success path: try { await save(); toast.success("Saved"); } catch (e) { toast.error("Could not save"); report(e); }' });
    }
  });

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
