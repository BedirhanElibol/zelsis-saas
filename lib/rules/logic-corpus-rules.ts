/**
 * Bugs from the real-world bug corpus (.cache/logic-bug-corpus.txt, verified sources) that no rule caught
 * (BUG-133.., Rule IDs 29780-29799): store mutation in selectors, setters called while rendering, Radix value
 * handlers reading events, react-hook-form on custom inputs, aria-hidden over focusable content, Expo Router params,
 * FastAPI background tasks and path params, naive vs aware datetimes, SvelteKit actions and Gin handlers.
 *
 * Reliability findings (type VIBECARE). Each rule matches one specific, documented mistake on the reported line.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category?: string; lineIdx: number; why: string; fix: string }

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|(?:^|\/)vendor\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?|testdata)\/|\.(?:test|spec|stories)\.[jt]sx?$|_test\.(?:go|py)$|(?:^|\/)test_\w+\.py$/i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };

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

/** Bodies of capitalised function components: [start, end) offsets of the text between the outer braces. */
function componentBodies(c: string): { name: string; s: number; e: number }[] {
  const out: { name: string; s: number; e: number }[] = [];
  for (const x of c.matchAll(/(?:function\s+([A-Z]\w*)\s*(\()|(?:const|let)\s+([A-Z]\w*)\s*(?::[^=]+)?=\s*(?:\([^)]*\)|\w+)\s*(?::[^=>{]+)?=>\s*\{)/g)) {
    let open: number;
    if (x[1]) { const pe = closeOf(c, x.index! + x[0].length - 1); if (pe < 0) continue; open = c.indexOf('{', pe); }
    else open = x.index! + x[0].length - 1;
    const end = open < 0 ? -1 : closeOf(c, open);
    if (end > open) out.push({ name: x[1] || x[3], s: open + 1, e: end - 1 });
  }
  return out;
}

/** Offsets of statements that sit directly in the body (not inside a nested block, callback or JSX expression). */
function topLevelCalls(c: string, s: number, e: number, name: string): number[] {
  const out: number[] = [];
  let depth = 0;
  for (let i = s; i < e; i++) {
    const ch = c[i];
    if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < e && c[i] !== ch; i++) if (c[i] === '\\') i++; continue; }
    if ('({['.includes(ch)) depth++;
    else if (')}]'.includes(ch)) depth--;
    else if (depth === 0 && c.startsWith(name, i) && /[\s;{}]/.test(c[i - 1] ?? '\n') && /^\s*\(/.test(c.slice(i + name.length, i + name.length + 3))) {
      const lineStart = c.lastIndexOf('\n', i) + 1;
      if (/^\s*$/.test(c.slice(lineStart, i))) out.push(i);
    }
  }
  return out;
}

function evaluateJs(path: string, c: string, add: (h: Hit) => void) {
  const at = (off: number) => lineAt(c, off);

  // BUG-133: selector that sorts / reverses / splices the store's own array (mutates state in place)
  for (const x of c.matchAll(/\b(use[A-Z]\w*)\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\2\.[\w.]+\.(sort|reverse|splice)\(/g)) {
    if (!/Store|State|useStore|Atom/.test(x[1]) && !new RegExp(`\\b${x[1]}\\b[^\\n]*from\\s*['"][^'"]*(?:store|state|zustand)`, 'i').test(c)) continue;
    add({ ruleId: 29780, code: 'BUG-133', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
      title: `${x[1]} Selector Calls .${x[3]}() on Store State`,
      why: `.${x[3]}() changes the array in place, so this selector rewrites the store's data every render without going through set(): other components see the reordered list, and subscribers are not notified.`,
      fix: `Copy before ordering: ${x[1]}((s) => [...s.items].${x[3]}(...)) or use toSorted() / toReversed(), ideally with useShallow or a memoized selector.` });
  }

  // BUG-134: atom / store setter called directly while rendering
  for (const comp of componentBodies(c)) {
    const body = c.slice(comp.s, comp.e);
    const setters = new Set<string>();
    for (const m of body.matchAll(/(?:const|let)\s+(\w+)\s*=\s*useSetAtom\(|(?:const|let)\s*\[\s*\w*\s*,\s*(\w+)\s*\]\s*=\s*useAtom\(/g)) setters.add(m[1] || m[2]);
    for (const name of setters) {
      for (const off of topLevelCalls(c, comp.s, comp.e, name)) {
        add({ ruleId: 29781, code: 'BUG-134', severity: 'HIGH', category: 'Logic Bug', lineIdx: at(off),
          title: `${name}() Called While ${comp.name} Renders`,
          why: 'Setting shared state during render schedules another render of every subscriber, including this component, which sets it again: React reports "Cannot update a component while rendering a different component" or loops until "Too many re-renders".',
          fix: `Set it in an effect or event handler: useEffect(() => { ${name}(value); }, [value]), or derive the value instead of storing it.` });
      }
    }
  }

  // BUG-135: Radix / shadcn onValueChange handler that reads an event
  for (const x of c.matchAll(/\bonValueChange\s*=\s*\{\s*\(?\s*(\w+)\s*\)?\s*=>\s*([^}]*)\}/g)) {
    if (!new RegExp(`\\b${x[1]}\\.(?:target|currentTarget|preventDefault|nativeEvent)\\b`).test(x[2])) continue;
    add({ ruleId: 29782, code: 'BUG-135', severity: 'HIGH', category: 'Logic Bug', lineIdx: at(x.index!),
      title: `onValueChange Receives a Value, Not an Event (${x[1]}.target)`,
      why: `Radix Select / RadioGroup / Tabs / ToggleGroup call onValueChange with the new value (a string), so ${x[1]}.target is undefined and reading .value throws "Cannot read properties of undefined": choosing an option crashes the form.`,
      fix: `Use the value directly: onValueChange={(value) => setVal(value)}.` });
  }

  // BUG-136: react-hook-form register() spread onto a component that has no native input
  if (/from\s+['"]react-hook-form['"]/.test(c)) {
    for (const x of c.matchAll(/<(Switch|Select|Checkbox|RadioGroup|Slider|Combobox|DatePicker|Calendar|Toggle|ToggleGroup|MultiSelect|Rating)\b[^>]*\{\s*\.\.\.\s*register\(\s*(['"`][^'"`]+['"`])/g)) {
      const imp = new RegExp(`import[^;]*\\b${x[1]}\\b[^;]*from\\s*['"]([^'"]+)['"]`).exec(c);
      if (imp && !/components\/ui|@radix-ui|@\/ui|ui\/|shadcn|@headlessui|@mantine|@mui/.test(imp[1])) continue;
      add({ ruleId: 29783, code: 'BUG-136', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
        title: `register(${x[2]}) Spread Onto <${x[1]}>, Which Has No Native Input`,
        why: `register() wires onChange/ref to a native <input>. ${x[1]} (Radix/shadcn) reports changes through onCheckedChange / onValueChange instead, so react-hook-form never sees the value: it submits undefined or the default.`,
        fix: `Use a Controller: <Controller name=${x[2]} control={control} render={({ field }) => <${x[1]} checked={field.value} onCheckedChange={field.onChange} />} /> (or shadcn <FormField>).` });
    }
  }

  // BUG-137: aria-hidden="true" on an element that contains focusable controls
  for (const x of c.matchAll(/<([a-z][\w-]*)\b[^>]*\baria-hidden\s*=\s*(?:"true"|\{\s*true\s*\})[^>]*>/g)) {
    if (/\binert\b/.test(x[0])) continue;
    const close = c.indexOf(`</${x[1]}>`, x.index! + x[0].length);
    if (close < 0) continue;
    const inner = c.slice(x.index! + x[0].length, close);
    if (inner.includes(`<${x[1]}`)) continue; // nested same tag: the matching close is unclear
    const f = /<(?:button|a\s[^>]*href|input|select|textarea|Button|Link)\b(?![^>]*tabIndex\s*=\s*\{?\s*-1)/.exec(inner);
    if (!f) continue;
    add({ ruleId: 29784, code: 'BUG-137', severity: 'MEDIUM', category: 'UI Bug', lineIdx: at(x.index!),
      title: 'aria-hidden="true" Hides Focusable Controls',
      why: 'aria-hidden removes the element from screen readers but not from the Tab order, so keyboard users land on buttons that screen readers announce as nothing (WCAG 4.1.2; browsers now warn "Blocked aria-hidden on an element because its descendant retained focus").',
      fix: 'Use the inert attribute (hides and disables focus), or remove aria-hidden from containers with interactive content.' });
  }

  // BUG-138: Expo Router params used as a string without narrowing (they can be string[])
  if (/from\s+['"]expo-router['"]/.test(c)) {
    for (const x of c.matchAll(/(?:const|let)\s*\{([^}]+)\}\s*=\s*use(?:Local|Global)SearchParams\(\s*\)/g)) {
      for (const v of x[1].split(',').map((p) => p.split(':').pop()!.split('=')[0].trim()).filter(Boolean)) {
        const use = new RegExp(`\\b${v}\\.(toLowerCase|toUpperCase|split|trim|replace|startsWith|endsWith|includes|slice|substring|padStart|match)\\(`).exec(c.slice(x.index!));
        if (!use) continue;
        add({ ruleId: 29785, code: 'BUG-138', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index! + use.index),
          title: `Route Param ${v} May Be an Array: ${v}.${use[1]}() Can Crash`,
          why: `useLocalSearchParams returns string | string[] for each param (repeated query keys or catch-all routes). Calling .${use[1]}() on an array throws "${use[1]} is not a function" and the screen crashes.`,
          fix: `Type and narrow it: const { ${v} } = useLocalSearchParams<{ ${v}: string }>(); or const value = Array.isArray(${v}) ? ${v}[0] : ${v};` });
      }
    }
  }

  // BUG-139: SvelteKit form action returns a plain error object (status 200, form shows success)
  if (/(?:^|\/)\+page\.server\.[jt]s$/.test(path)) {
    const a = /export\s+const\s+actions\s*(?::[^=]+)?=\s*\{/.exec(c);
    if (a) {
      const end = closeOf(c, a.index + a[0].length - 1);
      const block = c.slice(a.index, end > 0 ? end : c.length);
      for (const x of block.matchAll(/\breturn\s*\{\s*(?:error|errors|message|success\s*:\s*false|invalid)\b/g)) {
        add({ ruleId: 29786, code: 'BUG-139', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(a.index + x.index!),
          title: 'Form Action Returns an Error Without fail()',
          why: 'A plain object from a SvelteKit action is a successful (200) result: use:enhance treats it as success, invalidates data and resets the form, so the validation error is lost.',
          fix: "Return it through fail(): import { fail } from '@sveltejs/kit'; return fail(400, { error: 'Email required' });" });
      }
    }
  }
}

function evaluatePy(lines: string[], content: string, add: (h: Hit) => void) {
  const code = lines.map((l) => l.replace(/(^|\s)#.*$/, '$1'));

  // BUG-140: FastAPI background task given the request's DB session (closed when the response is sent)
  code.forEach((l, i) => {
    const m = /\b(\w+)\.add_task\(\s*\w+\s*,([^)]*)\)/.exec(l);
    if (!m) return;
    // find the enclosing def and its Depends() session parameters
    let d = i;
    while (d >= 0 && !/^\s*(?:async\s+)?def\s/.test(code[d])) d--;
    if (d < 0) return;
    let sig = '';
    for (let k = d; k < Math.min(code.length, d + 8); k++) { sig += code[k]; if (/\)\s*(?:->[^:]+)?:\s*$/.test(code[k])) break; }
    const sessions = [...sig.matchAll(/(\w+)\s*:\s*[\w.[\]]*\s*=\s*Depends\(\s*get_\w*(?:db|session)\w*\s*\)|(\w+)\s*:\s*Annotated\[\s*(?:Async)?Session\b/g)].map((x) => x[1] || x[2]);
    const passed = sessions.find((s) => new RegExp(`(?:^|[,\\s=])${s}\\s*(?:,|$)`).test(m[2]));
    if (!passed) return;
    add({ ruleId: 29787, code: 'BUG-140', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
      title: `Background Task Receives the Request Session "${passed}"`,
      why: 'Background tasks run after the response is sent, but the yield dependency closes the session first. The task then fails with "Session is closed" / DetachedInstanceError, or writes nothing.',
      fix: 'Open a new session inside the task: def generate_csv(): with SessionLocal() as db: ...; pass ids, not the session or ORM objects.' });
  });

  // BUG-141: FastAPI path parameter without a type annotation (always str)
  code.forEach((l, i) => {
    const r = /^\s*@\w+\.(?:get|post|put|patch|delete)\(\s*(['"])([^'"]*\{(\w+)\}[^'"]*)\1/.exec(l);
    if (!r) return;
    let k = i + 1;
    while (k < code.length && /^\s*@/.test(code[k])) k++;
    const params = /def\s+\w+\s*\(([^)]*)\)/.exec(code.slice(k, k + 6).join(' '));
    if (!params) return;
    for (const p of r[2].matchAll(/\{(\w+)(?::\w+)?\}/g)) {
      const name = p[1];
      if (!new RegExp(`(?:^|,|\\()\\s*${name}\\s*(?:=|,|$)`).test(params[1].trim())) continue;
      if (!/id$|_id$|^id|page|num|count|year|limit|offset/i.test(name)) continue;
      add({ ruleId: 29788, code: 'BUG-141', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: k,
        title: `Path Parameter ${name} Has No Type, So It Is Always a String`,
        why: `Without an annotation FastAPI passes ${name} as str. Comparing it with an integer column (Item.id == "5") or doing arithmetic finds nothing or raises, and invalid values are not rejected with 422.`,
        fix: `Annotate it: def read_item(${name}: int): ...` });
    }
  });

  // BUG-142: naive datetime.now()/utcnow() compared with an aware datetime in the same file
  if (/timezone\.utc|tzinfo\s*=|ZoneInfo\(|pytz\.|\.astimezone\(|tz\s*=\s*\w/.test(content) && !/^\s*(?:from|import)\s+django\b/m.test(content)) {
    code.forEach((l, i) => {
      if (!/datetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)\s*[<>]=?|[<>]=?\s*datetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)/.test(l)) return;
      add({ ruleId: 29789, code: 'BUG-142', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: i,
        title: 'Naive datetime.now() Compared in a File That Uses Aware Datetimes',
        why: 'This module creates timezone-aware datetimes elsewhere. Comparing one with a naive now() raises "can\'t compare offset-naive and offset-aware datetimes", so the expiry check crashes the request.',
        fix: 'Use an aware now: datetime.now(timezone.utc).' });
    });
  }
}

function evaluateGo(lines: string[], add: (h: Hit) => void) {
  // BUG-143: Gin handler writes an error response inside if { } without return, then keeps going
  lines.forEach((l, i) => {
    const m = /^(\s*)(\w+)\.(AbortWithStatusJSON|AbortWithStatus|AbortWithError|JSON|IndentedJSON|String|Status)\(\s*(?:http\.Status(?!OK\b)\w+|[45]\d\d)\b/.exec(l);
    if (!m) return;
    // previous non-blank line opens an if block; next non-blank line closes it
    let p = i - 1; while (p >= 0 && !lines[p].trim()) p--;
    let n = i + 1; while (n < lines.length && !lines[n].trim()) n++;
    if (p < 0 || n >= lines.length || !/^\s*(?:if|}\s*else\s+if)\b.*\{\s*$/.test(lines[p]) || !/^\s*}\s*$/.test(lines[n])) return;
    let after = n + 1; while (after < lines.length && !lines[after].trim()) after++;
    // block ends the function, has an else, or the outer block returns right after it
    if (after >= lines.length || /^\s*(?:}\s*(?:else\b|$)|return\b)/.test(lines[after])) return;
    add({ ruleId: 29790, code: 'BUG-143', severity: 'HIGH', category: 'Logic Bug', lineIdx: i,
      title: `${m[2]}.${m[3]}() Without return: the Handler Keeps Running`,
      why: 'Gin does not stop the handler when you write a response or call Abort. Execution continues after the if block, runs the success path and writes a second response ("[WARNING] Headers were already written"), so invalid requests are processed anyway.',
      fix: `Return right after it: ${m[2]}.${m[3]}(...)\n${m[1]}return` });
  });
}

export function evaluateLogicCorpusRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  if (/\.[cm]?[jt]sx?$/i.test(path)) evaluateJs(path, c, add);
  else if (/\.py$/i.test(path)) evaluatePy(lines, file.content, add);
  else if (/\.go$/i.test(path)) evaluateGo(lines, add);
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
      category: h.category ?? 'Logic Bug',
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
