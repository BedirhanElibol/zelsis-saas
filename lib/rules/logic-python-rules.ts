/**
 * Python / Django / FastAPI / Flask logic bugs in AI-written backends (BUG-94.., Rule IDs 29704-29739).
 *
 * Reliability findings (type VIBECARE), like logic-data-rules.ts: the code runs but stores the wrong time, loses a cent,
 * returns 200 for an error or leaks connections. Every rule matches a specific, documented mistake on the reported line
 * (Python, Django, SQLAlchemy, FastAPI, Celery, Stripe docs); none fires on the mere absence of a call in the file.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const SKIP_PATH = /(?:^|\/)(?:tests?|__tests__|fixtures?|migrations)\/|_test\.py$|(?:^|\/)test_\w+\.py$|(?:^|\/)conftest\.py$/i;

/** Lines with comments and docstrings blanked, so prose never matches. */
function maskPy(lines: string[]): string[] {
  const code: string[] = [];
  let inDoc: string | null = null;
  for (const l of lines) {
    if (inDoc) { code.push(''); if (l.includes(inDoc)) inDoc = null; continue; }
    const t = /^\s*[rRbBuUfF]?("""|''')/.exec(l);
    if (t) { code.push(''); if (l.split(t[1]).length - 1 < 2) inDoc = t[1]; continue; }
    code.push(l.replace(/(^|\s)#.*$/, '$1'));
  }
  return code;
}

const indentOf = (l: string) => l.length - l.trimStart().length;

/** Line indexes of the indented block that starts after line `i` (a def / with / finally header). */
function blockOf(code: string[], i: number): number[] {
  const base = indentOf(code[i]);
  const out: number[] = [];
  for (let k = i + 1; k < code.length; k++) {
    const l = code[k];
    if (!l.trim()) continue;
    if (indentOf(l) <= base) break;
    out.push(k);
  }
  return out;
}

/** For each line, the index of the enclosing def line (or -1). */
function enclosingDefs(code: string[]): number[] {
  const owner = new Array<number>(code.length).fill(-1);
  code.forEach((l, i) => {
    if (/^\s*(?:async\s+)?def\s+\w+/.test(l)) for (const k of blockOf(code, i)) owner[k] = i;
  });
  return owner;
}

function evaluate(code: string[], content: string, add: (h: Hit) => void) {
  const isDjango = /^\s*(?:from|import)\s+django\b/m.test(content);
  const defOf = enclosingDefs(code);

  // BUG-94: default evaluated once at import (every row gets the same timestamp / uuid)
  code.forEach((l, i) => {
    const m = /\bdefault\s*=\s*((?:timezone|datetime(?:\.datetime)?|date|dt)\.(?:now|utcnow|today)\(\)|uuid\.uuid4\(\)|time\.time\(\))/.exec(l);
    if (!m || !/\b(?:models\.\w+Field|Column|mapped_column|Field|\w+Field)\s*\(/.test(l)) return;
    add({ ruleId: 29704, code: 'BUG-94', severity: 'MEDIUM', lineIdx: i,
      title: `Field default=${m[1]} Is Evaluated Once, at Import`,
      why: `${m[1]} runs when the module is loaded, not when a row is created, so every row saved by that process gets the same timestamp/id until the server restarts (Django also writes the frozen value into the next migration).`,
      fix: `Pass the callable without parentheses: default=${m[1].replace(/\(\)$/, '')}${/uuid4/.test(m[1]) ? '' : ' (or auto_now_add=True for created dates)'}.` });
  });

  // BUG-95: created/joined timestamp with auto_now=True (overwritten on every save)
  code.forEach((l, i) => {
    const m = /^\s*(\w*(?:created|joined|registered|signed_up|signup|creation|date_added|added)\w*)\s*=\s*models\.\w*(?:DateTime|Date)Field\([^)]*\bauto_now\s*=\s*True/i.exec(l);
    if (!m) return;
    add({ ruleId: 29705, code: 'BUG-95', severity: 'MEDIUM', lineIdx: i,
      title: `${m[1]} Uses auto_now=True and Changes on Every Save`,
      why: 'auto_now sets the field to now on every save(), so the "created" date moves each time the row is edited and the original creation time is lost.',
      fix: `Use auto_now_add=True for ${m[1]} (auto_now is for updated_at).` });
  });

  // BUG-96: environment flag read as a string ("False" is truthy)
  code.forEach((l, i) => {
    const env = String.raw`os\.(?:getenv|environ\.get)\(\s*['"](\w+)['"]`;
    let m = new RegExp(String.raw`\bbool\(\s*${env}[^)]*\)\s*\)`).exec(l);
    let how = 'bool() of any non-empty string is True';
    if (!m) { m = new RegExp(env + String.raw`\s*,\s*(?:False|True)\s*\)`).exec(l); how = 'a set variable is returned as a string, and "False", "0" and "no" are all truthy'; }
    if (!m) {
      m = new RegExp(String.raw`^\s*(?:if|elif)\s+(?:not\s+)?${env}\s*\)\s*:`).exec(l);
      if (m && !/DEBUG|ENABLE|DISABLE|_ON$|FLAG|TESTING|USE_|SECURE|SSL|VERBOSE|DRY_RUN|MAINTENANCE|FEATURE/i.test(m[1])) m = null;
      how = 'any non-empty value, including "false" and "0", is truthy';
    }
    if (!m) return;
    add({ ruleId: 29706, code: 'BUG-96', severity: 'MEDIUM', lineIdx: i,
      title: `${m[1]} Flag Read as a String: "False" Turns It On`,
      why: `Environment variables are strings; ${how}. Setting ${m[1]}=False in production leaves the flag enabled (for DEBUG that means tracebacks and settings shown to visitors).`,
      fix: `Compare explicitly: ${m[1].toLowerCase()} = os.getenv("${m[1]}", "false").lower() in ("1", "true", "yes").` });
  });

  // BUG-97: int(x * 100) truncates money (19.99 * 100 = 1998.9999... -> 1998)
  code.forEach((l, i) => {
    const m = /\bint\(\s*(?!round\()([^()]*(?:\([^()]*\))?[^()]*?)\s*\*\s*100\s*\)/.exec(l);
    // a division inside is a percentage, not money
    const money = /amount|price|cents|total|cost|fee|charge|unit_amount|subtotal|balance|dollar/i;
    if (!m || m[1].includes('/') || !(money.test(l) || (defOf[i] >= 0 && money.test(code[defOf[i]])))) return;
    add({ ruleId: 29707, code: 'BUG-97', severity: 'MEDIUM', lineIdx: i,
      title: 'int(price * 100) Truncates Floats and Loses a Cent',
      why: 'Floats are not exact: 19.99 * 100 is 1998.9999999999998, and int() truncates it to 1998, so Stripe charges (or you store) one cent less on many prices.',
      fix: `Round before converting: int(round(${m[1].trim()} * 100)), or keep money as Decimal / integer cents end to end.` });
  });

  // BUG-98: result of list.sort() / .reverse() / random.shuffle() assigned (always None)
  code.forEach((l, i) => {
    const m = /^\s*(\w+(?:\.\w+)?)\s*=\s*(?:([\w.\]\[]+)\.(sort)\(\s*(?:(?:key|reverse)\s*=[^)]*)?\)|([\w.\]\[]+)\.(reverse)\(\s*\)|random\.(shuffle)\([^)]*\))\s*$/.exec(l);
    if (!m) return;
    const fn = m[3] || m[5] || m[6];
    add({ ruleId: 29708, code: 'BUG-98', severity: 'MEDIUM', lineIdx: i,
      title: `${m[1]} Is Always None: ${fn}() Works in Place`,
      why: `${fn}() changes the list in place and returns None, so ${m[1]} is None and the next use fails with "'NoneType' object is not iterable" or silently returns an empty response.`,
      fix: fn === 'sort' ? `Use ${m[1]} = sorted(${m[2]}${/key|reverse/.test(l) ? ', ...' : ''}) or call ${m[2]}.sort() on its own line.` : fn === 'reverse' ? `Use ${m[1]} = list(reversed(${m[4]})) or ${m[4]}[::-1].` : `Call random.shuffle(...) on its own line, or use random.sample(items, len(items)).` });
  });

  // BUG-99: Celery task queued inside transaction.atomic() (worker may run before the commit)
  code.forEach((l, i) => {
    if (!/^\s*with\s+transaction\.atomic\(/.test(l) && !/^\s*@transaction\.atomic\b/.test(l)) return;
    const start = /^\s*@/.test(l) ? code.findIndex((x, k) => k > i && /^\s*(?:async\s+)?def\s/.test(x)) : i;
    if (start < 0) return;
    for (const k of blockOf(code, start)) {
      if (!/\.(?:delay|apply_async)\(/.test(code[k]) || /on_commit\s*\(/.test(code[k])) continue;
      add({ ruleId: 29709, code: 'BUG-99', severity: 'MEDIUM', lineIdx: k,
        title: 'Background Task Queued Before the Transaction Commits',
        why: 'The task is sent to the broker immediately, but the rows written in this atomic block are not visible until it commits. A fast worker reads the old data or gets DoesNotExist, and if the transaction rolls back the task still runs.',
        fix: 'Queue it after commit: transaction.on_commit(lambda: task.delay(obj.id)) (or task.delay_on_commit in Celery 5.4+).' });
    }
  });

  // BUG-100: FastAPI DB dependency that returns the session instead of yielding it (never closed)
  // get_db usually lives in deps.py and is used with Depends() in other files, so the name alone is enough
  {
    code.forEach((l, i) => {
      const d = /^\s*(?:async\s+)?def\s+(get_\w*(?:db|session|conn)\w*)\s*\(/i.exec(l);
      if (!d || (!new RegExp(String.raw`Depends\(\s*${d[1]}\s*\)`).test(content) && !/^get_(?:db|session|db_session|async_session)$/i.test(d[1]))) return;
      const body = blockOf(code, i).map((k) => code[k]).join('\n');
      if (/\byield\b/.test(body) || !/=\s*(?:SessionLocal|Session|async_session\w*|sessionmaker\w*|AsyncSessionLocal|\w*[Ss]ession\w*)\(\)/.test(body) || !/^\s*return\s+\w+\s*$/m.test(body) || /\bwith\b/.test(body)) return;
      add({ ruleId: 29710, code: 'BUG-100', severity: 'MEDIUM', lineIdx: i,
        title: `${d[1]}() Returns the Session, So It Is Never Closed`,
        why: 'FastAPI only runs cleanup for dependencies that yield. A returned session is never closed, so each request leaks a pooled connection and the app hangs with "QueuePool limit reached" under load.',
        fix: 'db = SessionLocal()\ntry:\n    yield db\nfinally:\n    db.close()' });
    });
  }

  // BUG-101: route returns an error body with HTTP 200
  const isRouteFile = /@(?:app|router|bp|blueprint|api)\.(?:get|post|put|patch|delete|route)\(/.test(content) || (isDjango && /JsonResponse/.test(content));
  if (isRouteFile) {
    code.forEach((l, i) => {
      const t = l.trim();
      const err = String.raw`\{\s*['"](?:error|errors|detail)['"]\s*:`;
      let m = new RegExp(String.raw`^return\s+${err}`).exec(t);
      let fix = 'Raise HTTPException(status_code=404, detail="...") (or return JSONResponse({...}, status_code=400)).';
      if (m && !/@(?:app|router|api)\.(?:get|post|put|patch|delete)\(/.test(content)) m = null; // plain dict return is only a response in FastAPI
      if (!m) { m = new RegExp(String.raw`^return\s+jsonify\(\s*${err}`).exec(t); fix = 'Return a status with it: return jsonify({"error": "..."}), 400.'; }
      if (!m) { m = new RegExp(String.raw`^return\s+JsonResponse\(\s*${err}`).exec(t); fix = 'Pass a status: JsonResponse({"error": "..."}, status=400).'; }
      if (!m) return;
      // multi-line call: read until the call closes
      let stmt = t;
      for (let k = i + 1; k < code.length && (stmt.split('(').length > stmt.split(')').length || stmt.split('{').length > stmt.split('}').length); k++) stmt += code[k].trim();
      if (/\)\s*,\s*\d{3}\b|status(?:_code)?\s*=|,\s*HTTPStatus\./.test(stmt)) return;
      add({ ruleId: 29711, code: 'BUG-101', severity: 'MEDIUM', lineIdx: i,
        title: 'Error Returned With HTTP 200 OK',
        why: 'The response has no status code, so it goes out as 200. Frontends that check res.ok / response.status treat the error as success, retries never happen and monitoring never sees the failure.',
        fix });
    });
  }

  // BUG-102: missing f prefix: "{name}" printed literally
  code.forEach((l, i) => {
    const call = /^\s*(?:return\s+|raise\s+\w+\(\s*|(?:print|logger\.\w+|logging\.\w+|log\.\w+|flash|messages\.\w+\(\s*request\s*,)\s*\(?\s*)(['"])((?:(?!\1).)*\{([A-Za-z_]\w*(?:\.\w+)?)\}(?:(?!\1).)*)\1/.exec(l);
    if (!call || /\{\{/.test(call[2])) return;
    const after = l.slice(call.index + call[0].length);
    if (/^\s*(?:\.format|%|\.format_map)/.test(after)) return;
    const pre = l.slice(0, call.index + call[0].length - call[2].length - 2);
    if (/[fF][rR]?$|[rR][fF]$/.test(pre)) return;
    const name = call[3].split('.')[0];
    const d = defOf[i];
    if (d < 0) return;
    const scope = [code[d], ...blockOf(code, d).filter((k) => k < i).map((k) => code[k])].join('\n');
    if (!new RegExp(String.raw`(?:[(,]\s*${name}\s*[:=,)]|^\s*${name}\s*(?::[^=]+)?=(?!=)|\bfor\s+(?:\w+\s*,\s*)*${name}\b|\bas\s+${name}\b)`, 'm').test(scope)) return;
    add({ ruleId: 29712, code: 'BUG-102', severity: 'LOW', lineIdx: i,
      title: `Missing f Prefix: "{${call[3]}}" Is Shown Literally`,
      why: `The string has no f prefix, so users and logs see the text {${call[3]}} instead of its value.`,
      fix: `Add the prefix: f${call[1]}...{${call[3]}}...${call[1]}.` });
  });

  // BUG-103: the same route registered twice (the second handler is never reached)
  const seen = new Map<string, number>();
  code.forEach((l, i) => {
    const m = /^\s*@(\w+)\.(get|post|put|patch|delete)\(\s*(['"])([^'"]+)\3/.exec(l);
    if (!m) return;
    const key = `${m[1]} ${m[2].toUpperCase()} ${m[4]}`;
    if (seen.has(key)) {
      add({ ruleId: 29713, code: 'BUG-103', severity: 'MEDIUM', lineIdx: i,
        title: `${m[2].toUpperCase()} ${m[4]} Is Registered Twice`,
        why: `FastAPI/Flask match the first route registered for ${m[2].toUpperCase()} ${m[4]} (line ${seen.get(key)! + 1}), so this handler never runs and changes made to it have no effect.`,
        fix: 'Delete the stale handler or give it its own path.' });
    } else seen.set(key, i);
  });

  // BUG-104: naive datetime.now() mixed with Django's aware datetimes
  if (isDjango) {
    code.forEach((l, i) => {
      if (!/\bdatetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)/.test(l)) return;
      const inFilter = /__(?:lt|lte|gt|gte|range)\s*=[^,)]*datetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)/.test(l);
      const compared = /(?:[<>]=?)\s*datetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)|datetime(?:\.datetime)?\.(?:now|utcnow)\(\s*\)\s*(?:[-+]\s*timedelta\([^)]*\)\s*)?[<>]=?\s*\w+\.\w*(?:_at|date|expires\w*|deadline|until)\b/.test(l);
      if (!inFilter && !compared) return;
      add({ ruleId: 29714, code: 'BUG-104', severity: 'MEDIUM', lineIdx: i,
        title: 'Naive datetime.now() Mixed With Django Timezone-Aware Dates',
        why: 'With USE_TZ=True (the default) model dates are timezone-aware. Comparing them with a naive datetime.now() raises "can\'t compare offset-naive and offset-aware datetimes", and in a filter it is read as server-local time, shifting results by the UTC offset.',
        fix: 'Use django.utils.timezone.now() instead of datetime.now() / utcnow().' });
    });
  }

  // BUG-105: return / break / continue inside finally swallows the exception
  code.forEach((l, i) => {
    if (!/^\s*finally\s*:/.test(l)) return;
    const base = indentOf(l);
    for (const k of blockOf(code, i)) {
      const t = code[k];
      if (/^\s*(?:async\s+)?def\s/.test(t)) break;
      if (!/^\s*(?:return\b|break\s*$|continue\s*$)/.test(t)) continue;
      // a loop opened inside the finally owns its own break/continue
      const inner = blockOf(code, i).filter((x) => x < k && indentOf(code[x]) < indentOf(t) && indentOf(code[x]) > base);
      if (/^(?:break|continue)/.test(t.trim()) && inner.some((x) => /^\s*(?:for|while)\b/.test(code[x]))) continue;
      add({ ruleId: 29715, code: 'BUG-105', severity: 'MEDIUM', lineIdx: k,
        title: `${t.trim().split(/\s/)[0]} Inside finally Swallows Exceptions`,
        why: 'A return/break/continue in finally discards any exception raised in the try block, so failures (a failed payment, a DB error) look like success with no traceback (PEP 765; SyntaxWarning in Python 3.14).',
        fix: 'Only clean up in finally; move the return after the try statement.' });
      break;
    }
  });

  // BUG-106: async SQLAlchemy / asyncio call without await (the coroutine never runs)
  const asyncSa = /\bAsyncSession\b|async_sessionmaker|create_async_engine/.test(content);
  code.forEach((l, i) => {
    const d = defOf[i];
    if (d < 0 || !/^\s*async\s+def\b/.test(code[d])) return;
    let m = asyncSa ? /^\s*(?:\w+\s*=\s*)?((?:db|session|async_session|s)\.(?:commit|execute|refresh|flush|delete|rollback|scalars?|get|merge|close)\()/.exec(l) : null;
    if (!m) m = /^\s*(asyncio\.sleep\()/.exec(l);
    if (!m) return;
    add({ ruleId: 29716, code: 'BUG-106', severity: 'MEDIUM', lineIdx: i,
      title: `${m[1].replace(/\($/, '()')} Called Without await`,
      why: `In an async function ${m[1].replace(/\($/, '()')} returns a coroutine; without await it never runs ("coroutine was never awaited"), so the commit/query/sleep silently does not happen.`,
      fix: `await ${m[1]}...)` });
  });
}

export function evaluateLogicPythonRules(file: CodeFile, lines: string[], _cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.py$/i.test(path) || SKIP_PATH.test(path)) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  evaluate(maskPy(lines), file.content, add);

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
