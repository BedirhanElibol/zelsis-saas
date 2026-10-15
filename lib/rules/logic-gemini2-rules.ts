/**
 * Runtime logic bugs from part 2 of the Gemini rule report (BUG-223.., Rule IDs 30101-30199).
 * Same bar as part 1: the scanner missed the example, the mistake is provable from one file, and it is
 * wrong in essentially every context (a request that never goes out, a hung request, a regex that
 * alternates true/false). Proposals that are outdated (React event pooling, conditional use()), stylistic
 * or need runtime data were dropped.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { SKIP, blockAfter, closeOf, lineAt } from './logic-gemini-rules';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string; type?: Finding['type']; category?: string }
type Add = (h: Hit) => void;

const isRouteHandler = (path: string, c: string) =>
  /(?:^|\/)app\/(?:.*\/)?route\.[jt]s$|(?:^|\/)pages\/api\//.test(path)
  || /\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|all|route)\s*\(/.test(c)
  || /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/.test(c);

function evaluateJs(path: string, c: string, add: Add) {
  // BUG-223: http.request() whose request object is never ended: the request is never sent
  for (const m of c.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*(?:https?|http2)\.request\s*\(/g)) {
    const v = m[1];
    if (new RegExp(`\\b${v}\\s*\\.\\s*end\\s*\\(|\\.pipe\\(\\s*${v}\\b|pipeline\\([^)]*\\b${v}\\b|\\breturn\\s+${v}\\b|\\b${v}\\s*\\)`).test(c.slice(m.index! + m[0].length))) continue;
    add({ ruleId: 30101, code: 'BUG-223', severity: 'HIGH', lineIdx: lineAt(c, m.index!),
      title: `${v} = http.request() Is Never Ended, So the Request Is Never Sent`,
      why: `http.request() returns a ClientRequest that only goes out once ${v}.end() is called. Without it the callback never runs and the socket stays open until it times out.`,
      fix: `Call ${v}.end() after writing the body (or use http.get(), which ends the request for you).` });
  }

  // BUG-224: uncaughtException handler that keeps the process running
  for (const m of c.matchAll(/\bprocess\.on\(\s*['"]uncaughtException['"]\s*,/g)) {
    const open = c.indexOf('(', m.index!);
    const end = closeOf(c, open);
    if (end < 0) continue;
    const handler = c.slice(m.index! + m[0].length, end);
    if (/\bprocess\.exit\b|\bexit\s*\(|\bthrow\b|\bprocess\.kill\b|\bprocess\.abort\b|\bshutdown\w*\s*\(|\bclose\w*\s*\(/i.test(handler)) continue;
    // A bare identifier is a handler defined elsewhere; only judge inline functions
    if (!/=>|\bfunction\b/.test(handler)) continue;
    add({ ruleId: 30102, code: 'BUG-224', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!),
      title: 'uncaughtException Handler Keeps the Process Running',
      why: 'After an uncaught exception Node is in an undefined state (half-written responses, held locks, broken pools). The handler only logs, so the server keeps serving requests in that state instead of restarting.',
      fix: 'Log the error, then exit (process.exit(1)) and let the process manager restart the service.' });
  }

  // BUG-226: numeric enum iterated with Object.values/keys/entries includes the reverse mappings
  if (/\.tsx?$/.test(path)) {
    for (const e of c.matchAll(/\b(?:export\s+)?enum\s+(\w+)\s*\{/g)) {
      const b = blockAfter(c, e.index!);
      if (!b) continue;
      const body = c.slice(b.s, b.e);
      if (/=\s*['"`]/.test(body) || !/\w/.test(body)) continue;
      const it = new RegExp(`\\bObject\\.(values|keys|entries)\\(\\s*${e[1]}\\s*\\)`).exec(c);
      if (!it) continue;
      add({ ruleId: 30104, code: 'BUG-226', severity: 'MEDIUM', lineIdx: lineAt(c, it.index),
        title: `Object.${it[1]}(${e[1]}) on a Numeric Enum Lists Every Member Twice`,
        why: `TypeScript compiles numeric enums with reverse mappings (${e[1]}[0] === "Name"), so Object.${it[1]}(${e[1]}) returns both the names and the numbers. Dropdowns show duplicate options and validation accepts the name strings.`,
        fix: `Filter to one side (Object.values(${e[1]}).filter((v) => typeof v === 'number')) or use a string enum / an "as const" object.` });
    }
  }

  // BUG-227: decompressing request input with no output limit (zip bomb)
  for (const m of c.matchAll(/\bzlib\.(gunzip|inflate|inflateRaw|unzip|brotliDecompress)(Sync)?\s*\(\s*((?:await\s+)?(?:req|request|ctx\.request)\b[^,)]*|body\b[^,)]*|buf(?:fer)?\b[^,)]*)/g)) {
    const open = c.indexOf('(', m.index!);
    const end = closeOf(c, open);
    if (end < 0 || /maxOutputLength/.test(c.slice(open, end))) continue;
    if (!/^(?:await\s+)?(?:req|request|ctx)/.test(m[3]) && !isRouteHandler(path, c)) continue;
    add({ ruleId: 30105, code: 'BUG-227', severity: 'HIGH', lineIdx: lineAt(c, m.index!),
      title: `zlib.${m[1]}${m[2] ?? ''}() on Request Data Without maxOutputLength`,
      why: 'A few kilobytes of crafted gzip can expand to gigabytes. Without maxOutputLength the whole output is buffered in memory and one request can take the server down.',
      fix: `Pass a limit: zlib.${m[1]}${m[2] ?? ''}(data, { maxOutputLength: 10 * 1024 * 1024 }) and reject larger payloads.` });
  }

  // BUG-228: module-level /g regex reused with .test(): lastIndex makes every other call fail
  for (const m of c.matchAll(/^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*\/(?:\\.|[^/\\\n])+\/([a-z]*g[a-z]*)\s*;?\s*$/gm)) {
    const v = m[1];
    if (new RegExp(`\\b${v}\\.lastIndex\\s*=`).test(c)) continue;
    const use = new RegExp(`\\b${v}\\.test\\s*\\(`).exec(c);
    if (!use) continue;
    add({ ruleId: 30106, code: 'BUG-228', severity: 'MEDIUM', lineIdx: lineAt(c, use.index),
      title: `${v} Has the g Flag and Is Reused With .test()`,
      why: `A /g regex remembers lastIndex between calls. After one match, ${v}.test() starts from the old position on the next string and returns false, so the same valid input passes and fails on alternate calls.`,
      fix: `Remove the g flag from ${v} (test() does not need it) or reset ${v}.lastIndex = 0 before each test.` });
  }

  // BUG-230: async Express middleware whose catch neither responds nor calls next(err): the request hangs
  for (const m of c.matchAll(/\basync\s*(?:function\s*\w*\s*)?\(\s*(\w+)\s*(?::[^,()\n]+)?,\s*(\w+)\s*(?::[^,()\n]+)?,\s*(next)\s*(?::[^()\n]+)?\)\s*(?::[^{=\n]+)?(?:=>)?\s*\{/g)) {
    const end = closeOf(c, m.index! + m[0].length - 1);
    if (end < 0) continue;
    const body = c.slice(m.index!, end);
    for (const k of body.matchAll(/\bcatch\s*(?:\([^)]*\))?\s*\{/g)) {
      const kEnd = closeOf(body, k.index! + k[0].length - 1);
      if (kEnd < 0) continue;
      const handler = body.slice(k.index!, kEnd);
      // Only the try/catch that wraps the whole success path: the function ends right after the catch,
      // and the try block is what calls next() or responds. Inner fallbacks (catch, then carry on) are fine.
      if (!/^[\s;})]*$/.test(body.slice(kEnd))) continue;
      const tryAt = body.lastIndexOf('try', k.index!);
      const tryBlock = tryAt >= 0 ? body.slice(tryAt, k.index!) : '';
      if (!new RegExp(`\\bnext\\s*\\(|\\b${m[2]}\\s*\\.\\s*(?:status|send|json|end|redirect|sendStatus|render)\\b`).test(tryBlock)) continue;
      if (/\bnext\s*\(|\bthrow\b|\breturn\b/.test(handler) || new RegExp(`\\b${m[2]}\\s*\\.\\s*(?:status|send|json|end|redirect|sendStatus|render|write)\\b`).test(handler)) continue;
      add({ ruleId: 30108, code: 'BUG-230', severity: 'MEDIUM', lineIdx: lineAt(c, m.index! + k.index!),
        title: 'Middleware catch Swallows the Error and Never Calls next()',
        why: `The catch block logs (or ignores) the error but neither calls next(err) nor sends a response, so the request never finishes: the client waits until its timeout and Express's error handler never runs.`,
        fix: 'Call next(err) in the catch block (or send an error response with res.status(500)).' });
    }
  }

  // BUG-231: cookies().set() in a Server Component: Next.js only allows it in Server Actions and Route Handlers
  if (/(?:^|\/)app\/(?:.*\/)?(?:page|layout|template|default)\.[jt]sx?$/.test(path) && !/['"]use server['"]/.test(c)) {
    const store = c.match(/\b(?:const|let)\s+(\w+)\s*=\s*(?:await\s+)?cookies\s*\(\s*\)/)?.[1];
    const re = new RegExp(`(?:\\bcookies\\s*\\(\\s*\\)\\s*\\)?|${store ? `\\b${store}` : '(?!)'})\\s*\\.\\s*(set|delete)\\s*\\(`);
    const m = re.exec(c);
    if (m) add({ ruleId: 30109, code: 'BUG-231', severity: 'HIGH', lineIdx: lineAt(c, m.index),
      title: `cookies().${m[1]}() Called While Rendering a Server Component`,
      why: `Next.js throws "Cookies can only be modified in a Server Action or Route Handler" when a page or layout calls cookies().${m[1]}() during render, so this page errors instead of setting the cookie.`,
      fix: `Move the cookie change into a Server Action, a Route Handler, or middleware (proxy.ts), and only read cookies in the page.` });
  }

  // BUG-229: synchronous password hashing inside a request handler blocks every other request
  if (isRouteHandler(path, c)) {
    for (const m of c.matchAll(/\b(bcrypt(?:js)?\.(?:hashSync|compareSync|genSaltSync)|crypto\.(?:pbkdf2Sync|scryptSync)|(?<![\w.])(?:pbkdf2Sync|scryptSync))\s*\(/g)) {
      add({ ruleId: 30107, code: 'BUG-229', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!),
        title: `${m[1]}() in a Request Handler Blocks the Event Loop`,
        why: `${m[1]} runs on the main thread for tens to hundreds of milliseconds. While one user logs in, every other request on this server waits.`,
        fix: `Use the async version (${m[1].replace(/Sync$/, '')} with await / a callback), which runs on the libuv thread pool.` });
    }
  }
}

/** Placebo features from part 2 (FAKE-16.., Rule IDs 30151-30199). */
function evaluateFake(c: string, add: Add) {
  // FAKE-16: export / download button that saves an empty file
  if (/URL\.createObjectURL\s*\(|\bsaveAs\s*\(|\bdownload\s*=/.test(c)) {
    for (const m of c.matchAll(/new\s+Blob\s*\(\s*\[\s*(?:''|""|``|'\[\]'|"\[\]"|'\{\}'|"\{\}"|JSON\.stringify\(\s*(?:\[\s*\]|\{\s*\})\s*(?:,[^)]*)?\))?\s*\]/g)) {
      add({ ruleId: 30151, code: 'FAKE-16', severity: 'HIGH', lineIdx: lineAt(c, m.index!),
        title: 'Export Downloads an Empty File',
        why: 'The Blob is built from an empty string, [] or {}, so the export / audit log / report button always saves a file with no data while the UI reports success.',
        fix: 'Build the Blob from the real records (fetched from your API) or hide the export until it is implemented.' });
    }
  }

  // FAKE-17: 2FA backup / recovery codes hard-coded in the source: every user gets the same codes
  for (const m of c.matchAll(/\b(\w*(?:backup|recovery)_?codes?)\b\s*(?::[^=\n]+)?=\s*(?:useState\s*(?:<[^>]*>)?\s*\(\s*)?\[\s*(['"])[A-Za-z0-9]{3,}-?[A-Za-z0-9]{3,}\2\s*,\s*(['"])[A-Za-z0-9]{3,}-?[A-Za-z0-9]{3,}\3\s*,\s*['"][A-Za-z0-9]{3,}-?[A-Za-z0-9]{3,}['"]/gi)) {
    add({ ruleId: 30152, code: 'FAKE-17', severity: 'HIGH', lineIdx: lineAt(c, m.index!),
      title: `${m[1]} Are Hard-Coded in the Source`,
      why: 'Every account sees the same recovery codes, and anyone who reads the bundle or the repository knows them. They are not stored per user, so they cannot recover a real account either.',
      fix: 'Generate random codes on the server per user, store them hashed, show them once, and verify them server-side.' });
  }
}

const LLM_CALL = /\b(?:chat\.completions\.create|responses\.create|messages\.create|generateText|generateObject|streamText|\.invoke|\.generateContent|ollama\.chat)\s*\(/;

/** AI agent mistakes from part 2 (AIX-01.., Rule IDs 30201-30249). */
function evaluateAi(c: string, add: Add) {
  // AIX-01: agent loop calling the model with no step / iteration cap
  for (const m of c.matchAll(/\bwhile\s*\(\s*(?:true|1)\s*\)\s*\{|\bfor\s*\(\s*;\s*;\s*\)\s*\{/g)) {
    const end = closeOf(c, m.index! + m[0].length - 1);
    if (end < 0) continue;
    const body = c.slice(m.index!, end);
    if (!LLM_CALL.test(body)) continue;
    if (/\b(?:i|n|\w*(?:step|iter|turn|round|attempt|loop|hop|count|depth)\w*)\s*(?:>=?|<=?|===?)\s*\w*(?:max|MAX|limit|LIMIT|\d)/i.test(body) || /\+\+\s*(?:>=?|<)|(?:>=?|<)\s*\w*max/i.test(body)) continue;
    add({ ruleId: 30201, code: 'AIX-01', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), category: 'AI & LLM Cost',
      title: 'Agent Loop Calls the Model With No Step Limit',
      why: 'The loop only stops when the model decides it is done. A model that keeps requesting tools (or repeats the same call) loops forever, paying for every turn until the request times out or the budget is gone.',
      fix: 'Count iterations and stop at a fixed maximum (e.g. 10 steps), returning a partial answer, or use the SDK\'s maxSteps / stopWhen option.' });
  }

  // AIX-02: agent tool that reads / writes / deletes a file at a path the model chose
  for (const m of c.matchAll(/\bexecute\s*:\s*async\s*\(\s*\{([^}]*)\}\s*\)\s*=>\s*\{?/g)) {
    const args = m[1].split(',').map((a) => a.split(':')[0].trim()).filter(Boolean);
    const pathArg = args.find((a) => /path|file|dir|filename|name/i.test(a));
    if (!pathArg) continue;
    const start = m.index! + m[0].length;
    const body = c.slice(start, start + 800);
    const fsCall = new RegExp(`\\b(?:fs(?:\\.promises)?\\.|fsp\\.|)(readFile|writeFile|appendFile|unlink|rm|rmdir|readdir|createReadStream|createWriteStream)(?:Sync)?\\s*\\(\\s*(?:path\\.(?:join|resolve)\\([^)]*\\b${pathArg}\\b|${pathArg}\\b)`).exec(body);
    if (!fsCall) continue;
    if (/startsWith\s*\(|path\.relative\s*\(|isInside|isSubPath|assertInside|sandbox|\.\.\//.test(body.slice(0, fsCall.index + 200))) continue;
    add({ ruleId: 30202, code: 'AIX-02', severity: 'HIGH', lineIdx: lineAt(c, start + fsCall.index), type: 'SECURITY', category: 'AI & LLM Security',
      title: `Agent Tool Runs ${fsCall[1]}() on a Path the Model Chose`,
      why: `The model fills in ${pathArg}, and text it reads (a web page, a document, a user message) can steer it to "../../.env" or an absolute path. The tool then reads or overwrites files outside the folder it was meant for.`,
      fix: `Resolve the path against a fixed base directory and reject it unless path.resolve(base, ${pathArg}).startsWith(base + path.sep).` });
  }
}

/** Go, container and manifest mistakes from part 2 (BUG-232.., SEC2-01.., Rule IDs 30110+ / 30251+). */
function evaluateOther(path: string, c: string, add: Add) {
  // BUG-232: sync.WaitGroup / Mutex passed by value: Done()/Unlock() act on a copy
  if (/\.go$/.test(path)) {
    for (const m of c.matchAll(/\bfunc\s*(?:\([^)]*\)\s*)?\w*\s*\(([^)]*)\)/g)) {
      const p = /\b(\w+)\s+sync\.(WaitGroup|Mutex|RWMutex|Once|Cond)\b/.exec(m[1]);
      if (!p) continue;
      add({ ruleId: 30110, code: 'BUG-232', severity: 'HIGH', lineIdx: lineAt(c, m.index!),
        title: `sync.${p[2]} ${p[1]} Passed by Value`,
        why: `Go copies the ${p[2]} into the function, so ${p[1]}.${p[2] === 'WaitGroup' ? 'Done()' : 'Unlock()'} changes the copy. The caller's ${p[2] === 'WaitGroup' ? 'Wait() never returns' : 'lock is never released'} and the program deadlocks.`,
        fix: `Take a pointer: ${p[1]} *sync.${p[2]} (and pass &${p[1]}).` });
    }
    return;
  }

  // SEC2-01: Node inspector listening on every interface: anyone who reaches the port runs code
  if (/(?:^|\/)(?:Dockerfile[\w.-]*|[\w.-]*\.dockerfile|docker-compose[\w.-]*\.ya?ml|compose[\w.-]*\.ya?ml|package\.json|Procfile|fly\.toml|render\.yaml|railway\.json)$/i.test(path) && !/(?:^|[./-])(?:dev|development|local|debug)(?:[./-]|$)/i.test(path)) {
    const m = /--inspect(?:-brk)?=(?:0\.0\.0\.0|\[::\]|\*)(?::\d+)?/.exec(c);
    if (m && !(/package\.json$/i.test(path) && /"(?:dev|debug|start:dev|inspect)\w*"\s*:\s*"[^"]*--inspect/.test(c) && !/"start"\s*:\s*"[^"]*--inspect/.test(c)))
      add({ ruleId: 30251, code: 'SEC2-01', severity: 'CRITICAL', lineIdx: lineAt(c, m.index), type: 'SECURITY', category: 'Remote Code Execution',
        title: `Node Inspector Exposed on All Interfaces (${m[0]})`,
        why: 'The V8 inspector has no authentication. Anyone who can reach this port can attach a debugger and run arbitrary JavaScript with the server\'s permissions (read env secrets, open a shell).',
        fix: 'Remove --inspect from the production command, or bind it to 127.0.0.1 and reach it through an SSH tunnel.' });
  }

  // SEC2-02: dependency downloaded over plain http:// or git:// (no TLS): a network attacker can swap the code
  if (/(?:^|\/)package\.json$/i.test(path)) {
    const deps = c.match(/"(?:dependencies|devDependencies|optionalDependencies|peerDependencies)"\s*:\s*\{[^}]*\}/g)?.join('\n') ?? '';
    const m = /"([@\w./-]+)"\s*:\s*"((?:git\+)?(?:http|git):\/\/[^"]+)"/.exec(deps);
    if (m) {
      const at = c.indexOf(m[0]);
      add({ ruleId: 30252, code: 'SEC2-02', severity: 'HIGH', lineIdx: lineAt(c, at), type: 'SECURITY', category: 'Supply Chain',
        title: `${m[1]} Is Downloaded Over an Unencrypted URL`,
        why: `${m[2].split(':')[0]}:// has no TLS, so anyone on the network path (CI runner, Wi-Fi, a proxy) can replace the package with their own code during npm install.`,
        fix: 'Use an https:// or git+https:// URL pinned to a commit, or publish the package to a registry.' });
    }
  }
}

export function evaluateLogicGemini2Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };
  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  if (/\.[cm]?[jt]sx?$/i.test(path)) {
    evaluateJs(path, c, add);
    evaluateFake(c, add);
    evaluateAi(c, add);
  } else evaluateOther(path, c, add);

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `bug${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type ?? 'VIBECARE',
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
