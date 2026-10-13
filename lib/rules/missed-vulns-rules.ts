/**
 * Vulnerabilities small teams ship that the other packs missed (GAP-01.., Rule IDs 28801-28899).
 * Found by a false-negative hunt over realistic snippets from public incidents and advisories
 * (Supabase / Firebase open data, mass assignment, client-controlled roles, leaked secrets in responses,
 * upload file names, template injection, postMessage token leaks). Each rule keys on a pattern that is
 * wrong in essentially every context, so a hit is a real defect rather than a style preference.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';
import { PUBLIC_ARTIFACT } from '../scanner/scan-paths';

export interface MissedVulnsRuleResult {
  findings: Finding[];
  logs: string[];
}

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

/** Table names that hold per-user or confidential rows; a public read on them is a leak, not a catalog. */
export const PRIVATE_TABLE = /^(?:users?|accounts?|messages?|chats?|chat_messages|conversations?|notes?|documents?|files?|orders?|payments?|invoices?|transactions?|subscriptions?|customers?|emails?|addresses|secrets?|tokens?|api_keys?|sessions?|private_\w+|\w+_private)$/i;

/** Bucket names that signal per-user confidential files (avatars, images, public assets are meant to be readable). */
const PRIVATE_BUCKET = /(?:^|[-_])(?:invoices?|receipts?|documents?|docs|private|contracts?|kyc|identity|ids|passports?|licen[cs]es?|medical|health|statements?|attachments?|backups?|exports?|reports?|resumes?|cvs?|payslips?|tax(?:es)?|secure|confidential|user[-_]?files)(?:$|[-_])/i;

/** A SELECT USING (true) policy on a catalog table (products, prices): a deliberate public read. */
export const isPublicCatalogRead = (stmt: string) => /\bFOR\s+SELECT\b/i.test(stmt)
  && !PRIVATE_TABLE.test(stmt.match(/\bON\s+(?:"?\w+"?\.)?"?(\w+)"?/i)?.[1] || '');

const lineAt = (content: string, offset: number) => content.slice(0, Math.max(0, offset)).split('\n').length - 1;
const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*|#)/.test(l);

/** Request-derived values in a JS/TS file: variables assigned or destructured from request input. */
function requestVars(content: string): Set<string> {
  const vars = new Set<string>();
  for (const m of content.matchAll(/(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*[^;\n]*(?:\breq(?:uest)?\.(?:query|body|params)\b|searchParams\.get\(|\b\w*[fF]orm(?:Data)?\.get\()/g)) vars.add(m[1]);
  for (const m of content.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:req(?:uest)?\.(?:query|body|params)\b|req(?:uest)?\.json\(\)|ctx\.request\.body)/g)) {
    m[1].split(',').map((x) => x.split(':').pop()!.split('=')[0].trim()).filter((x) => /^\w+$/.test(x)).forEach((x) => vars.add(x));
  }
  return vars;
}

export function evaluateMissedVulnsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): MissedVulnsRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path;
  if (/(?:^|\/)node_modules\//.test(path)) return { findings, logs };
  const isJs = /\.[cm]?[jt]sx?$/i.test(path) && !/\.d\.ts$/i.test(path);
  const isPy = /\.py$/i.test(path);
  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };

  // GAP-01: RLS policy that lets anyone UPDATE / DELETE every row (USING (true) / WITH CHECK (true))
  if (/\.sql$/i.test(path) && (context?.exposesDatabaseToClients || /(?:^|\/)supabase\//i.test(path))) {
    const sql = cleanContent.split('\n').map((l) => l.replace(/--.*$/, '')).join('\n');
    let n = 0;
    for (const m of sql.matchAll(/CREATE\s+POLICY\b[^;]*;/gi)) {
      const stmt = m[0];
      const cmd = (stmt.match(/\bFOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)\b/i)?.[1] || 'ALL').toUpperCase();
      if (cmd === 'SELECT' || cmd === 'INSERT') continue;
      if (/\bTO\s+(?:service_role|postgres|supabase_admin)\b/i.test(stmt)) continue;
      const t = stmt.search(/\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i);
      if (t === -1) continue;
      add({ ruleId: 28801, code: 'GAP-01', severity: 'HIGH', category: 'Row Level Security', lineIdx: lineAt(sql, m.index! + t),
        title: 'RLS Policy Lets Any Client Modify Every Row (USING (true))',
        why: `This ${cmd} policy evaluates to true for every row, so anyone holding the public anon key (or any signed-in user) can ${cmd === 'DELETE' ? 'delete' : 'overwrite'} other users' rows straight from the browser through /rest/v1.`,
        fix: 'Scope the policy to the row owner: USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id), or drop the policy and write from the server with the service role.' });
      if (++n >= 3) break;
    }
    // GAP-17: SELECT USING (true) on a table that holds private data (public read of products/prices is normal)
    let r = 0;
    for (const m of sql.matchAll(/CREATE\s+POLICY\b[^;]*;/gi)) {
      const stmt = m[0];
      if (!/\bFOR\s+SELECT\b/i.test(stmt) || /\bTO\s+(?:service_role|postgres|supabase_admin)\b/i.test(stmt)) continue;
      const table = stmt.match(/\bON\s+(?:"?\w+"?\.)?"?(\w+)"?/i)?.[1] || '';
      if (!PRIVATE_TABLE.test(table)) continue;
      const t = stmt.search(/\bUSING\s*\(\s*true\s*\)/i);
      if (t === -1) continue;
      add({ ruleId: 28817, code: 'GAP-17', severity: 'HIGH', category: 'Row Level Security', lineIdx: lineAt(sql, m.index! + t),
        title: `RLS Policy Lets Anyone Read Every Row of ${table} (USING (true))`,
        why: `The SELECT policy on ${table} is true for every row, so anyone holding the public anon key can download all of it from the browser through /rest/v1.`,
        fix: `Scope the read to the owner: USING (auth.uid() = user_id), or expose only public columns through a view.` });
      if (++r >= 3) break;
    }
    // GAP-21: storage SELECT policy that lets every caller read a private bucket (scoped by bucket_id only)
    for (const m of sql.matchAll(/CREATE\s+POLICY\b[^;]*?\bON\s+"?storage"?\s*\.\s*"?objects"?\b([^;]*);/gi)) {
      const rest = m[1];
      if (!/\bFOR\s+SELECT\b/i.test(rest) || /\bTO\s+service_role\b/i.test(rest)) continue;
      const using = rest.slice(Math.max(0, rest.search(/\bUSING\b/i)));
      if (/auth\.(?:uid|jwt|email)\s*\(|\bowner(?:_id)?\b|foldername|\bselect\b|\b(?:is|has|can)_\w+\s*\(/i.test(using)) continue;
      const bucket = rest.match(/\bbucket_id\s*=\s*'([\w-]+)'/i)?.[1] || '';
      if (!PRIVATE_BUCKET.test(bucket)) continue;
      add({ ruleId: 28821, code: 'GAP-21', severity: 'HIGH', category: 'Broken Access Control', lineIdx: lineAt(sql, m.index! + m[0].search(/\bbucket_id\b/i)),
        title: `Storage Policy Lets Every Caller Read All Files in the "${bucket}" Bucket`,
        why: `The SELECT policy on storage.objects only checks bucket_id = '${bucket}', so ${/\bTO\s+authenticated\b/i.test(rest) ? 'any signed-in user' : 'anyone with the anon key'} can list and download every other user's files in it.`,
        fix: `Scope reads to the owner's folder: USING (bucket_id = '${bucket}' AND (storage.foldername(name))[1] = auth.uid()::text), and upload under \${user.id}/.` });
      break;
    }
  }

  // GAP-02: Firestore / Storage rules open to everyone or to every signed-in user over the whole database
  if (/\.rules$/i.test(path) || /service\s+(?:cloud\.firestore|firebase\.storage)/.test(cleanContent)) {
    const stack: { path: string; depth: number }[] = [];
    let depth = 0;
    lines.forEach((raw, i) => {
      const l = raw.replace(/\{[\w=*]+\}/g, 'X');
      const mm = raw.match(/^\s*match\s+(\S+)\s*\{/);
      const al = raw.match(/^\s*allow\s+([\w\s,]+?)\s*(?::\s*if\s+(.+?))?\s*;\s*$/);
      if (al && !isComment(raw)) {
        const ops = al[1];
        const cond = (al[2] || '').trim();
        const rootWide = stack.some((s) => /^\/\{\w+=\*\*\}$/.test(s.path));
        const writes = /\b(?:write|create|update|delete)\b/.test(ops);
        if (!al[2] && (writes || rootWide)) {
          add({ ruleId: 28802, code: 'GAP-02', severity: 'CRITICAL', category: 'Access Control', lineIdx: i,
            title: 'Firebase Rules Open Data to Everyone: allow Without Any Condition',
            why: `"allow ${ops.trim()};" has no condition, so anyone with the public Firebase config can ${writes ? 'write, overwrite and delete' : 'read'} this data without signing in.`,
            fix: 'Add a condition that ties access to the caller: allow read, write: if request.auth != null && request.auth.uid == userId;' });
        } else if (rootWide && /^request\.auth\s*!=\s*null$|^request\.auth\.uid\s*!=\s*null$/.test(cond)) {
          add({ ruleId: 28802, code: 'GAP-02', severity: 'HIGH', category: 'Access Control', lineIdx: i,
            title: 'Firebase Rules Open Data to Everyone: Any Signed-In User Reaches All Documents',
            why: 'The recursive wildcard match covers every document / file, and the only check is that the caller is signed in. Anyone can create an account and then read or modify every other user\'s data.',
            fix: 'Write per-collection rules that compare request.auth.uid with the document owner (match /users/{userId} { allow read, write: if request.auth.uid == userId; }) and remove the root {document=**} grant.' });
        }
      }
      for (const ch of l) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (mm) stack.push({ path: mm[1], depth });
      while (stack.length && stack[stack.length - 1].depth > depth) stack.pop();
    });
  }

  // GAP-03: Realtime Database rules with ".write": true, or ".read": true at the root
  if (/(?:^|\/)database(?:\.rules)?\.json$|\.rules\.json$/i.test(path) && /"rules"\s*:/.test(cleanContent)) {
    let prev = '';
    lines.forEach((l, i) => {
      if (/"\.write"\s*:\s*(?:true|"true")/.test(l) || (/"\.read"\s*:\s*(?:true|"true")/.test(l) && /"rules"\s*:\s*\{\s*$/.test(prev))) {
        add({ ruleId: 28803, code: 'GAP-03', severity: 'CRITICAL', category: 'Access Control', lineIdx: i,
          title: 'Firebase Realtime Database Rules Open to the Public',
          why: 'A rule of true needs no sign-in: anyone with the database URL (shipped in the app) can dump or overwrite this part of the database.',
          fix: 'Replace true with an owner check, e.g. ".write": "auth != null && auth.uid === $uid" under a $uid path.' });
      }
      if (l.trim()) prev = l;
    });
  }

  if (isJs) {
    const reqVars = requestVars(cleanContent);

    // GAP-04: whole request body written to the database (mass assignment / role escalation)
    {
      const raw = new Set<string>();
      for (const m of cleanContent.matchAll(/(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:await\s+(?:req|request)\.json\(\)|(?:req|request)\.body|Object\.fromEntries\(\s*(?:await\s+)?\w*[fF]orm\w*(?:\.entries\(\))?\s*\))\s*(?:as\s+[^;\n]+)?;?\s*$/gm)) raw.add(m[1]);
      for (const v of [...raw]) {
        if (new RegExp(String.raw`\.(?:safe)?[pP]arse(?:Async)?\(\s*` + v + String.raw`\b|\bvalidate\w*\(\s*` + v + String.raw`\b|\bpick\(\s*` + v + String.raw`\b`).test(cleanContent)) raw.delete(v);
      }
      const src = String.raw`(?:` + [...raw, String.raw`req\.body`, String.raw`await\s+req(?:uest)?\.json\(\)`].join('|') + String.raw`)`;
      const whole = String.raw`(?:` + src + String.raw`|\{\s*\.\.\.` + src + String.raw`\s*[,}])`;
      const supabaseWrite = new RegExp(String.raw`\.(?:update|insert|upsert)\(\s*` + whole + String.raw`\s*[,)]`);
      const odmWrite = new RegExp(String.raw`\.(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|replaceOne|insertMany)\(\s*(?:[^,()]+(?:\([^)]*\))?\s*,\s*)?` + whole + String.raw`\s*[,)]`);
      const prismaVars = [...raw].filter((v) => v !== 'body');
      const prismaData = prismaVars.length ? new RegExp(String.raw`\bdata\s*:\s*(?:` + prismaVars.join('|') + String.raw`)\s*[,}]`) : null;
      lines.forEach((l, i) => {
        if (isComment(l)) return;
        const sb = supabaseWrite.test(l) && lines.slice(Math.max(0, i - 3), i + 1).some((x) => /\.from\(\s*['"`]/.test(x));
        const odm = odmWrite.test(l);
        const prisma = !!prismaData && prismaData.test(l) && /\.(?:create|update|upsert|updateMany|createMany)\s*\(/.test(lines.slice(Math.max(0, i - 3), i + 1).join(' '));
        if (sb || odm || prisma) {
          add({ ruleId: 28804, code: 'GAP-04', severity: 'HIGH', category: 'Mass Assignment', lineIdx: i,
            title: 'Request Body Written to the Database As-Is (Mass Assignment)',
            why: 'Every field the client sends is stored, so a user can add role, is_admin, plan, credits, user_id or stripe_customer_id to the JSON and grant themselves privileges or take over other records (OWASP API3:2023).',
            fix: 'Parse the body with a schema that lists the writable fields (const { name, avatarUrl } = Schema.parse(await req.json())) and write only those.' });
        }
      });
    }

    // GAP-05: authorization decided by a cookie or query parameter the client sets
    {
      const ROLE = String.raw`(?:role|roles|userRole|user_role|isAdmin|is_admin|admin|isSuperAdmin|is_super_admin|superuser)`;
      const cookieRead = String.raw`(?:(?:cookies\(\)\)?|cookieStore|\(await\s+cookies\(\)\))\.get\(\s*['"]` + ROLE + String.raw`['"]\s*\)(?:\?\.value|\.value)?|\b(?:req|request|ctx)\.cookies(?:\.` + ROLE + String.raw`\b|\[\s*['"]` + ROLE + String.raw`['"]\s*\]|\.get\(\s*['"]` + ROLE + String.raw`['"]\s*\)(?:\?\.value|\.value)?))`;
      const QROLE = String.raw`(?:admin|isAdmin|is_admin|isSuperAdmin|superuser)`;
      const queryRead = String.raw`(?:\b(?:req|request|ctx)\.query\.` + QROLE + String.raw`\b|searchParams\.get\(\s*['"]` + QROLE + String.raw`['"]\s*\))`;
      const cmp = String.raw`\s*[!=]==?\s*['"\x60]`;
      const direct = new RegExp(String.raw`(?:` + cookieRead + '|' + queryRead + ')' + cmp);
      const assign = new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:` + cookieRead + '|' + queryRead + String.raw`)\s*;?\s*$`);
      const why = 'The value comes from a cookie or query parameter that the browser controls, so any user can set role=admin (DevTools or ?admin=true) and pass the check.';
      const fix = 'Read the role from the verified server session or the database (session.user.id -> users.role), never from a raw cookie, header or query parameter.';
      lines.forEach((l, i) => {
        if (isComment(l)) return;
        if (direct.test(l)) {
          add({ ruleId: 28805, code: 'GAP-05', severity: 'HIGH', category: 'Broken Access Control', lineIdx: i, title: 'Authorization Decided by a Client-Controlled Cookie or Query Parameter', why, fix });
          return;
        }
        const a = l.match(assign);
        if (a) {
          const useRe = new RegExp(String.raw`\b` + a[1] + String.raw`\b` + cmp + String.raw`|['"\x60]\s*[!=]==?\s*` + a[1] + String.raw`\b`);
          const j = lines.findIndex((x, k) => k > i && k <= i + 6 && useRe.test(x));
          if (j !== -1) add({ ruleId: 28805, code: 'GAP-05', severity: 'HIGH', category: 'Broken Access Control', lineIdx: j, title: 'Authorization Decided by a Client-Controlled Cookie or Query Parameter', why, fix });
        }
      });
    }

    // GAP-06: role / admin flag trusted from a custom request header
    lines.forEach((l, i) => {
      if (isComment(l)) return;
      if (/(?:headers\.get\(\s*['"]x-(?:user-)?(?:role|admin|is-admin)['"]\s*\)|headers\[\s*['"]x-(?:user-)?(?:role|admin|is-admin)['"]\s*\])\s*[!=]==?\s*['"]/i.test(l)) {
        add({ ruleId: 28806, code: 'GAP-06', severity: 'MEDIUM', category: 'Broken Access Control', lineIdx: i,
          title: 'Admin Check Trusts a Custom Request Header',
          why: 'Clients can send any header. Unless a proxy or middleware strips and re-sets it on every request (the CVE-2025-29927 class of bypass), x-user-role: admin is attacker-controlled.',
          fix: 'Resolve the role from the verified session or token inside the handler instead of a forwarded header.' });
      }
    });

    // GAP-07: server-only secret returned in an HTTP response
    {
      const secretEnv = /process\.env\.(?!NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_)\w*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|API_KEY|PASSWORD|ACCESS_KEY|_TOKEN)\w*\b/;
      const valueUse = /(?::\s*|\(\s*)process\.env\.\w+\s*(?:[,})]|$)/;
      const responseCall = /(?:Response|NextResponse)\.json\(|\bres\.(?:json|send)\(|\bc\.json\(|\bjson\(\s*\{/;
      lines.forEach((l, i) => {
        if (isComment(l) || !secretEnv.test(l) || !valueUse.test(l)) return;
        if (/!!\s*process\.env|Boolean\(\s*process\.env/.test(l)) return;
        if (lines.slice(Math.max(0, i - 3), i + 1).some((x) => responseCall.test(x))) {
          add({ ruleId: 28807, code: 'GAP-07', severity: 'CRITICAL', category: 'Secrets Management', lineIdx: i,
            title: 'Server Secret Returned in an HTTP Response',
            why: 'The handler sends a server-only key (service role, API key, signing secret) to whoever calls the endpoint, which hands out full database or provider access.',
            fix: 'Never return secrets: perform the privileged call on the server and return only its result. Rotate the exposed key.' });
        }
      });
    }

    // GAP-08: hardcoded session / auth signing secret
    {
      const usesAuthLib = /from\s+['"](?:next-auth|@auth\/[\w-]+)['"]|require\(\s*['"]next-auth['"]\s*\)/.test(cleanContent);
      const usesIron = /['"]iron-session['"]/.test(cleanContent);
      const why = 'Anyone who can read the source (repo access, leaked bundle, former contractor) can forge session cookies or tokens for any user, including admins.';
      const fix = 'Load the secret from the environment (process.env.AUTH_SECRET / SESSION_SECRET), fail startup when it is missing, and rotate the committed value.';
      lines.forEach((l, i) => {
        if (isComment(l)) return;
        const authSecret = usesAuthLib && /^\s*secret\s*:\s*['"][^'"]{3,}['"]\s*,?\s*$/.test(l);
        const ironPw = usesIron && /^\s*password\s*:\s*['"][^'"]{8,}['"]\s*,?\s*$/.test(l);
        // Skip mentions inside a string, e.g. express's error message 'cookieParser("secret") required for signed cookies'
        const cpAt = l.search(/\bcookieParser\(\s*['"][^'"]{3,}['"]/);
        const cookieParser = cpAt !== -1 && (l.slice(0, cpAt).match(/['"`]/g) || []).length % 2 === 0;
        const sessionSecret = /^\s*(?:secret|keys)\s*:\s*(?:\[\s*)?['"][^'"]{3,}['"]/.test(l) && lines.slice(Math.max(0, i - 6), i + 1).some((x) => /\b(?:session|cookieSession|expressSession)\s*\(\s*\{/.test(x));
        if (authSecret || ironPw || cookieParser || sessionSecret) {
          add({ ruleId: 28808, code: 'GAP-08', severity: 'HIGH', category: 'Secrets Management', lineIdx: i, title: 'Hardcoded Session / Auth Signing Secret', why, fix });
        }
      });
    }

    // GAP-09: uploaded file saved under the client-supplied file name
    {
      const clientName = String.raw`\b(?:file|files\[\w+\]|upload\w*|uploaded\w*|image|img|avatar|attachment|photo|document|doc|f)\.(?:name|originalname|originalFilename)\b`;
      const safe = /basename\(|sanitize\w*\(|randomUUID|uuid|nanoid|slugify|\.replace\(/;
      const writeCall = /(?:writeFile(?:Sync)?|createWriteStream|rename(?:Sync)?|copyFile(?:Sync)?)\s*\(|\.mv\(/;
      const nameInPath = new RegExp(String.raw`(?:path\.(?:join|resolve)\([^;\n]*|\x60[^\x60]*\$\{\s*|['"][^'"]*['"]\s*\+\s*|,\s*)` + clientName);
      lines.forEach((l, i) => {
        if (isComment(l) || safe.test(l)) return;
        const multer = new RegExp(String.raw`\b(?:cb|callback|done)\s*\(\s*null\s*,[^)]*\bfile\.originalname\b`).test(l);
        let at = -1;
        if (multer || (writeCall.test(l) && nameInPath.test(l))) at = i;
        else {
          const a = l.match(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*` + String.raw`(?:path\.(?:join|resolve)\([^;\n]*|\x60[^\x60]*\$\{\s*)` + clientName));
          if (a && lines.slice(i + 1, i + 7).some((x) => writeCall.test(x) && new RegExp(String.raw`\b` + a[1] + String.raw`\b`).test(x))) at = i;
        }
        if (at !== -1) {
          add({ ruleId: 28809, code: 'GAP-09', severity: 'HIGH', category: 'Path Traversal', lineIdx: at,
            title: 'Upload Saved Under the Client-Supplied File Name',
            why: 'The file name comes from the multipart request and is not sanitized: "../../.env" or "../app/page.js" writes outside the upload folder, and "index.html" / ".svg" in a public folder becomes stored XSS. Same-name uploads also overwrite other users\' files.',
            fix: 'Generate the stored name on the server (crypto.randomUUID() + an extension from an allow-list) and keep the original name only as metadata.' });
        }
      });
    }

    // GAP-10: server-side template injection (user input compiled as a template)
    {
      const tainted = reqVars.size ? String.raw`|\b(?:` + [...reqVars].join('|') + String.raw`)\b` : '';
      const re = new RegExp(String.raw`\b(?:ejs|pug|jade|nunjucks|Handlebars|handlebars|doT|dot|_|lodash)\.(?:render|compile|template|renderString)\s*\(\s*(?:(?:req|request|ctx)\.(?:body|query|params)\b` + tainted + ')');
      lines.forEach((l, i) => {
        if (!isComment(l) && re.test(l)) {
          add({ ruleId: 28810, code: 'GAP-10', severity: 'CRITICAL', category: 'Code Injection', lineIdx: i,
            title: 'Server-Side Template Injection: Request Input Compiled as a Template',
            why: 'EJS, Pug, Handlebars, Nunjucks and lodash templates execute JavaScript; a template from the request runs attacker code on the server (<%= process.mainModule.require("child_process").execSync("id") %>).',
            fix: 'Render fixed templates from disk and pass user input only as data: ejs.renderFile("views/preview.ejs", { content }).' });
        }
      });
    }

    // GAP-11: credentials posted to any origin with postMessage(..., '*')
    lines.forEach((l, i) => {
      if (isComment(l) || !/\.postMessage\s*\(/.test(l)) return;
      const win = lines.slice(i, i + 5).join(' ');
      const m = win.match(/\.postMessage\s*\(([^;]*?),\s*['"]\*['"]\s*\)/);
      if (m && /\b(?:token|accessToken|access_token|idToken|id_token|refreshToken|refresh_token|jwt|session|sessionId|password|secret|apiKey|api_key|credentials?)\b/.test(m[1])) {
        add({ ruleId: 28811, code: 'GAP-11', severity: 'HIGH', category: 'Sensitive Data Exposure', lineIdx: i,
          title: 'Credentials Sent With postMessage to Any Origin (\'*\')',
          why: 'targetOrigin "*" delivers the message to whatever page is the parent / opener, so a malicious site that frames or opens this page receives the token.',
          fix: 'Pass the exact trusted origin as targetOrigin (window.parent.postMessage(data, "https://app.example.com")) and verify event.origin on the receiver.' });
      }
    });

    // GAP-12: Math.random inside a function that generates OTPs, tokens or secrets
    {
      const fnRe = /(?:function\s+|(?:const|let|var)\s+)((?:generate|create|make|new|random|gen|issue|build)\w*)\s*(?:=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::\s*[\w<>]+\s*)?=>|\()/;
      const secWord = /otp|token|secret|password|passcode|nonce|salt|verification_?code|reset_?code|auth_?code|login_?code|api_?key|secret_?key|access_?key|pin(?:code)?$/i;
      const sec38 = /\b\w*(?:token|secret|password|passwd|nonce|salt|otp|csrf|apiKey|api_key|sessionId|session_id|resetCode|verificationCode|inviteCode)\s*[=:]\s*[^;\n]*Math\.random\s*\(\)/i;
      lines.forEach((l, i) => {
        const m = l.match(fnRe);
        if (!m || !secWord.test(m[1]) || isComment(l)) return;
        for (let k = i; k < Math.min(lines.length, i + 8); k++) {
          if (k > i && /^(?:\}|export\b|function\b)/.test(lines[k])) break;
          if (/Math\.random\s*\(\)/.test(lines[k]) && !sec38.test(lines[k])) {
            add({ ruleId: 28812, code: 'GAP-12', severity: 'HIGH', category: 'Cryptography', lineIdx: k,
              title: 'Predictable Math.random() in an OTP / Token Generator',
              why: 'Math.random is not a cryptographic generator; its output can be predicted from earlier values, so OTPs, reset tokens or keys made with it can be guessed.',
              fix: 'Use crypto.randomInt(100000, 1000000) for numeric codes and crypto.randomBytes(32).toString("hex") / randomUUID() for tokens.' });
            break;
          }
        }
      });
    }

    // GAP-14: PostgREST .or() filter built by interpolating request input
    {
      const names = new Set([...reqVars]);
      const re = new RegExp(String.raw`\.or\(\s*\x60[^\x60]*\$\{\s*(?:` + (names.size ? [...names].join('|') + '|' : '') + String.raw`q|query|search\w*|term|keyword)\s*\}`);
      lines.forEach((l, i) => {
        if (!isComment(l) && re.test(l) && !/encode|escape|sanitize/i.test(l)) {
          add({ ruleId: 28814, code: 'GAP-14', severity: 'MEDIUM', category: 'Injection', lineIdx: i,
            title: 'Supabase .or() Filter Built From User Input (PostgREST Filter Injection)',
            why: 'Commas, dots and parentheses in the value are parsed as PostgREST syntax, so the user can add their own conditions (e.g. "x%,is_private.eq.true") and change which rows the query returns.',
            fix: 'Use separate .ilike() / .eq() calls, or strip , . ( ) from the term (or quote it with double quotes) before building the .or() string.' });
        }
      });
    }

    // GAP-15: privilege stored in user-editable Supabase user metadata
    lines.forEach((l, i) => {
      if (isComment(l) || !/\bauth\.(?:signUp|updateUser)\s*\(/.test(l)) return;
      for (let k = i; k < Math.min(lines.length, i + 10); k++) {
        if (/\bdata\s*:\s*\{[^}]*\b(?:role|roles|is_admin|isAdmin|admin|plan|tier|credits|permissions|is_pro|isPro|subscription_tier)\s*[:,}]/.test(lines[k])) {
          add({ ruleId: 28815, code: 'GAP-15', severity: 'MEDIUM', category: 'Authorization', lineIdx: k,
            title: 'Privilege Field Stored in User-Editable Supabase user_metadata',
            why: 'options.data / updateUser({ data }) writes raw_user_meta_data, which the user can change at any time with supabase.auth.updateUser(); any check that reads this role, plan or credit value can be self-granted.',
            fix: 'Keep privileges in app_metadata (set with the service role via auth.admin.updateUserById) or in a table users cannot write.' });
          break;
        }
        if (k > i && /\)\s*;?\s*$/.test(lines[k]) && /^\s*\}\s*\)/.test(lines[k])) break;
      }
    });

    // GAP-16: storage upload keyed only by the client file name
    if (/\.storage\b/.test(cleanContent)) {
      lines.forEach((l, i) => {
        if (!isComment(l) && /\.upload\(\s*(?:\x60\$\{\s*)?\w*(?:file|image|avatar|upload|photo)\w*\.name(?:\s*\}\x60)?\s*,/i.test(l)) {
          add({ ruleId: 28816, code: 'GAP-16', severity: 'MEDIUM', category: 'Broken Access Control', lineIdx: i,
            title: 'Storage Upload Path Is Only the Client File Name',
            why: 'Every user writes into the same namespace, so uploading "avatar.png" replaces another user\'s file of the same name (with upsert) or fails unpredictably, and file names leak between users.',
            fix: 'Prefix the object path with the user id and a random name: `${user.id}/${crypto.randomUUID()}.${ext}`, and scope the storage policy to that folder.' });
        }
      });
    }

    // GAP-18: Clerk middleware that lists the whole /api tree as public, so auth.protect() never runs for it
    if (/\bclerkMiddleware\s*\(/.test(cleanContent)) {
      for (const m of cleanContent.matchAll(/\b(?:const|let|var)\s+(\w*public\w*)\s*=\s*createRouteMatcher\s*\(\s*\[([^\]]*)\]/gi)) {
        const wide = m[2].match(/['"](\/api(?:\(\.\*\)|\/\(\.\*\)|\/:path\*|\/\.\*)|\/\(api\|trpc\)\(\.\*\))['"]/);
        if (!wide) continue;
        add({ ruleId: 28818, code: 'GAP-18', severity: 'HIGH', category: 'Broken Access Control', lineIdx: lineAt(cleanContent, m.index! + m[0].indexOf(wide[0])),
          title: `Clerk Middleware Marks Every API Route Public (${wide[1]})`,
          why: `${m[1]} matches ${wide[1]}, so the middleware skips auth.protect() for every API route. Any handler that does not call auth() itself is open to anonymous requests.`,
          fix: 'List only the routes that must be public (e.g. "/api/webhooks(.*)") and let every other API route go through auth.protect().' });
      }
    }
  }

  // GAP-13: Flask debug server (Werkzeug console) bound to every interface
  if (isPy) {
    lines.forEach((l, i) => {
      if (isComment(l) || !/\b\w+\.run\s*\(/.test(l)) return;
      const win = lines.slice(i, i + 3).join(' ');
      const call = win.slice(win.search(/\.run\s*\(/)).split(/\)\s*(?:$|\n)/)[0];
      if (/\bdebug\s*=\s*True\b/.test(call) && /\bhost\s*=\s*['"]0\.0\.0\.0['"]/.test(call)) {
        add({ ruleId: 28813, code: 'GAP-13', severity: 'HIGH', category: 'Remote Code Execution', lineIdx: i,
          title: 'Flask Debug Server Exposed on All Interfaces',
          why: 'debug=True enables the Werkzeug interactive debugger, which executes Python from the browser; host 0.0.0.0 makes it reachable from the network (container port, LAN, cloud VM).',
          fix: 'Serve with gunicorn/uvicorn in production and read debug from the environment: app.run(debug=os.getenv("FLASK_DEBUG") == "1") bound to 127.0.0.1.' });
      }
    });
  }

  // GAP-22: whole submitted form written to the database (Object.fromEntries(formData))
  if (isJs && /Object\.fromEntries/.test(cleanContent)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /(?:\.(?:update|insert|upsert)\(\s*|\bdata\s*:\s*)(?:\{\s*\.\.\.)?Object\.fromEntries\(\s*(?:await\s+)?\w*(?:form|req)\w*(?:\.entries\(\))?\s*\)/i.test(l)) {
        add({ ruleId: 28822, code: 'GAP-22', severity: 'HIGH', category: 'Mass Assignment', lineIdx: i,
          title: 'Every Submitted Form Field Is Written to the Database (Object.fromEntries)',
          why: 'Form fields come from the client, so a request can add role, plan, credits or user_id to the form and the update writes them as-is.',
          fix: 'Parse the form with a Zod schema that lists the editable fields (schema.parse(Object.fromEntries(formData))) and write only the parsed object.' });
      }
    });
  }

  // GAP-23: every key of a request dict copied onto a model (for k, v in payload.items(): setattr(obj, k, v))
  if (isPy) {
    lines.forEach((l, i) => {
      const loop = l.match(/^\s*for\s+(\w+)\s*,\s*(\w+)\s+in\s+(\w+(?:\.\w+)*(?:\(\))?)\.items\(\)\s*:/);
      if (!loop || isComment(l) || !/payload|body|data|update|changes|patch|request|json|form|params/i.test(loop[3])) return;
      const win = lines.slice(i, i + 3).join('\n');
      if (new RegExp(String.raw`\bif\s+(?:not\s+)?` + loop[1] + String.raw`\s+(?:not\s+)?in\b`).test(win)) return;
      if (new RegExp(String.raw`\bsetattr\(\s*\w+\s*,\s*` + loop[1] + String.raw`\s*,\s*` + loop[2] + String.raw`\s*\)`).test(win)) {
        add({ ruleId: 28823, code: 'GAP-23', severity: 'HIGH', category: 'Mass Assignment', lineIdx: i,
          title: 'Every Request Field Is Copied Onto the Model (setattr loop)',
          why: `Each key in ${loop[3]} becomes an attribute, so a request can set is_admin, role, balance or owner_id along with the fields the form shows.`,
          fix: 'Validate with a Pydantic model that lists the editable fields and copy only those: for k, v in UserUpdate(**payload).model_dump(exclude_unset=True).items().' });
      }
    });
  }

  // GAP-24: Go handler reflects the request Origin while allowing credentials
  if (/\.go$/i.test(path) && /Access-Control-Allow-Credentials["']?\s*,\s*["']true/i.test(cleanContent)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /Header\(\)\.(?:Set|Add)\(\s*"Access-Control-Allow-Origin"\s*,\s*\w+\.Header\.Get\(\s*"Origin"\s*\)\s*\)/.test(l)) {
        add({ ruleId: 28824, code: 'GAP-24', severity: 'HIGH', category: 'Network & CORS', lineIdx: i,
          title: 'CORS Reflects Any Origin With Credentials Allowed',
          why: 'Echoing the request Origin together with Allow-Credentials: true lets any website make authenticated requests with the user\'s cookies and read the responses.',
          fix: 'Compare the Origin against an allow-list of exact origins and only then echo it (and add Vary: Origin).' });
      }
    });
  }

  // GAP-25: Supabase Edge Function runs an auth.admin operation for any caller
  if (/(?:^|\/)supabase\/functions\/.+\.[jt]s$/i.test(path) && /SERVICE_ROLE/.test(cleanContent)
    && !/\.auth\.getUser\s*\(|getClaims\s*\(|jwtVerify|verify\w*\s*\(|headers\.get\(/i.test(cleanContent)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /\.auth\.admin\.(?:deleteUser|updateUserById|createUser|inviteUserByEmail|generateLink)\s*\(/.test(l)) {
        add({ ruleId: 28825, code: 'GAP-25', severity: 'HIGH', category: 'Broken Access Control', lineIdx: i,
          title: 'Edge Function Runs an Admin Auth Operation Without Checking the Caller',
          why: 'Edge Functions accept the public anon key as a valid JWT by default, and this function never resolves the caller, so anyone can trigger the service-role admin call on any user.',
          fix: 'Resolve the caller first (const { data: { user } } = await supabase.auth.getUser(token) from the Authorization header), check they may act on the target, and only then use the admin client.' });
      }
    });
  }

  const isNextConfig = /(?:^|\/)next\.config\.[cm]?[jt]s$/i.test(path);
  // GAP-26: server secret inlined into the client bundle through next.config env
  if (isNextConfig && /\benv\s*:\s*\{/.test(cleanContent)) {
    const block = cleanContent.slice(cleanContent.search(/\benv\s*:\s*\{/));
    const end = block.indexOf('}');
    const start = cleanContent.length - block.length;
    for (const m of block.slice(0, end).matchAll(/\b(\w*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|DATABASE_URL|API_KEY|TOKEN)\w*)\s*:/gi)) {
      if (/PUBLISHABLE|PUBLIC|ANON/i.test(m[1])) continue;
      add({ ruleId: 28826, code: 'GAP-26', severity: 'CRITICAL', category: 'Secret Isolation', lineIdx: lineAt(cleanContent, start + m.index!),
        title: `Server Secret ${m[1]} Inlined Into the Browser Bundle (next.config env)`,
        why: 'Values in the next.config env block are replaced into client-side JavaScript at build time, so anyone can read this secret from the shipped bundle.',
        fix: `Remove ${m[1]} from next.config env and read process.env.${m[1]} only in server code (route handlers, server actions, server components).` });
    }
  }

  // GAP-27: rewrite whose destination host comes from the request path (open proxy / SSRF)
  if (isNextConfig) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /\bdestination\s*:\s*['"\x60]https?:\/\/:\w+/.test(l)) {
        add({ ruleId: 28827, code: 'GAP-27', severity: 'HIGH', category: 'Server-Side Request Forgery', lineIdx: i,
          title: 'Rewrite Destination Host Taken From the Request Path (Open Proxy)',
          why: 'The host part of the destination is a path parameter, so a request can make the server fetch any URL, including internal services and cloud metadata endpoints, and return the response.',
          fix: 'Hard-code the destination host (https://api.example.com/:path*) and keep only the path as a parameter.' });
      }
    });
  }

  // GAP-28: secret transformed before printing, which defeats GitHub log masking
  if (/(?:^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(path)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /\$\{\{\s*secrets\.\w+\s*\}\}[^|\n]*\|\s*(?:base64|rev|xxd|od|hexdump|sed|tr)\b/.test(l)) {
        add({ ruleId: 28828, code: 'GAP-28', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
          title: 'Workflow Prints an Encoded Secret, Bypassing Log Masking',
          why: 'GitHub masks only the literal secret value; base64 or other transforms print a different string that is not masked, and the log (public for public repos) reveals the secret.',
          fix: 'Never echo secrets. Pass them to tools through env: and let the tool read them; if you need an encoded form, register it with ::add-mask:: before printing anything.' });
      }
    });
  }

  // GAP-29: secret baked into a Docker image layer
  if (/(?:^|\/)Dockerfile(?:\.[\w-]+)?$/i.test(path)) {
    lines.forEach((l, i) => {
      if (isComment(l)) return;
      const copyEnv = /^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?\s/i.test(l);
      const envSecret = /^\s*ENV\s+(\w*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|PASSWORD|API_KEY|_TOKEN)\w*)\s*[= ]\s*\S/i.exec(l);
      if (!copyEnv && !(envSecret && !/PUBLIC|PUBLISHABLE/i.test(envSecret[1]))) return;
      add({ ruleId: 28829, code: 'GAP-29', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
        title: copyEnv ? 'Environment File Copied Into the Docker Image' : `Secret ${envSecret![1]} Stored in a Docker Image Layer`,
        why: 'Image layers keep every file and ENV value; anyone who can pull the image (registry, CI cache, a leaked tarball) reads the secret with docker history or by unpacking the layer.',
        fix: 'Pass secrets at runtime (docker run -e / orchestrator secrets) or with BuildKit RUN --mount=type=secret during the build; add .env to .dockerignore.' });
    });
  }

  const isTemplate = /\.(?:example|sample|template|dist)(?:\.[a-z]+)?$/i.test(path);
  // GAP-30: Supabase Supavisor pooler URI with the database password inline (SEC-SECRET-82 covers only db.<ref>.supabase.co)
  if (!isTemplate) {
    lines.forEach((l, i) => {
      const m = /postgres(?:ql)?:\/\/postgres\.[a-z0-9]{15,25}:([^@\s'"`]{6,})@aws-\d+-[a-z0-9-]+\.pooler\.supabase\.com/i.exec(l);
      if (!m || /\$\{|\$[A-Z_]|<|\[|YOUR|PASSWORD|placeholder/i.test(m[1])) return;
      add({ ruleId: 28830, code: 'GAP-30', severity: 'CRITICAL', category: 'Secret Isolation', lineIdx: i,
        title: 'Supabase Pooler Connection String With the Database Password Committed',
        why: 'The pooler URI carries the postgres password, which bypasses RLS entirely: anyone with the repo can read and write every table.',
        fix: 'Reset the database password in Supabase (Project Settings > Database) and read the URI from an environment variable such as DATABASE_URL.' });
    });
  }

  // GAP-31: Convex production deploy/admin key in code (full read/write on every table)
  if (!isTemplate) {
    lines.forEach((l, i) => {
      if (/\bprod:[a-z]+-[a-z]+-\d{2,4}\|[A-Za-z0-9+/=_-]{40,}/.test(l)) {
        add({ ruleId: 28831, code: 'GAP-31', severity: 'CRITICAL', category: 'Secret Isolation', lineIdx: i,
          title: 'Convex Production Deploy Key Committed',
          why: 'A Convex prod deploy key grants admin access to the deployment: it can run any function and read or overwrite all data, skipping your auth checks.',
          fix: 'Regenerate the deploy key in the Convex dashboard and provide it only through CONVEX_DEPLOY_KEY in CI or hosting secrets.' });
      }
    });
  }

  // GAP-32: Next.js server actions encryption key hard-coded in build/deploy config
  if (/(?:^|\/)(?:Dockerfile(?:\.[\w-]+)?|docker-compose[\w.-]*\.ya?ml|compose\.ya?ml|next\.config\.[cm]?[jt]s|vercel\.json|\.github\/workflows\/[^/]+\.ya?ml)$/i.test(path)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /NEXT_SERVER_ACTIONS_ENCRYPTION_KEY['"]?\s*[:=\s]\s*['"]?[A-Za-z0-9+/]{32,}={0,2}/.test(l)) {
        add({ ruleId: 28832, code: 'GAP-32', severity: 'HIGH', category: 'Secrets Management', lineIdx: i,
          title: 'Next.js Server Actions Encryption Key Hard-Coded',
          why: 'This key encrypts the variables that server actions capture from their closure; with it an attacker can read those values and forge action payloads.',
          fix: 'Generate a new key and inject NEXT_SERVER_ACTIONS_ENCRYPTION_KEY at build time from a secret store (CI secret, Docker build secret), never as a literal.' });
      }
    });
  }

  // GAP-33: env file, dump, Terraform state, private key, backup or log inside a folder the host serves as-is
  if (PUBLIC_ARTIFACT.test(path)) {
    const name = path.split('/').pop() || path;
    const critical = /^\.env|\.(?:sql|dump|sql\.gz|tfstate|tfstate\.backup|p12|pfx|pem)$|^id_/i.test(name);
    add({ ruleId: 28833, code: 'GAP-33', severity: critical ? 'CRITICAL' : 'HIGH', category: 'Information Disclosure', lineIdx: 0,
      title: `Sensitive File in a Public Web Folder (${name})`,
      why: `Everything under public/ (or static/) is copied into the deployment and served as a plain file, so anyone can download ${path.replace(/^.*?(?:public|static)\//i, '/')} without signing in. On static hosts such as Vercel and Netlify this is the usual way such a file gets exposed.`,
      fix: 'Delete the file from the public folder and from git history, then rotate every secret it held. Keep dumps, state files and keys outside the repository.' });
  }

  if (isJs) {
    // GAP-34: service role key read in a 'use client' module (bundled for the browser)
    if (/^\s*(?:\/\/[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*['"]use client['"]/.test(file.content)) {
      const i = lines.findIndex((l) => !isComment(l) && /process\.env\.[A-Z_]*SERVICE_ROLE[A-Z_]*/.test(l));
      add({ ruleId: 28834, code: 'GAP-34', severity: 'CRITICAL', category: 'Secrets Management', lineIdx: i,
        title: "Supabase Service Role Key Used in a 'use client' Module",
        why: "A 'use client' module is bundled for the browser. If the variable is exposed to the client it ships to every visitor, and the service role key skips every Row Level Security policy; if it is not, the client gets undefined and the code only works by accident on the server.",
        fix: "Move the admin client into a server-only module (import 'server-only'; route handler or server action) and call it from the client through that boundary." });
    }

    // GAP-35: CORS wildcard origin together with credentials in static header config
    if (/(?:^|\/)next\.config\.[cm]?[jt]s$/i.test(path) && /Access-Control-Allow-Credentials['"]?\s*,\s*value\s*:\s*['"]true/i.test(cleanContent)) {
      const i = lines.findIndex((l) => /Access-Control-Allow-Origin['"]?\s*,\s*value\s*:\s*['"]\*['"]/i.test(l));
      add({ ruleId: 28835, code: 'GAP-35', severity: 'MEDIUM', category: 'CORS Misconfiguration', lineIdx: i,
        title: 'CORS Allows Any Origin with Credentials',
        why: 'Browsers refuse credentialed responses for Access-Control-Allow-Origin: *, so cross-site calls with cookies fail. The usual next "fix" is to reflect the request Origin, which lets any website act as the signed-in user.',
        fix: 'List the exact origins that may call the API with credentials, or drop Access-Control-Allow-Credentials if the API does not use cookies.' });
    }

    // GAP-36: user-controlled URL rendered as a link without a scheme check
    if (/\.[jt]sx$/i.test(path) && !/\b(?:safeUrl|sanitizeUrl|isSafeUrl|isValidUrl|sanitize|startsWith\(\s*['"]https?:)/.test(cleanContent)) {
      const i = lines.findIndex((l) => !isComment(l) && /\bhref=\{\s*(?:props\.)?(?:profile|user|author|member|account|seller|owner|creator)\??\.(?:website|homepage|url|link|social\w*|portfolio\w*)\s*\}/i.test(l));
      add({ ruleId: 28836, code: 'GAP-36', severity: 'MEDIUM', category: 'Cross-Site Scripting', lineIdx: i,
        title: 'User-Supplied URL Rendered as a Link Without a Scheme Check',
        why: 'A user can save "javascript:…" as their website; React 18 and older render it and the code runs for every visitor who clicks the link (React 19 blocks javascript: URLs, other schemes like data: still pass).',
        fix: "Accept only http(s): check new URL(value).protocol is 'http:' or 'https:' when saving and before rendering, and add rel=\"noopener noreferrer\" for external links." });
    }

    // GAP-37: request body deep-merged into an object
    {
      const i = lines.findIndex((l) => !isComment(l) && /\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep)\s*\((?:[^()]*,)?\s*req(?:uest)?\.(?:body|query)\s*[,)]/.test(l));
      add({ ruleId: 28837, code: 'GAP-37', severity: 'MEDIUM', category: 'Mass Assignment', lineIdx: i,
        title: 'Request Body Deep-Merged into an Object',
        why: 'Every key the client sends lands in the result, including fields it should not control (role, plan, limits). With lodash older than 4.17.12 a "__proto__" key also pollutes Object.prototype for the whole process.',
        fix: 'Validate the body with a schema (zod, joi) that lists the allowed fields, then merge only the parsed result.' });
    }
  }

  // GAP-38: FastAPI route that changes or deletes data without an auth dependency
  if (isPy && /\bfrom\s+fastapi\b/.test(cleanContent) && !/APIRouter\([^)]*dependencies\s*=/.test(cleanContent)) {
    lines.forEach((l, i) => {
      const m = l.match(/^\s*@\w+\.(delete|put|patch)\(\s*['"]([^'"]*)['"]([^)]*)\)/);
      if (!m || /dependencies\s*=/.test(m[3]) || /webhook|callback|health/i.test(m[2])) return;
      // Signature: the def line(s) up to the closing "):"
      let sig = '';
      for (let j = i + 1; j < Math.min(lines.length, i + 12); j++) {
        sig += lines[j];
        if (/\)\s*(?:->[^:]*)?:\s*$/.test(lines[j])) break;
      }
      if (!/^\s*(?:async\s+)?def\s/.test(lines[i + 1] || '')) return;
      // Parameters only (not the function name). The caller is identified by an auth dependency (Depends(get_current_user_id)),
      // an auth-named parameter (current_user: …) or an auth type (CurrentUser); a record id such as user_id: str is not one.
      const params = sig.slice(sig.indexOf('(') + 1);
      if (/(?:Depends|Security)\(\s*[\w.]*(?:user|auth|token|admin|current|verify|require|permission|principal|api_?key|owner|login)/i.test(params)
        || /(?:^|[(,\s])(?!\w*_ids?\s*:)\w*(?:user|auth|admin|principal|token|api_?key)\w*\s*:/i.test(params)
        || /:\s*(?:Annotated\[\s*)?(?:Current\w+|\w*(?:Principal|AuthUser|AuthContext))\b/.test(params)) return;
      add({ ruleId: 28838, code: 'GAP-38', severity: 'HIGH', category: 'Broken Access Control', lineIdx: i + 1,
        title: `FastAPI ${m[1].toUpperCase()} Route Without an Auth Dependency (${m[2]})`,
        why: 'Nothing in the route signature identifies the caller (no Depends(get_current_user), Security() or user parameter) and the router has no dependencies=, so anyone who can reach the API can call it.',
        fix: 'Add current_user: User = Depends(get_current_user) (or router-level dependencies=[Depends(...)]) and check that the user may change this record.' });
    });
  }

  // GAP-19: Auth.js / NextAuth links an OAuth sign-in to an existing account by e-mail alone
  if (isJs && /next-auth|@auth\//.test(cleanContent)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /\ballowDangerousEmailAccountLinking\s*:\s*true\b/.test(l)) {
        add({ ruleId: 28819, code: 'GAP-19', severity: 'MEDIUM', category: 'Authentication', lineIdx: i,
          title: 'OAuth Account Linked to an Existing User by E-mail Alone (allowDangerousEmailAccountLinking)',
          why: 'A sign-in from this provider is merged into any existing account with the same e-mail. If the provider (or a second one) lets users set an unverified address, an attacker registers the victim\'s e-mail there and signs in as the victim.',
          fix: 'Remove the flag and let users link providers from their settings page while signed in, or keep it only for providers that guarantee verified e-mails.' });
      }
    });
  }

  // GAP-20: Laravel model with mass assignment fully open
  if (/\.php$/i.test(path) && /\bextends\s+(?:Model|Authenticatable)\b/.test(cleanContent)) {
    lines.forEach((l, i) => {
      if (!isComment(l) && /^\s*protected\s+\$guarded\s*=\s*\[\s*\]\s*;/.test(l)) {
        add({ ruleId: 28820, code: 'GAP-20', severity: 'MEDIUM', category: 'Mass Assignment', lineIdx: i,
          title: 'Laravel Model Allows Mass Assignment of Every Column ($guarded = [])',
          why: 'Model::create($request->all()) or ->update($request->all()) then writes any column the client sends, such as is_admin, role or balance.',
          fix: 'Declare $fillable with the columns users may set, and pass $request->validated() instead of $request->all().' });
      }
    });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `gap${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [GAP] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
