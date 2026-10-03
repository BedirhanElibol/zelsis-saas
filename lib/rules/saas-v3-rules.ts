/**
 * Webhook and payment integrity, browser messaging, Supabase RLS identity and Next.js 16 request API rules (SAAS3-xx, Rule IDs 28701-28749).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit {
  ruleId: number;
  code: string;
  title: string;
  severity: Finding['severity'];
  category: string;
  lineIdx: number;
  why: string;
  fix: string;
}

const lineAt = (text: string, idx: number): number => {
  let n = 0;
  for (let i = 0; i < idx && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
};

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Index of the bracket closing the one at `openIdx` (counts (), [] and {} together; skips quoted strings on one line). */
function matchClose(src: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'") {
      const end = src.indexOf(c, i + 1);
      const nl = src.indexOf('\n', i + 1);
      if (end !== -1 && (nl === -1 || end < nl)) { i = end; continue; }
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
      if (depth < 0) return -1;
    }
  }
  return -1;
}

/** Splits a parameter / destructuring list on top-level commas. */
function splitTopLevel(src: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
    else if (c === ')' || c === ']' || c === '}' || (c === '>' && src[i - 1] !== '=')) depth--;
    else if (c === ',' && depth === 0) { out.push(src.slice(start, i)); start = i + 1; }
  }
  out.push(src.slice(start));
  return out.map((s) => s.trim()).filter(Boolean);
}

// ─── SAAS3-01 ───────────────────────────────────────────────────────────────────────────────
/** Parsed (not raw) request body sources. */
const PARSED_BODY = String.raw`(?:await\s+)?(?:\w+\.)*(?:req|request|c\.req)\.json\(\s*\)|(?:\w+\.)?(?:req|request)\.body\b(?!\s*(?:\.|\?\.|\[))`;

function verifyOverReserializedJson(content: string): number {
  const parsed = new Set<string>();
  for (const m of content.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*(?::[^=;\n]+)?=\s*(?:${PARSED_BODY})`, 'g'))) parsed.add(m[1]);
  const parsedSrc = [PARSED_BODY, ...[...parsed].map((p) => String.raw`\b${escapeRe(p)}\b`)].join('|');
  const stringifyOfParsed = new RegExp(String.raw`JSON\.stringify\(\s*(?:${parsedSrc})\s*[,)]`);
  const stringified = new Set<string>();
  for (const m of content.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*(?::[^=;\n]+)?=\s*JSON\.stringify\(\s*(?:${parsedSrc})\s*[,)]`, 'g'))) stringified.add(m[1]);

  const sdkVerify = /svix|standardwebhooks|standard-webhooks|@polar-sh|webhook/i.test(content);
  const hmac = /createHmac\s*\(/.test(content) && /webhook|signature/i.test(content);
  const calls = /\b(constructEvent(?:Async)?|validateEvent|verify|update)\s*\(/g;
  for (const m of content.matchAll(calls)) {
    const fn = m[1];
    if (fn === 'verify' && !sdkVerify) continue;
    if (fn === 'update' && !hmac) continue;
    if (fn === 'update') {
      // Only an HMAC update (chained on createHmac or on an hmac variable)
      const before = content.slice(Math.max(0, m.index - 200), m.index);
      if (!/createHmac\s*\([^;]*$|\b\w*(?:hmac|hasher|hash|mac|signer)\w*\s*\.?\s*$/i.test(before)) continue;
    }
    const open = m.index + m[0].length - 1;
    const close = matchClose(content, open);
    if (close === -1) continue;
    const args = content.slice(open + 1, close);
    const first = splitTopLevel(args)[0] || '';
    if (stringifyOfParsed.test(args) || stringified.has(first)) return lineAt(content, m.index);
  }
  return -1;
}

// ─── SAAS3-02 ───────────────────────────────────────────────────────────────────────────────
const PAYMENT_EVENT = /['"`](?:checkout\.session\.(?:completed|async_payment_succeeded)|invoice\.(?:paid|payment_succeeded)|payment_intent\.succeeded|charge\.succeeded|customer\.subscription\.(?:created|updated)|order[._](?:created|paid|completed)|subscription[._](?:created|updated|renewed|payment_success|active)|transaction\.completed|checkout\.completed)['"`]/;
const BALANCE_FIELD = String.raw`\w*(?:credit|balance|token|quota|point|coin|minute|generation)s?\w*`;
const INCREMENTS: RegExp[] = [
  new RegExp(String.raw`\b${BALANCE_FIELD}\s*:\s*\{\s*increment\s*:`, 'i'),
  /\$inc\s*:/,
  /\.rpc\(\s*['"`](?:increment|add|grant|top_?up)\w*['"`]/i,
  new RegExp(String.raw`\b${BALANCE_FIELD}\s*(?::|=(?!=))\s*\(?\s*(?:[\w?.]*\.)?${BALANCE_FIELD}\s*(?:\?\?\s*0\s*\)?\s*|\|\|\s*0\s*\)?\s*)?\+\s*[\w(]`, 'i'),
  new RegExp(String.raw`\b${BALANCE_FIELD}\s*\+=`, 'i'),
  new RegExp(String.raw`SET\s+"?${BALANCE_FIELD}"?\s*=\s*"?${BALANCE_FIELD}"?\s*\+`, 'i')
];
const EVENT_DEDUPE = /\b(?:event|evt|webhookEvent|stripeEvent|payload|body)\s*(?:\.|\?\.)\s*id\b|\b(?:event_?id|eventId|webhook_?id|webhookId|svix-id|webhook-id|idempoten\w*|processed_?\w*events?|webhook_?events?|stripe_?events?|already_?processed|alreadyProcessed|isDuplicate|dedup\w*)\b|['"]?\w*(?:session|payment|order|invoice|event|checkout|transaction|charge)_?id['"]?\s*[:,]\s*[\w.?]+\.id\b/i;

// ─── SAAS3-03 ───────────────────────────────────────────────────────────────────────────────
const SDK_VERIFIER = /constructEvent|construct_event|validateEvent|validate_event|\bsvix\b|standardwebhooks|standard-webhooks|@slack\/bolt|SignatureVerifier|@octokit\/webhooks/i;
const FRESHNESS = /Date\.now\s*\(|new Date\s*\(\s*\)|getTime\s*\(|time\.time\s*\(|datetime\.(?:utc)?now|timezone\.now|time\.Now|tolerance|max_?age|maxAge|freshness|\bstale\b|expired|replay|skew|Math\.abs|\babs\s*\(|time\.monotonic|now\s*\(\s*\)/i;
const TIMESTAMP_SOURCE = /timestamp['"`]|['"`]t=|\.t\b|\[\s*['"`]t['"`]\s*\]|x-[\w-]*timestamp|webhook-timestamp/i;

// ─── SAAS3-04 ───────────────────────────────────────────────────────────────────────────────
const MESSAGE_SINK = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|\beval\s*\(|new\s+Function\s*\(|location\b|window\.open\s*\(|\.href\s*=|\.src\s*=|setAttribute\s*\(|localStorage|sessionStorage|document\.cookie|\bfetch\s*\(|axios|\.postMessage\s*\(|navigate\s*\(|router\.(?:push|replace)\s*\(|redirect\s*\(|setSession|setToken|setAuth|signIn|login|\.rpc\s*\(|\.from\s*\(\s*['"`]|\.(?:insert|update|delete|upsert)\s*\(/i;
function messageHandlerRisk(handler: string): boolean {
  const pm = /^\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*(\{[^}]*\}|[A-Za-z_$][\w$]*)/.exec(handler);
  if (!pm) return false;
  const param = pm[1];
  let usesData = false;
  if (param.startsWith('{')) usesData = /\bdata\b/.test(param);
  else {
    const p = escapeRe(param);
    usesData = new RegExp(String.raw`\b${p}\s*(?:\?\.|\.)\s*data\b|\{[^{}]*\bdata\b[^{}]*\}\s*=\s*${p}\b`).test(handler);
  }
  if (!usesData) return false;
  if (/\borigin\b/i.test(handler)) return false;
  if (/\.source\s*[!=]==?|[!=]==?\s*[\w.]+\.source\b|\bsource\s*[!=]==?/.test(handler)) return false;
  // Only handlers that act on the message: logging or rendering it as React text is not exploitable
  return MESSAGE_SINK.test(handler);
}

/** Text of a handler defined by name in the same file (function declaration or const arrow / useCallback). */
function namedHandlerText(content: string, name: string): string | null {
  const n = escapeRe(name);
  const def = new RegExp(String.raw`(?:function\s+${n}\s*\(|(?:const|let|var)\s+${n}\s*(?::[^=\n]+)?=\s*(?:useCallback\s*\(\s*)?)`).exec(content);
  if (!def) return null;
  const start = def.index + def[0].length;
  if (/^function/.test(def[0])) {
    const close = matchClose(content, start - 1);
    if (close === -1) return null;
    const brace = content.indexOf('{', close);
    const end = brace === -1 ? -1 : matchClose(content, brace);
    return end === -1 ? null : content.slice(start - 1, end + 1);
  }
  const rest = content.slice(start);
  const arrow = rest.search(/=>/);
  const fnKw = /^\s*(?:async\s+)?function\b/.test(rest);
  if (arrow === -1 && !fnKw) return null;
  let i = fnKw ? rest.indexOf('{', matchClose(rest, rest.indexOf('('))) : arrow + 2;
  while (i < rest.length && /\s/.test(rest[i])) i++;
  if (rest[i] === '{') {
    const end = matchClose(rest, i);
    return end === -1 ? null : rest.slice(0, end + 1);
  }
  const nl = rest.indexOf('\n', i);
  return rest.slice(0, nl === -1 ? undefined : nl);
}

// ─── SAAS3-06 ───────────────────────────────────────────────────────────────────────────────
const NEXT_ENTRY = /(?:^|\/)app\/(?:.*\/)?(?:page|layout|default|route)\.[cm]?[jt]sx?$/;
const NEXT_EXPORT = /export\s+default\s+(?:async\s+)?function\s*\w*\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|generateMetadata|generateViewport)\s*\(|export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|generateMetadata|generateViewport)\s*=\s*(?:async\s*)?\(/g;

function syncRequestPropAccess(content: string): number {
  const starts: number[] = [];
  for (const m of content.matchAll(NEXT_EXPORT)) starts.push(m.index + m[0].length - 1);
  const defName = /export\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/m.exec(content);
  if (defName) {
    const d = new RegExp(String.raw`(?:const|let)\s+${escapeRe(defName[1])}\s*(?::[^=\n]+)?=\s*(?:async\s*)?\(`).exec(content);
    if (d) starts.push(d.index + d[0].length - 1);
  }
  for (const open of starts) {
    const close = matchClose(content, open);
    if (close === -1) continue;
    const head = /^\s*(?::\s*[\w.<>[\]| ]*?)?\s*(?:=>\s*)?\{/.exec(content.slice(close + 1, close + 200));
    if (!head) continue;
    const bodyOpen = close + head[0].length;
    const bodyClose = matchClose(content, bodyOpen);
    if (bodyClose === -1) continue;
    const body = content.slice(bodyOpen, bodyClose);
    const names = new Set<string>();
    const propsIds: string[] = [];
    for (const param of splitTopLevel(content.slice(open + 1, close))) {
      if (param.startsWith('{')) {
        const pEnd = matchClose(param, 0);
        if (pEnd === -1) continue;
        for (const entry of splitTopLevel(param.slice(1, pEnd))) {
          const em = /^(params|searchParams)\b\s*(?::\s*([\s\S]*))?$/.exec(entry);
          if (!em) continue;
          if (em[2] && em[2].trim().startsWith('{')) return lineAt(content, open + 1 + content.slice(open + 1).indexOf(entry));
          names.add(em[2] && /^[A-Za-z_$][\w$]*$/.test(em[2].trim()) ? em[2].trim() : em[1]);
        }
      } else {
        const id = /^([A-Za-z_$][\w$]*)/.exec(param);
        if (id && !/^(?:req|request|_req|_request|_)$/.test(id[1])) propsIds.push(id[1]);
      }
    }
    for (const p of propsIds) {
      const pe = escapeRe(p);
      for (const m of body.matchAll(new RegExp(String.raw`(?:const|let)\s*\{([^{}]*)\}\s*=\s*${pe}\s*(?:;|\n)`, 'g'))) {
        for (const e of splitTopLevel(m[1])) {
          const em = /^(params|searchParams)\b\s*(?::\s*([A-Za-z_$][\w$]*))?$/.exec(e);
          if (em) names.add(em[2] || em[1]);
        }
      }
      for (const prop of ['params', 'searchParams']) {
        const chain = String.raw`\b${pe}\s*(?:\?\.|\.)\s*${prop}`;
        if (new RegExp(String.raw`await\s+\(?\s*${chain}|use\(\s*${chain}|${chain}\s*\.then\s*\(`).test(body)) continue;
        const sync = new RegExp(String.raw`${chain}\s*(?:(?:\?\.|\.)\s*(?!then\b|catch\b|finally\b)[A-Za-z_$]|\?\.\s*\[|\[)`).exec(body);
        if (sync) return lineAt(content, bodyOpen + sync.index);
      }
    }
    for (const n of names) {
      const ne = escapeRe(n);
      if (new RegExp(String.raw`await\s+\(?\s*${ne}\b|use\(\s*${ne}\s*\)|\b${ne}\s*\.then\s*\(|\b${ne}\s*=(?!=)`).test(body)) continue;
      const sync = new RegExp(String.raw`(?<![\w$.])${ne}\s*(?:(?:\?\.|\.)\s*(?!then\b|catch\b|finally\b)[A-Za-z_$]|\?\.\s*\[|\[)|(?:const|let|var)\s*\{[^{}]*\}\s*=\s*${ne}\s*(?:;|\n)`).exec(body);
      if (sync) return lineAt(content, bodyOpen + sync.index);
    }
  }
  return -1;
}

export function evaluateSaasV3Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = (file.path || '').replace(/\\/g, '/');
  if (/node_modules\//.test(path)) return { findings, logs };
  const isJs = /\.[cm]?[jt]sx?$/i.test(path);
  const isPy = /\.py$/i.test(path);
  const hits: Hit[] = [];

  // SAAS3-01: webhook signature verified over JSON.stringify(parsed body) instead of the raw bytes
  if (isJs && /JSON\.stringify/.test(cleanContent)) {
    const at = verifyOverReserializedJson(cleanContent);
    if (at !== -1) {
      hits.push({
        ruleId: 28701, code: 'SAAS3-01', severity: 'MEDIUM', category: 'Webhook Integrity', lineIdx: at,
        title: 'Webhook Signature Verified Over Re-Serialized JSON Instead of the Raw Body',
        why: 'The provider signs the exact raw bytes it sent. JSON.stringify of the parsed body changes whitespace, key order and number/unicode formatting, so genuine events fail verification (teams then disable the check) and many distinct raw payloads map to one "verified" object.',
        fix: 'Read the raw body (`const payload = await req.text()` in a route handler, `express.raw({ type: "application/json" })` in Express) and pass that string or Buffer to the verifier; JSON.parse it only after verification succeeds.'
      });
    }
  }

  // SAAS3-02: payment webhook increments a balance without recording the event id (retries double-credit)
  if ((isJs || isPy) && PAYMENT_EVENT.test(cleanContent) && (/webhook/i.test(path) || /webhook|constructEvent|construct_event|validateEvent|stripe-signature|x-signature/i.test(cleanContent))) {
    const incIdx = lines.findIndex((l) => INCREMENTS.some((re) => re.test(l)));
    if (incIdx !== -1 && !EVENT_DEDUPE.test(cleanContent)) {
      hits.push({
        ruleId: 28702, code: 'SAAS3-02', severity: 'HIGH', category: 'Payment Integrity', lineIdx: incIdx,
        title: 'Payment Webhook Grants Credits Without Event-ID Deduplication',
        why: 'Payment providers deliver webhooks at least once and retry on timeouts or 5xx, and anyone holding one signed delivery can replay it. An increment that is not keyed on the event id credits the account again on every redelivery.',
        fix: 'Record event.id (or the checkout/order id) in a table with a unique constraint inside the same transaction as the increment, and skip the side effect when the insert conflicts; or set the balance from the order total instead of incrementing it.'
      });
    }
  }

  // SAAS3-03: hand-rolled HMAC that signs a timestamp but never checks how old it is
  if ((isJs || isPy) && /createHmac\s*\(|hmac\.new\s*\(|crypto\.subtle\.(?:sign|verify)\s*\(/.test(cleanContent) &&
      !SDK_VERIFIER.test(cleanContent) && !FRESHNESS.test(cleanContent) &&
      /timingSafeEqual|compare_digest|signature/i.test(cleanContent)) {
    const tsVars = new Set<string>();
    for (const l of lines) {
      const am = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w|<> ]+)?\s*=(?!=)\s*(.+)$/.exec(l);
      if (am && TIMESTAMP_SOURCE.test(am[2]) && !/Date\.now|new Date|time\.time/.test(am[2])) tsVars.add(am[1]);
    }
    let at = -1;
    for (const t of tsVars) {
      const te = escapeRe(t);
      const signed = new RegExp(String.raw`\$\{\s*${te}\s*\}|\{${te}\}|\b${te}\s*\+|\+\s*${te}\b|update\(\s*${te}\b|\[\s*${te}\s*,`);
      const i = lines.findIndex((l) => signed.test(l) && !/^\s*(?:const|let|var)?\s*\w+\s*=\s*[^=]*\bparseInt\b/.test(l));
      if (i !== -1) { at = i; break; }
    }
    if (at !== -1) {
      hits.push({
        ruleId: 28703, code: 'SAAS3-03', severity: 'MEDIUM', category: 'Webhook Integrity', lineIdx: at,
        title: 'Webhook HMAC Signs a Timestamp That Is Never Checked for Freshness',
        why: 'The timestamp is included in the signed payload but never compared with the current time, so a captured request (signature and timestamp together) stays valid forever and can be replayed.',
        fix: 'Reject the request when |now - timestamp| exceeds a small tolerance (e.g. 300 seconds) before comparing signatures, or use the provider SDK verifier, which enforces the tolerance for you.'
      });
    }
  }

  // SAAS3-04: window message listener reads event.data without checking event.origin
  if (/\.(?:[cm]?[jt]sx?|vue|svelte|html?|astro)$/i.test(path) && !/worker|(?:^|\/)sw\.[cm]?[jt]s$/i.test(path) &&
      !/\bimportScripts\s*\(|WorkerGlobalScope/.test(cleanContent)) {
    const regs = /\b(?:window|globalThis)\s*(?:\.|\?\.)\s*addEventListener\s*\(\s*['"`]message['"`]\s*,\s*|\bwindow\s*\.\s*onmessage\s*=\s*/g;
    for (const m of cleanContent.matchAll(regs)) {
      const start = m.index + m[0].length;
      let handler: string | null = null;
      const named = /^([A-Za-z_$][\w$]*)\s*(?:[,);]|$)/m.exec(cleanContent.slice(start, start + 80));
      if (named && !/^(?:async|function)$/.test(named[1])) handler = namedHandlerText(cleanContent, named[1]);
      else if (m[0].includes('addEventListener')) {
        const close = matchClose(cleanContent, m.index + m[0].indexOf('(', m[0].indexOf('addEventListener')));
        if (close !== -1) handler = cleanContent.slice(start, close);
      } else {
        const fnBrace = cleanContent.indexOf('{', start);
        const end = fnBrace === -1 ? -1 : matchClose(cleanContent, fnBrace);
        if (end !== -1) handler = cleanContent.slice(start, end + 1);
      }
      if (handler && messageHandlerRisk(handler)) {
        hits.push({
          ruleId: 28704, code: 'SAAS3-04', severity: 'HIGH', category: 'Cross-Origin Messaging', lineIdx: lineAt(cleanContent, m.index),
          title: 'postMessage Listener Trusts event.data Without Checking event.origin',
          why: 'Any page can call postMessage on this window (by opening it, or framing it if framing is allowed). Without an event.origin check the handler acts on attacker-controlled data: tokens, navigation targets, HTML or state updates.',
          fix: "Return early unless event.origin is exactly an expected origin (e.g. `if (event.origin !== 'https://app.example.com') return;`), and validate event.data with a schema before using it."
        });
        break;
      }
    }
  }

  // SAAS3-05: RLS policy authorizes on the email claim
  if (/\.sql$/i.test(path)) {
    const sql = cleanContent.replace(/--[^\n]*/g, '');
    for (const m of sql.matchAll(/CREATE\s+POLICY[\s\S]*?;/gi)) {
      const body = m[0];
      if (/user_metadata|raw_user_meta_data/i.test(body)) continue; // NEXT-SB-04 covers user_metadata
      if (/email_verified|email_confirmed_at|confirmed_at/i.test(body)) continue;
      const em = /auth\.email\s*\(\s*\)|auth\.jwt\s*\(\s*\)\s*->>\s*'email'|auth\.jwt\s*\(\s*\)\s*->\s*'email'|current_setting\(\s*'request\.jwt\.claims?'[^)]*\)\s*(?:::\s*jsonb?\s*)?->>\s*'email'/i.exec(body);
      if (!em) continue;
      hits.push({
        ruleId: 28705, code: 'SAAS3-05', severity: 'MEDIUM', category: 'Authorization', lineIdx: lineAt(sql, m.index + em.index),
        title: 'RLS Policy Authorizes Rows by the JWT Email Claim',
        why: 'The email claim is not a stable or necessarily verified identity: with email confirmation off, an OAuth provider that does not verify emails, or an email change in flight, a user can hold a JWT for someone else\'s address and read or write rows granted to it (invites, shared docs, admin allow-lists).',
        fix: 'Authorize on auth.uid() against a membership / roles table; for invites, resolve the invite to a user id at acceptance time. If email must be used, also require verified email (e.g. join auth.users on email_confirmed_at IS NOT NULL).'
      });
      break;
    }
  }

  // SAAS3-06: Next.js 16 params / searchParams read synchronously (they are Promises)
  if (isJs && context?.nextMajorVersion != null && context.nextMajorVersion >= 16 && NEXT_ENTRY.test(path) &&
      /\b(?:params|searchParams)\b/.test(cleanContent)) {
    const at = syncRequestPropAccess(cleanContent);
    if (at !== -1) {
      hits.push({
        ruleId: 28706, code: 'SAAS3-06', severity: 'MEDIUM', category: 'Correctness', lineIdx: at,
        title: 'Next.js 16 Request Props Are Promises: params / searchParams Read Without await',
        why: 'Since Next.js 16 the params and searchParams props of pages, layouts and route handlers are Promises only; sync access returns undefined, so lookups and ownership checks built on params.id silently run against undefined (wrong record, empty filter or skipped authorization).',
        fix: 'Await the prop before reading it (`const { id } = await params`), or `use(params)` in a client component; type it as `Promise<{ id: string }>` (run `npx @next/codemod@latest next-async-request-api .`).'
      });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `saas3${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [SAAS V3] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
