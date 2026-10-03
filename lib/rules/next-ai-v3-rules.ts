/**
 * Next.js cache isolation, server-to-client data leaks and destructive AI agent tools (NEXTAI-xx, Rule IDs 28751-28799).
 *
 * Sources: Next.js `unstable_cache` reference (arguments and the function source form the cache key; closure
 * values must be listed in keyParts), React Server Components serialization of Client Component props,
 * Vercel AI SDK tool calling (`needsApproval`), OWASP Top 10 for LLM Applications 2025 (LLM06 Excessive Agency).
 * Not repeated here: AI-APP-04 / AI-APP-05 (#28204-28205, shell / file-system tools), LLM-V2-09 (#28309, fetch tools).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { emptyRepoContext, type RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const lineOf = (text: string, idx: number) => text.slice(0, idx).split('\n').length - 1;
const IDENT_G = /[A-Za-z_$][\w$]*/g;

/** Index of the bracket closing the one at `open`, skipping string and template literals (no nesting inside `${}`). */
function matchClose(text: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
  const stack: string[] = [];
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === ')' || c === ']' || c === '}') {
      if (stack.pop() !== c) return -1;
      if (!stack.length) return i;
    }
  }
  return -1;
}

/** Top-level comma-separated arguments of an argument list (text between the parentheses). */
function splitArgs(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { out.push(text.slice(start, i)); start = i + 1; }
  }
  if (text.slice(start).trim()) out.push(text.slice(start));
  return out;
}

/** Names declared with const / let / var (plain, object or array destructuring) in a code fragment. */
function declaredNames(code: string): Set<string> {
  const names = new Set<string>();
  for (const m of code.matchAll(/\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)/g)) {
    for (const part of m[1].replace(/^[{[]|[}\]]$/g, '').split(',')) {
      const binding = part.replace(/=[\s\S]*$/, '').split(':').pop()!.replace(/^\s*\.\.\./, '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(binding)) names.add(binding);
    }
  }
  // parameters of nested callbacks: (row) => ..., ({ id }) => ..., item => ...
  for (const m of code.matchAll(/\(([^()]*)\)\s*(?::[^=]*?)?=>|([A-Za-z_$][\w$]*)\s*=>/g)) {
    for (const id of (m[1] ?? m[2] ?? '').match(IDENT_G) || []) names.add(id);
  }
  return names;
}

/* ------------------------------------------------------------------------------------------------ */
/* NEXTAI-01: unstable_cache callback closes over a per-user value missing from keyParts              */
/* ------------------------------------------------------------------------------------------------ */

const SCOPED_ID = /(?<![\w$.])(userId|user_id|uid|orgId|org_id|organizationId|organisationId|tenantId|tenant_id|teamId|team_id|accountId|account_id|workspaceId|workspace_id|customerId|projectId|sessionId)\b(?!\s*:(?!:))/g;
const SCOPED_MEMBER = /(?<![\w$.])(session|user|currentUser|authUser|viewer|me|auth)(?:\??\.user)?\??\.(?:id|email|orgId|organizationId|tenantId|teamId|sub)\b/g;
const REQUEST_SOURCE = /\b(?:cookies|headers|auth|getServerSession|getSession|currentUser|getCurrentUser|getUser|getAuth|getServerUser|validateRequest|getKindeServerSession)\s*\(/;

function cacheLeaks(content: string, hits: Hit[]): void {
  if (!/\bunstable_cache\b/.test(content)) return;
  for (const m of content.matchAll(/\bunstable_cache\s*\(/g)) {
    const start = m.index ?? 0;
    const lineIdx = lineOf(content, start);
    const lineText = content.split('\n')[lineIdx] || '';
    // Module-level caches close over module constants, not request data
    if (!/^\s+/.test(lineText)) continue;
    const open = start + m[0].length - 1;
    const close = matchClose(content, open);
    if (close === -1) continue;
    const args = splitArgs(content.slice(open + 1, close));
    if (!args.length) continue;
    const fn = args[0].trim();
    const keyParts = (args[1] || '').trim();
    // A keyParts variable cannot be checked statically
    if (keyParts && !keyParts.startsWith('[')) continue;
    const sig = fn.match(/^async\s*(?:function\s*[\w$]*\s*)?\(([^)]*)\)\s*(?::[^=]*?)?(?:=>)?/) || fn.match(/^async\s+([A-Za-z_$][\w$]*)\s*=>/);
    if (!sig) continue; // a named function reference: its parameters are its key
    const params = new Set(sig[1].match(IDENT_G) || []);
    const body = fn.slice(sig[0].length);
    const locals = declaredNames(body);
    const before = content.slice(0, start);
    const enclosing = before.split('\n').slice(-80).join('\n');
    // Values read from cookies() / headers() / auth() in the enclosing function (one hop)
    const requestVars = new Set<string>();
    for (const d of enclosing.matchAll(/\b(?:const|let)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*([^;\n]*)/g)) {
      const fromRequest = REQUEST_SOURCE.test(d[2]) || [...requestVars].some((v) => new RegExp(String.raw`\b${escapeRe(v)}\b`).test(d[2]));
      if (!fromRequest) continue;
      for (const id of declaredNames(`const ${d[1]} = 0`)) requestVars.add(id);
    }
    const declaredBefore = (name: string) => new RegExp(String.raw`\b(?:const|let|var)\s+(?:${escapeRe(name)}\b|\{[^}]*\b${escapeRe(name)}\b[^}]*\})|\([^()]*\b${escapeRe(name)}\b[^()]*\)\s*(?::[^{=]*)?(?:=>|\{)`).test(enclosing);
    const candidates = new Set<string>();
    for (const c of body.matchAll(SCOPED_ID)) candidates.add(c[1]);
    for (const c of body.matchAll(SCOPED_MEMBER)) candidates.add(c[1]);
    for (const v of requestVars) {
      if (new RegExp(String.raw`(?<![\w$.])${escapeRe(v)}\b(?!\s*:(?!:))`).test(body)) candidates.add(v);
    }
    const leaked = [...candidates].find((name) =>
      !params.has(name) && !locals.has(name) && (requestVars.has(name) || declaredBefore(name)) &&
      !new RegExp(String.raw`\b${escapeRe(name)}\b`).test(keyParts));
    if (!leaked) continue;
    hits.push({
      ruleId: 28751, code: 'NEXTAI-01', severity: 'HIGH', category: 'Access Control', lineIdx,
      title: 'unstable_cache Callback Reads a Per-User Value Missing From the Cache Key',
      why: `The cached callback uses \`${leaked}\` from the surrounding request scope, but unstable_cache keys entries only by the callback's arguments, its source and keyParts. The first user's result is cached under a key that does not include \`${leaked}\`, so every later user (or tenant) receives that user's data until revalidation.`,
      fix: `Pass \`${leaked}\` as an argument of the cached function (unstable_cache(async (${leaked}) => ..., ['key'])) and call it with the value, or add it to keyParts ([\`orders\`, ${leaked}]). On Next.js 16 prefer a 'use cache' function, whose closed-over values become part of the key.`
    });
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* NEXTAI-02: whole database row passed as a prop to a Client Component                               */
/* ------------------------------------------------------------------------------------------------ */

const IS_CLIENT_MODULE = /^\s*['"]use client['"]/;

function resolveImport(fromPath: string, spec: string, clientModules: Set<string>): boolean {
  const strip = (p: string) => p.replace(/\.(?:[cm]?[jt]sx?)$/i, '').replace(/\/$/, '');
  const candidates: string[] = [];
  if (spec.startsWith('.')) {
    const parts = fromPath.split('/').slice(0, -1);
    for (const seg of spec.split('/')) {
      if (seg === '..') parts.pop();
      else if (seg !== '.' && seg) parts.push(seg);
    }
    candidates.push(parts.join('/'));
  } else if (/^[@~]\//.test(spec)) {
    const rest = spec.slice(2);
    candidates.push(rest, `src/${rest}`);
    // monorepo app: apps/web/... imports '@/components/x' relative to the app root
    const appRoot = fromPath.match(/^((?:apps|packages)\/[^/]+)\//);
    if (appRoot) candidates.push(`${appRoot[1]}/${rest}`, `${appRoot[1]}/src/${rest}`);
  } else {
    return false;
  }
  return candidates.some((c) => clientModules.has(strip(c)));
}

interface RowVar { name: string; model: string; source: string }

function wholeRowVars(content: string): RowVar[] {
  const out: RowVar[] = [];
  // Prisma: const user = await prisma.user.findUnique({ where }) without select / omit; Drizzle: db.query.users.findFirst() without columns
  for (const m of content.matchAll(/\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*await\s+(?:[\w$]+\.)?(?:prisma|db|client)\.(query\.)?([A-Za-z_$][\w$]*)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany)\s*\(/g)) {
    const open = (m.index ?? 0) + m[0].length - 1;
    const close = matchClose(content, open);
    const args = close === -1 ? '' : content.slice(open + 1, close);
    if (m[2] ? /\bcolumns\s*:/.test(args) : /\b(?:select|omit)\s*:/.test(args)) continue;
    out.push({ name: m[1], model: m[3], source: `${m[2] ? 'db.query.' : 'prisma.'}${m[3]}.${m[4]}()` });
  }
  // Supabase: const { data: profile } = await supabase.from('profiles').select('*') / .select()
  for (const m of content.matchAll(/\b(?:const|let)\s+\{\s*data\s*(?::\s*([A-Za-z_$][\w$]*))?[^}]*\}\s*=\s*await\s+[\w$.()]*?\.from\(\s*['"](\w+)['"]\s*\)\s*\.select\(\s*(?:['"]\s*\*\s*['"])?\s*\)/g)) {
    out.push({ name: m[1] || 'data', model: m[2], source: `.from('${m[2]}').select('*')` });
  }
  // Drizzle core: const [user] = await db.select().from(users)
  for (const m of content.matchAll(/\b(?:const|let)\s+(?:\[\s*([A-Za-z_$][\w$]*)\s*\]|([A-Za-z_$][\w$]*))\s*(?::[^=]+)?=\s*await\s+[\w$]+\s*\.select\(\s*\)\s*\.from\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    out.push({ name: m[1] || m[2], model: m[3], source: `db.select().from(${m[3]})` });
  }
  return out;
}

function sensitiveColumnsFor(model: string, ctx: RepoContext): string[] {
  const k = model.toLowerCase();
  return ctx.sensitiveColumnsByModel.get(k) || ctx.sensitiveColumnsByModel.get(`${k}s`) || ctx.sensitiveColumnsByModel.get(k.replace(/s$/, '')) || [];
}

function rowToClient(path: string, content: string, ctx: RepoContext, hits: Hit[]): void {
  if (!/\.[jt]sx$/i.test(path) || !ctx.clientComponentModules.size || !ctx.sensitiveColumnsByModel.size) return;
  if (IS_CLIENT_MODULE.test(content.replace(/^\s+/, ''))) return;
  const rows = wholeRowVars(content).map((r) => ({ ...r, cols: sensitiveColumnsFor(r.model, ctx) })).filter((r) => r.cols.length);
  if (!rows.length) return;
  const clientComponents = new Set<string>();
  for (const m of content.matchAll(/\bimport\s+(?!type\b)(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/g)) {
    if (!resolveImport(path, m[3], ctx.clientComponentModules)) continue;
    if (m[1]) clientComponents.add(m[1]);
    for (const part of (m[2] || '').split(',')) {
      const local = part.replace(/^\s*type\s+/, '').split(/\s+as\s+/).pop()?.trim();
      if (local && /^[A-Za-z_$][\w$]*$/.test(local)) clientComponents.add(local);
    }
  }
  if (!clientComponents.size) return;
  for (const row of rows) {
    const v = escapeRe(row.name);
    for (const p of content.matchAll(new RegExp(String.raw`[\w$-]+=\{\s*${v}\s*\}|\{\s*\.\.\.\s*${v}\s*\}`, 'g'))) {
      const at = p.index ?? 0;
      const preceding = content.slice(Math.max(0, at - 600), at);
      const tagAt = preceding.search(/<([A-Z][\w$.]*)\b(?![\s\S]*<[A-Za-z])/);
      if (tagAt === -1) continue;
      const between = preceding.slice(tagAt).replace(/=>/g, '');
      if (/>/.test(between.slice(1))) continue;
      const tag = (preceding.slice(tagAt).match(/^<([A-Z][\w$]*)/) || [])[1];
      if (!tag || !clientComponents.has(tag)) continue;
      hits.push({
        ruleId: 28752, code: 'NEXTAI-02', severity: 'HIGH', category: 'Data Exposure', lineIdx: lineOf(content, at),
        title: 'Whole Database Row With Secret Columns Passed to a Client Component',
        why: `\`${row.name}\` is a full ${row.model} record (${row.source} without a column selection) and is passed as a prop to <${tag}>, a 'use client' component. Every prop of a Client Component is serialized into the page's RSC payload, so ${row.cols.slice(0, 3).join(', ')} reach the browser even if the component never renders them.`,
        fix: `Select only the fields the component needs (prisma: select: { id: true, name: true }; Supabase: .select('id, name')) or map the row to a DTO before passing it, and add import 'server-only' to the data-access module. React's experimental_taintObjectReference can also block the raw object from crossing to the client.`
      });
      return;
    }
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* NEXTAI-03: destructive agent tool without human approval                                           */
/* ------------------------------------------------------------------------------------------------ */

const JS_AGENT_FRAMEWORK = /(?:from\s+|require\(\s*)['"](?:ai|@ai-sdk\/[\w-]+|@modelcontextprotocol\/sdk[\w/.-]*|@langchain\/[\w/-]+|langchain[\w/-]*|@openai\/agents[\w/-]*|@mastra\/core[\w/-]*|mcp-handler)['"]/;
const APPROVAL_FLOW = /needsApproval|requireApproval|requiresApproval|human[-_ ]?in[-_ ]?the[-_ ]?loop|humanInTheLoop|\binterrupt\s*\(|\bconfirm(?:ed|ation|ations)?\b|\bapprov(?:e|ed|al|als)\b/i;
const DESTRUCTIVE: Array<[RegExp, string]> = [
  [/\b(?:prisma|db|tx|trx|client|knex)\b(?:\.[\w$]+)*\.(?:delete|deleteMany|destroy)\s*\(/, 'deletes database records'],
  [/\.from\(\s*['"`][\w.]+['"`]\s*\)\s*\.delete\s*\(/, 'deletes database records'],
  [/['"`]\s*(?:DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|DROP\s+TABLE)\s+/i, 'deletes database records'],
  [/\bstripe\.(?:transfers|refunds|payouts|charges)\.create\s*\(/, 'moves money'],
  [/\bstripe\.(?:subscriptions\.(?:cancel|del)|customers\.del)\s*\(/, 'cancels billing'],
  [/\b(?:resend\.batch\.send|sgMail\.sendMultiple|\w+\.sendBulk\w*|\w+\.sendBatch\w*)\s*\(/, 'sends bulk email'],
];

function destructiveTools(content: string, hits: Hit[]): void {
  if (!JS_AGENT_FRAMEWORK.test(content) || APPROVAL_FLOW.test(content)) return;
  const starts = /\btool\s*\(\s*\{|\bnew\s+(?:DynamicStructuredTool|DynamicTool)\s*\(|\.(?:tool|registerTool)\s*\(|\btool\s*\(\s*async\b|\bcreateTool\s*\(\s*\{/g;
  const seen = new Set<number>();
  for (const m of content.matchAll(starts)) {
    const open = (m.index ?? 0) + m[0].search(/\(/);
    const close = matchClose(content, open);
    if (close === -1) continue;
    const block = content.slice(open, close + 1);
    if (/needsApproval/.test(block)) continue;
    // The handler must take model-chosen input
    const handler = block.match(/(?:execute|func|handler)\s*:\s*async\s*\(\s*([^)]*)\)|async\s+execute\s*\(\s*([^)]*)\)|async\s*\(\s*([^)]*)\)\s*(?::[^=]*)?=>/);
    if (!handler || !(handler[1] ?? handler[2] ?? handler[3] ?? '').trim()) continue;
    for (const [re, what] of DESTRUCTIVE) {
      const at = block.search(re);
      if (at === -1) continue;
      const lineIdx = lineOf(content, open + at + (block.slice(at).match(re)?.[0].search(/\S/) ?? 0));
      if (seen.has(lineIdx)) break;
      seen.add(lineIdx);
      hits.push({
        ruleId: 28753, code: 'NEXTAI-03', severity: 'MEDIUM', category: 'AI & LLM Security', lineIdx,
        title: 'Destructive Agent Tool Runs Without Human Approval',
        why: `This tool ${what} with arguments chosen by the model, and nothing in the file asks a person to confirm first. Prompt injection in a chat message, document or web page the agent reads can trigger it (OWASP LLM06 Excessive Agency).`,
        fix: 'Require approval before the side effect: set needsApproval: true on the AI SDK tool (or return a pending action the user confirms in the UI / a LangGraph interrupt()), scope the operation to the signed-in user, and cap amounts / batch sizes server-side.'
      });
      break;
    }
  }
}

/* ------------------------------------------------------------------------------------------------ */

export function evaluateNextAiV3Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context: RepoContext = emptyRepoContext()): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = (file.path || '').replace(/\\/g, '/');
  if (!/\.[cm]?[jt]sx?$/i.test(path) || /(?:^|\/)node_modules\//.test(path) || /\.d\.ts$/i.test(path)) return { findings, logs };
  const content = cleanContent.replace(/\r/g, '');
  const hits: Hit[] = [];

  cacheLeaks(content, hits);
  rowToClient(path, content, context, hits);
  destructiveTools(content, hits);

  const reportLines = content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `nextai${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (reportLines[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEXT/AI] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
