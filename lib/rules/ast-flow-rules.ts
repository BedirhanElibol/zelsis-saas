/**
 * AST-based JS/TS analysis with @babel/parser: route/auth/ownership flow and intra-file taint
 * (AST-01.., Rule IDs 29301-29399).
 *
 * The line rules see one line (or one file) at a time; these rules follow values through variables,
 * destructuring and same-file helper calls inside each request handler. A file that fails to parse is
 * skipped silently (the line rules still run on it).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { isParsablePath, parseSource } from '../scanner/ast/parse';
import { analyzeProgram, PUBLIC_FORM_MODEL, PUBLIC_READ_MODEL, type Ctx, type DbQuery, type SinkCode } from '../scanner/ast/flow';
import { within } from '../scanner/ast/walk';
import { middlewareAuthenticates, resolveImport, routePathOf } from '../scanner/ast/cross-file';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; line: number; why: string; fix: string }

/** Cheap pre-filter: only files that can contain a handler or a browser source are parsed. */
const WORTH_PARSING = /['"]use server['"]|\breq(?:uest)?\b|\bparams\b|searchParams|\bc\.req\b|Procedure\b|\bMutation\b|\blocation\.|useSearchParams|useParams|innerHTML|document\.write/;
const PUBLIC_MUTATION_PATH = /webhook|\/cron\/|(?:^|\/)(?:auth|login|log-in|signin|sign-in|signup|sign-up|register|logout|password|reset|forgot|verify|invite|invitations?|callback|oauth|unsubscribe|subscribe|newsletter|waitlist|contact|feedback|public|track|analytics|og|health)(?:\/|\.|\b)/i;
const PUBLIC_ACTION_NAME = /^(?:sign|log)_?(?:in|out|up)|register|reset|forgot|verify|subscribe|contact|feedback|waitlist|newsletter|track|increment|view|vote|like/i;

export function evaluateAstFlowRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const content = file.content || '';
  if (!isParsablePath(file.path) || !WORTH_PARSING.test(content)) return { findings, logs };
  const program = parseSource(file.path, content);
  if (!program) return { findings, logs };

  let result;
  try {
    const cross = context?.crossFileAuth;
    result = analyzeProgram(program, file.path, content, cross && {
      isAuthHelper: (src, name) => resolveImport(file.path, src).some((k) => !!cross.authHelpers.get(k)?.has(name)),
      middlewareAuthed: middlewareAuthenticates(cross.middleware, routePathOf(file.path)),
    });
  } catch {
    return { findings, logs };
  }
  const hits: Hit[] = [];
  const path = file.path.replace(/\\/g, '/');

  for (const h of result.handlers) {
    const spec = h.spec!;
    // AST-01: signed-in caller, record picked by a request id, no owner constraint or owner check
    if (h.authed && !h.adminCheck) {
      for (const q of h.queries) {
        if (!isIdorQuery(q, h)) continue;
        hits.push({
          ruleId: 29301, code: 'AST-01', severity: 'HIGH', category: 'Authentication & Access Control', line: q.line,
          title: 'IDOR: Record Accessed by Request ID Without an Ownership Check',
          why: `${handlerLabel(spec.kind, spec.name)} authenticates the caller, then ${q.write ? 'modifies' : 'loads'} ${q.model || 'a record'} (${q.lib} ${q.op}) by an id taken from the request with no owner/tenant filter and no later check that the row belongs to the user. Any signed-in user can ${q.write ? 'change or delete' : 'read'} other users' records by changing the id.`,
          fix: `Scope the query to the caller (e.g. where: { id, userId: session.user.id }, .eq('user_id', user.id), and(eq(t.id, id), eq(t.userId, user.id))) or compare the row's owner to the session user before using it.`,
        });
      }
    }
    // AST-09: unauthenticated endpoint writes to GitHub (PR, branch, file) for a repo or record the caller picks
    if (!h.authed && !h.guarded && !spec.wrapped && h.externalWrites?.length && isMutatingEntry(h, path, cleanContent)) {
      const callerPicked = h.queries.some((q) => q.idTainted);
      const w = h.externalWrites.find((x) => x.tainted) ?? (callerPicked ? h.externalWrites[0] : undefined);
      if (w) {
        hits.push({
          ruleId: 29309, code: 'AST-09', severity: 'HIGH', category: 'Authentication & Access Control', line: w.line,
          title: 'Unauthenticated Endpoint Writes to GitHub for a Caller-Chosen Repository',
          why: `${handlerLabel(spec.kind, spec.name)} is reachable by anyone (${spec.kind === 'action' ? 'Server Actions are public POST endpoints' : 'no session, token or signature check on its path'}) and calls ${w.api} ${w.tainted ? 'with request-controlled arguments' : 'for a record selected by request input'}. With an app or installation token behind the client, any caller can push branches, files or pull requests to repositories that belong to other users.`,
          fix: 'Authenticate the caller inside the handler (auth(), getServerSession, supabase.auth.getUser(token)) and load the repository only from a record the caller owns (where: { id, userId: user.id }).',
        });
      }
    }
    // AST-02: state-changing endpoint, no authentication anywhere on its path, record chosen by the caller
    if (!h.authed && !h.guarded && !spec.wrapped && isMutatingEntry(h, path, cleanContent)) {
      const q = h.queries.find((x) => x.write && x.idTainted && !x.counterOnly && !(x.lib === 'supabase' && x.client !== 'admin') && !PUBLIC_FORM_MODEL.test(x.model));
      if (q) {
        hits.push({
          ruleId: 29302, code: 'AST-02', severity: 'HIGH', category: 'Authentication & Access Control', line: q.line,
          title: 'Unauthenticated Mutation: Endpoint Modifies a Caller-Chosen Record',
          why: `${handlerLabel(spec.kind, spec.name)} is reachable by anyone (${spec.kind === 'action' ? 'Server Actions are public POST endpoints' : 'no session, token or signature check on its path'}) and runs ${q.lib} ${q.op} on ${q.model || 'a record'} selected by request input, so an anonymous caller can modify or delete arbitrary records.`,
          fix: 'Authenticate inside the handler/action itself (auth(), getServerSession, supabase.auth.getUser(), requireUser()) and scope the write to the caller; middleware alone is not enough for Server Actions and route handlers.',
        });
      }
    }
  }

  for (const s of result.sinks) {
    const meta = sinkMeta(s.code, s.ctx);
    if (!meta) continue;
    hits.push({ ...meta, line: s.line, why: `${s.detail}. ${meta.why}` });
  }

  const raw = content.split('\n');
  const ts = new Date().toLocaleTimeString();
  const seen = new Set<string>();
  for (const h of hits) {
    const key = `${h.ruleId}:${h.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id: `ast${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${h.line}`,
      snippet: (raw[h.line - 1] ?? lines[h.line - 1] ?? '').trim(),
      reproductionSteps: [`Traced request input through ${file.path}:${h.line} (AST data flow).`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${h.line})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false,
    });
    logs.push(`[${ts}] [AST FLOW] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${h.line}`);
  }
  return { findings, logs };
}

function isIdorQuery(q: DbQuery, h: Ctx): boolean {
  if (!q.idTainted || q.owned) return false;
  // The user's own Supabase client: RLS enforces ownership
  if (q.lib === 'supabase' && q.client !== 'admin') return false;
  const model = q.model.split('.').pop() || '';
  if (!q.write && PUBLIC_READ_MODEL.test(model)) return false;
  // Any comparison / access-check call mixing the user with the request id or the fetched row counts as a check
  return !h.mixes.some((m) => !within(m, q.node));
}

function isMutatingEntry(h: Ctx, path: string, cleanContent: string): boolean {
  const spec = h.spec!;
  const mutating = spec.method === 'POST' || spec.method === 'PUT' || spec.method === 'PATCH' || spec.method === 'DELETE' || spec.method === 'ALL';
  if (!mutating || PUBLIC_MUTATION_PATH.test(path)) return false;
  switch (spec.kind) {
    case 'route': return true;
    case 'action': return !PUBLIC_ACTION_NAME.test(spec.name);
    case 'express': case 'hono': return !!spec.standaloneApp && !spec.middlewareAuth;
    case 'trpc': return !!spec.publicProc;
    case 'graphql': return !!spec.publicProc && !/shield|permissions|directive|@auth|authChecker|requireAuth|isAuthenticated|guard/i.test(cleanContent);
    default: return false;
  }
}

function handlerLabel(kind: string, name: string): string {
  switch (kind) {
    case 'route': return `The ${name} route handler`;
    case 'action': return `Server Action ${name}()`;
    case 'page': return 'This page';
    case 'trpc': return `This ${name} tRPC procedure`;
    case 'graphql': return `Resolver ${name}`;
    default: return `Route ${name}`.trim();
  }
}

function sinkMeta(code: SinkCode, ctx: Ctx): Omit<Hit, 'line'> | null {
  switch (code) {
    case 'AST-03': return {
      ruleId: 29303, code, severity: 'CRITICAL', category: 'Injection',
      title: 'SQL Injection: Request Input Reaches a Raw Query Through Variables (CWE-89)',
      why: 'The query text is assembled from request input (possibly via intermediate variables or a helper), so a caller can change the SQL that runs.',
      fix: 'Use parameterized queries (tagged sql`` / $queryRaw template, pool.query(text, [values]), knex bindings) and allow-list identifiers such as sort columns.',
    };
    case 'AST-04': return {
      ruleId: 29304, code, severity: 'CRITICAL', category: 'Injection',
      title: 'Command Injection: Request Input Reaches a Shell Command Through Variables (CWE-78)',
      why: 'A shell command line is built from request input, so metacharacters (; | $( )) run arbitrary commands on the server.',
      fix: 'Call execFile/spawn with a fixed binary and an argument array (no shell), and validate the input against an allow-list.',
    };
    case 'AST-05': return ctx.pathGuard ? null : {
      ruleId: 29305, code, severity: 'HIGH', category: 'Injection',
      title: 'Path Traversal: Request Input Reaches a File System Path (CWE-22)',
      why: 'A file path is built from request input without a containment check, so ../ sequences or absolute paths read or overwrite files outside the intended directory.',
      fix: 'Reduce the input to path.basename() or an allow-listed id, resolve it, and check resolved.startsWith(baseDir + path.sep) before touching the file system.',
    };
    case 'AST-06': return ctx.urlGuard ? null : {
      ruleId: 29306, code, severity: 'HIGH', category: 'Network & SSRF',
      title: 'SSRF: Request Input Chooses the Host of a Server-Side Request (CWE-918)',
      why: 'The server fetches a URL whose scheme and host come from the request, so callers can reach internal services or cloud metadata (169.254.169.254).',
      fix: 'Allow-list destination hosts, resolve DNS and reject private/link-local ranges, or keep the host fixed and pass user input only as an encoded path/query part.',
    };
    case 'AST-07': return ctx.redirectGuard ? null : {
      ruleId: 29307, code, severity: 'MEDIUM', category: 'Authentication & Access Control',
      title: 'Open Redirect: Request Input Chooses the Redirect Target (CWE-601)',
      why: 'The redirect destination comes from request/URL input with no same-origin check, enabling phishing redirects (and javascript: URLs for client-side navigation).',
      fix: 'Only redirect to relative paths (value.startsWith("/") && !value.startsWith("//")) or to an allow-list of hosts; fall back to a fixed page.',
    };
    case 'AST-08': return {
      ruleId: 29308, code, severity: 'HIGH', category: 'Injection',
      title: 'XSS: Request/URL Input Rendered as HTML (CWE-79)',
      why: 'Input from the request, query string or location is inserted as raw HTML, so a crafted link runs script in the victim\'s session.',
      fix: 'Render the value as text, or sanitize it with DOMPurify / sanitize-html before using dangerouslySetInnerHTML / innerHTML.',
    };
    default: return null;
  }
}
