/**
 * Scope-aware data-flow pass over one parsed JS/TS file.
 *
 * - Finds request handlers (Next route handlers, Server Actions, pages, Express/Hono/Fastify routes and
 *   controllers, tRPC procedures, GraphQL resolvers) and seeds their request input as tainted.
 * - Propagates taint through assignments, destructuring, template literals, property access, a small set of
 *   string/number helpers and calls to functions defined in the same file (bounded depth).
 * - Records, per handler: authentication, DB queries keyed by a tainted id and whether they are owner-scoped,
 *   and sink calls reached by tainted strings (SQL, shell, fs, outbound URL, redirect, HTML).
 *
 * Taint levels: 0 = clean, 1 = user-controlled but numeric (cannot inject; still picks a record), 2 = string.
 */
import {
  type AstNode, children, isFunction, isMember, isCall, unwrap, unwrapAwait, propName, keyName, calleeName,
  memberPath, lineOf, stringValue, walk,
} from './walk';

export type HandlerKind = 'route' | 'action' | 'express' | 'hono' | 'trpc' | 'graphql' | 'page' | 'controller';

export interface HandlerSpec {
  kind: HandlerKind;
  name: string;
  /** HTTP method when known (route export name, app.post, tRPC mutation -> POST). */
  method?: string;
  /** Exported through a wrapper call (withAuth(handler), authAction(...)): auth assumed to live there. */
  wrapped?: boolean;
  /** Route has middleware before the handler (Express/Hono/Fastify) or a protected tRPC procedure. */
  middlewareAuth?: boolean;
  /** tRPC publicProcedure / GraphQL Mutation: may be reached without a session. */
  publicProc?: boolean;
  /** tRPC adminProcedure and similar: admins may read any record. */
  adminProc?: boolean;
  /** Express/Hono route in a file that creates the app itself with no auth-looking app.use(). */
  standaloneApp?: boolean;
}

export type QueryLib = 'prisma' | 'drizzle' | 'supabase' | 'mongoose' | 'sequelize';

export interface DbQuery {
  node: AstNode;
  line: number;
  lib: QueryLib;
  model: string;
  op: string;
  write: boolean;
  /** Record selected by a request-controlled id. */
  idTainted: boolean;
  /** The filter also constrains by owner / tenant / the signed-in user. */
  owned: boolean;
  client?: 'rls' | 'admin' | 'unknown';
  /** Write whose data only increments counters (views, likes). */
  counterOnly?: boolean;
}

export type SinkCode = 'AST-03' | 'AST-04' | 'AST-05' | 'AST-06' | 'AST-07' | 'AST-08';

export interface SinkHit { code: SinkCode; line: number; detail: string; ctx: Ctx }

export interface Ctx {
  spec: HandlerSpec | null;
  line: number;
  authed: boolean;
  guarded: boolean;
  adminCheck: boolean;
  pathGuard: boolean;
  urlGuard: boolean;
  redirectGuard: boolean;
  queries: DbQuery[];
  mixes: AstNode[];
}

export interface FlowResult { handlers: Ctx[]; sinks: SinkHit[]; parsedFunctions: number }

interface Binding {
  t: number;
  /** Taint of the start of the string (host / scheme control) when it differs from t. */
  h?: number;
  user?: boolean;
  url?: boolean;
  ctx?: boolean;
  req?: 'next' | 'express' | 'hono';
  authCtx?: boolean;
  trpcOpts?: boolean;
  client?: 'rls' | 'admin';
  row?: boolean;
  fn?: AstNode;
}

class Scope {
  vars = new Map<string, Binding>();
  constructor(public parent?: Scope) {}
  lookup(name: string): Binding | undefined {
    return this.vars.get(name) ?? this.parent?.lookup(name);
  }
  declare(name: string, b: Binding) { this.vars.set(name, b); }
  /** Updates the nearest scope that declares name; returns false when none does. */
  private update(name: string, b: Binding): boolean {
    const prev = this.vars.get(name);
    // Taint follows the latest assignment; "holds the signed-in user" survives branch reassignments
    if (prev) { this.vars.set(name, prev.user && !b.user ? { ...b, user: true } : b); return true; }
    return this.parent ? this.parent.update(name, b) : false;
  }
  assign(name: string, b: Binding) {
    if (!this.update(name, b)) this.vars.set(name, b);
  }
}

interface Frame { ret: number; retUser: boolean }

const CLEAN: Binding = { t: 0 };
const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const ROUTE_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'del', 'all']);
const COMPARE_OPS = new Set(['===', '!==', '==', '!=']);

export const AUTH_FN = /^(?:auth|getServerSession|unstable_getServerSession|getServerAuthSession|getSession|getClaims|currentUser|getAuth|protect|authenticate|isAuthenticated|withAuth|getKindeServerSession|validateRequest|validateSession|verifySession|getToken|getIronSession|jwtVerify|requireAuth\w*|ensureAuth\w*|assertAuth\w*|checkAuth\w*|requireLogin|ensureLoggedIn|requireOrg\w*|(?:get|require|ensure|verify|validate|check|assert|load|fetch|read|use)\w*(?:User|Session|Auth|Viewer|Member|Account|Claims|Identity)(?:OrThrow|OrRedirect|OrNull|OrFail|Id|FromRequest|FromSession|FromCookies?|FromHeaders?)?)$/;
/** Request values that are secrets (one-time tokens, codes): a lookup by them is not an IDOR. */
const SECRET_VALUE = /token|secret|code|nonce|otp|hash|signature|key|challenge|csrf/i;
const LOGGING_CALL = /^(?:log|info|debug|warn|error|trace|track|capture\w*|identify|emit|json|stringify|send|set|push|add|fireAndForget)$/;
const GUARD_FN = /^(?:constructEvent|constructEventAsync|verifyWebhook\w*|verifySignature|validateSignature|checkSignature|isValidSignature|verify|timingSafeEqual|createHmac|verifyRequest\w*|verifyKey|verifyApiKey|validateApiKey|checkApiKey|isValidApiKey|requireApiKey|verifyCronSecret|verifyToken|isAuthorized|authorize\w*)$/;
const ADMIN_FN = /admin|role|permission|isStaff|superuser/i;
const MIX_FN = /auth|owner|access|permission|member|^can[A-Z]?|assert|check|verify|ensure|guard|policy|require|belong|allow|authori|isOwn/i;
const ARRAY_MEMBERSHIP = new Set(['includes', 'some', 'find', 'every', 'has', 'indexOf', 'findIndex']);
const ADMIN_PROP = /^(?:role|roles|isAdmin|admin|isSuperAdmin|superAdmin|isSuperuser|permissions|isStaff|isOwner|platformRole|userRole)$/;
const USER_PROP = /^(?:user|auth|session|userId|currentUser|account|viewer)$/;

const OWNER_KEY = /^(?:user|owner|org|organization|team|tenant|workspace|account|author|creator|member|members|company|customer|profile|seller|buyer|client|users|owners|collaborators|participants|createdBy|created_by|uploadedBy|uploaded_by|createdById|ownerUserId)(?:_?[iI]d|_?[iI]ds|_uuid|Uuid)?$/;
const IDISH_KEY = /^(?:id|_id|uuid|[a-z][a-zA-Z0-9]*Id|[a-z][a-z0-9_]*_id)$/;
export const PUBLIC_READ_MODEL = /^(?:posts?|articles?|products?|categor(?:y|ies)|tags?|pages?|blogs?|blogPosts?|courses?|lessons?|events?|listings?|plans?|prices?|templates?|comments?|reviews?|authors?|faqs?|changelogs?|releases?|countr(?:y|ies)|cit(?:y|ies)|languages?|currenc(?:y|ies)|features?|public\w*|recipes?|videos?|episodes?|podcasts?|jobs?|stores?|menus?|menuItems?|collections?|tutorials?|guides?|docs?|news|announcements?|polls?|questions?|answers?|threads?|topics?|forums?|games?|movies?|songs?|albums?|books?|shops?|brands?|locations?|venues?|images?|media|assets?|icons?|emojis?|stickers?|themes?|fonts?|plugins?|extensions?|integrations?|apps?|models?|voices?|prompts?|showcases?|testimonials?)$/i;
export const PUBLIC_FORM_MODEL = /waitlist|newsletter|contact|feedback|subscriber|subscription_request|lead|inquir|signup|sign_up|enquir|demo_request|interest/i;

const PRISMA_READ = new Set(['findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow']);
const PRISMA_WRITE = new Set(['update', 'delete', 'upsert', 'updateMany', 'deleteMany']);
const MONGOOSE_OPS: Record<string, boolean> = {
  findById: false, findByIdAndUpdate: true, findByIdAndDelete: true, findByIdAndRemove: true,
  findOne: false, findOneAndUpdate: true, findOneAndDelete: true, findOneAndRemove: true,
  deleteOne: true, updateOne: true,
};
const SEQUELIZE_OPS: Record<string, boolean> = { findByPk: false, destroy: true };
const DB_ROOT = /^(?:prisma|db|tx|trx|client|prismaClient|database|dbClient|orm)$/i;
const PROPAGATE_METHODS = new Set([
  'trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase', 'toString',
  'slice', 'substring', 'substr', 'replace', 'replaceAll', 'split', 'join', 'concat', 'get', 'getAll', 'at', 'padStart',
  'padEnd', 'normalize', 'valueOf', 'flat', 'filter', 'find', 'pop', 'shift', 'values', 'entries', 'keys', 'text',
]);
const PARSE_METHODS = new Set(['parse', 'parseAsync', 'safeParse', 'safeParseAsync', 'validate', 'validateSync', 'cast']);
const SANITIZER = /sanitiz|escape|purify|basename|encode|clean|strip|safe|xss|filterXSS|slugify|quote|validat/i;
const NUMERIC_FN = new Set(['Number', 'parseInt', 'parseFloat', 'BigInt', 'Math']);
const FS_MODULES = /^(?:node:)?fs(?:\/promises)?$|^fs-extra$|^graceful-fs$/;
const FS_PATH_FNS = new Set([
  'readFile', 'readFileSync', 'createReadStream', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'createWriteStream', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'readdir', 'readdirSync',
  'copyFile', 'copyFileSync', 'rename', 'renameSync', 'outputFile', 'outputFileSync', 'remove', 'removeSync',
  'readJson', 'readJSON', 'readJsonSync', 'writeJson', 'writeJSON', 'open', 'openSync',
]);
const SQL_RAW_METHODS = new Set(['whereRaw', 'orWhereRaw', 'andWhereRaw', 'orderByRaw', 'havingRaw', 'joinRaw', 'groupByRaw', 'selectRaw', 'fromRaw']);
const SQL_QUERY_OBJ = /^(?:pool|client|db|conn|connection|pg|mysql|database|sequelize|knex|trx|tx|sql|pgClient|dbClient|pgPool|mysqlPool|connectionPool|postgres)$/i;
const HTTP_CLIENT_FNS = new Set(['fetch', 'axios', 'got', 'ky', 'needle', 'superagent', 'request', 'ofetch', '$fetch', 'undiciFetch', 'nodeFetch']);
const HTTP_CLIENT_OBJ = /^(?:axios|got|ky|needle|superagent|http|https|undici|request|ofetch|\$fetch|apiClient|httpClient)$/;
const HTTP_CLIENT_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'fetch']);
const RESPONSE_OBJ = /^(?:res|reply|response|c|ctx|resp)$/;

/** Walks a parsed Program and returns handler facts and taint sink hits. */
/** Facts from other files: imported helpers that authenticate, and Next.js middleware covering this route. */
export interface CrossFileHints {
  isAuthHelper(importSource: string, name: string): boolean;
  middlewareAuthed: boolean;
}

export function analyzeProgram(program: AstNode, path: string, source: string, crossFile?: CrossFileHints): FlowResult {
  const normPath = path.replace(/\\/g, '/');
  const imports = new Map<string, string>();
  const localFns = new Map<string, AstNode>();
  const moduleScope = new Scope();
  const handlers: Ctx[] = [];
  const sinks: SinkHit[] = [];
  const callCache = new Map<AstNode, { t: number; user: boolean }>();
  const queryNodes = new WeakSet<AstNode>();
  const active = new Set<AstNode>();
  let budget = 600;
  let parsedFunctions = 0;
  const usesMongoose = /mongoose|\bmodel\s*\(|Schema\s*\(/.test(source);
  const usesSequelize = /sequelize/i.test(source);
  const usesDrizzle = /drizzle-orm/.test(source);

  collectModuleFacts(program, imports, localFns);
  const specs = findHandlers(program, normPath, imports);

  const newCtx = (spec: HandlerSpec | null, line: number): Ctx => ({
    spec, line, authed: false, guarded: false, adminCheck: false, pathGuard: false, urlGuard: false, redirectGuard: false, queries: [], mixes: [],
  });
  const moduleCtx = newCtx(null, 1);

  // ---------- binding / taint evaluation ----------

  const importedFrom = (name: string): string | undefined => imports.get(name);

  function reqKindOf(e: AstNode, scope: Scope): Binding['req'] | undefined {
    const u = unwrap(e);
    return u.type === 'Identifier' ? scope.lookup(u.name)?.req : undefined;
  }

  function isReqUrlObj(e: AstNode, scope: Scope): boolean {
    const u = unwrapAwait(e);
    if (u.type === 'Identifier') return !!scope.lookup(u.name)?.url;
    if (isMember(u) && propName(u) === 'nextUrl' && reqKindOf(u.object, scope) === 'next') return true;
    if (u.type === 'NewExpression' && u.callee?.type === 'Identifier' && u.callee.name === 'URL' && u.arguments[0]) {
      const a = unwrap(u.arguments[0]);
      return isMember(a) && propName(a) === 'url' && !!reqKindOf(a.object, scope);
    }
    return false;
  }

  /** Request-input member reads: req.body, params, searchParams of the request URL, location.hash, ... */
  function memberSource(e: AstNode, scope: Scope): number | null {
    const obj = unwrap(e.object);
    const prop = propName(e);
    if (!prop) return null;
    const rk = reqKindOf(obj, scope);
    if (rk === 'express' && (prop === 'params' || prop === 'query' || prop === 'body')) return 2;
    if (obj.type === 'Identifier') {
      const b = scope.lookup(obj.name);
      if (b?.ctx && (prop === 'params' || prop === 'searchParams')) return 2;
      if (b?.trpcOpts && prop === 'input') return 2;
    }
    if (prop === 'searchParams' && isReqUrlObj(obj, scope)) return 2;
    const mp = memberPath(e);
    if (mp) {
      const j = mp.join('.');
      if (/^(?:window\.|document\.)?location\.(?:search|hash|href)$/.test(j) || j === 'document.referrer' || j === 'document.URL' || j === 'window.name') return 2;
    }
    return null;
  }

  function taintOf(e: AstNode | null | undefined, scope: Scope, depth = 0): number {
    if (!e || depth > 40) return 0;
    const u = unwrap(e);
    switch (u.type) {
      case 'Identifier': return scope.lookup(u.name)?.t ?? 0;
      case 'TemplateLiteral': return Math.max(0, ...u.expressions.map((x: AstNode) => taintOf(x, scope, depth + 1)));
      case 'BinaryExpression': {
        if (u.operator === '+') return Math.max(taintOf(u.left, scope, depth + 1), taintOf(u.right, scope, depth + 1));
        if (['-', '*', '/', '%', '**', '|', '&', '^', '<<', '>>', '>>>'].includes(u.operator)) return Math.min(1, Math.max(taintOf(u.left, scope, depth + 1), taintOf(u.right, scope, depth + 1)));
        return 0;
      }
      case 'LogicalExpression': return Math.max(taintOf(u.left, scope, depth + 1), taintOf(u.right, scope, depth + 1));
      case 'ConditionalExpression':
        // ['jpg', 'png'].includes(x) ? x : 'jpg' only ever yields an allow-listed value
        if (isAllowListTest(u.test)) return taintOf(u.alternate, scope, depth + 1);
        return Math.max(taintOf(u.consequent, scope, depth + 1), taintOf(u.alternate, scope, depth + 1));
      case 'AwaitExpression': return taintOf(u.argument, scope, depth + 1);
      case 'SequenceExpression': return taintOf(u.expressions[u.expressions.length - 1], scope, depth + 1);
      case 'AssignmentExpression': return taintOf(u.right, scope, depth + 1);
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const src = memberSource(u, scope);
        if (src !== null) return src;
        if (isReqUrlObj(u.object, scope)) return 0;
        const objT = taintOf(u.object, scope, depth + 1);
        if (objT > 0 && propName(u) === 'length') return 1;
        return objT;
      }
      case 'CallExpression':
      case 'OptionalCallExpression': return callTaint(u, scope, depth);
      case 'NewExpression': {
        const n = u.callee?.type === 'Identifier' ? u.callee.name : '';
        if (n === 'URL' || n === 'URLSearchParams' || n === 'String') return taintOf(u.arguments[0], scope, depth + 1);
        return 0;
      }
      case 'ObjectExpression': {
        let t = 0;
        for (const p of u.properties) {
          if (p.type === 'SpreadElement') t = Math.max(t, taintOf(p.argument, scope, depth + 1));
          else if (p.type === 'ObjectProperty') t = Math.max(t, taintOf(p.value, scope, depth + 1));
        }
        return t;
      }
      case 'ArrayExpression': return Math.max(0, ...u.elements.filter(Boolean).map((x: AstNode) => taintOf(x.type === 'SpreadElement' ? x.argument : x, scope, depth + 1)));
      case 'SpreadElement': return taintOf(u.argument, scope, depth + 1);
      default: return 0;
    }
  }

  function callTaint(call: AstNode, scope: Scope, depth: number): number {
    const cached = callCache.get(call);
    if (cached) return cached.t;
    const callee = unwrap(call.callee);
    const args: AstNode[] = call.arguments || [];
    const argT = (i: number) => taintOf(args[i], scope, depth + 1);
    if (callee.type === 'Identifier') {
      const n = callee.name;
      if (n === 'useSearchParams' || n === 'useParams') return 2;
      if (n === 'String' || n === 'decodeURIComponent' || n === 'decodeURI' || n === 'unescape' || n === 'structuredClone') return argT(0);
      if (NUMERIC_FN.has(n)) return Math.min(1, argT(0));
      if (n === 'Boolean') return 0;
      if (SANITIZER.test(n)) return 0;
      return 0;
    }
    if (isMember(callee)) {
      const m = propName(callee);
      const obj = unwrap(callee.object);
      if (!m) return 0;
      const rk = reqKindOf(obj, scope);
      if (rk === 'next' && (m === 'json' || m === 'formData' || m === 'text')) return 2;
      if (rk === 'express' && m === 'param') return 2;
      if (isMember(obj) && propName(obj) === 'req' && reqKindOf(obj.object, scope) === 'hono'
        && ['param', 'query', 'queries', 'json', 'parseBody', 'formData', 'valid', 'text'].includes(m)) return 2;
      const objName = obj.type === 'Identifier' ? obj.name : null;
      if (objName === 'JSON' && m === 'parse') return argT(0);
      if (objName === 'Object' && (m === 'fromEntries' || m === 'assign' || m === 'values' || m === 'entries')) return Math.max(0, ...args.map((_, i) => argT(i)));
      if (objName === 'Math') return Math.min(1, Math.max(0, ...args.map((_, i) => argT(i))));
      if (objName === 'Array' && m === 'from') return argT(0);
      if (objName && (objName === 'path' || /^(?:node:)?path$/.test(importedFrom(objName) || ''))) {
        if (m === 'join' || m === 'resolve' || m === 'normalize' || m === 'format' || m === 'posix' || m === 'relative') return Math.max(0, ...args.map((_, i) => argT(i)));
        return 0;
      }
      if (PARSE_METHODS.has(m) && objName !== 'JSON') return Math.max(0, ...args.map((_, i) => argT(i)));
      if (SANITIZER.test(m)) return 0;
      const objT = taintOf(obj, scope, depth + 1);
      if (objT > 0 && PROPAGATE_METHODS.has(m)) return objT;
      if (m === 'concat') return Math.max(objT, ...args.map((_, i) => argT(i)));
      return 0;
    }
    return 0;
  }

  /** Taint of the start of a URL / path string: a fixed `https://host/` or `/` prefix pins the destination. */
  function hostTaint(e: AstNode | null | undefined, scope: Scope, depth = 0): number {
    if (!e || depth > 20) return 0;
    const u = unwrap(e);
    const pinned = (s: string) => /^[a-z][a-z0-9+.-]*:\/\/[^/?#\s]+[/?#]/i.test(s) || /^\/(?![/\\])/.test(s);
    if (u.type === 'TemplateLiteral') {
      const q0 = u.quasis[0]?.value?.cooked ?? '';
      if (pinned(q0)) return 0;
      if (q0 === '' && u.expressions.length) return hostTaint(u.expressions[0], scope, depth + 1);
      return 0;
    }
    if (u.type === 'BinaryExpression' && u.operator === '+') {
      let left = unwrap(u.left);
      while (left.type === 'BinaryExpression' && left.operator === '+') left = unwrap(left.left);
      const s = stringValue(left);
      if (s !== null) return pinned(s) ? 0 : (s === '' ? taintOf(u.right, scope) : 0);
      if (left.type === 'TemplateLiteral') return hostTaint(left, scope, depth + 1);
      return hostTaint(left, scope, depth + 1);
    }
    if (u.type === 'Identifier') {
      const b = scope.lookup(u.name);
      return b ? (b.h ?? b.t) : 0;
    }
    if (u.type === 'NewExpression' && u.callee?.type === 'Identifier' && u.callee.name === 'URL') return hostTaint(u.arguments[0], scope, depth + 1);
    if (u.type === 'LogicalExpression') return Math.max(hostTaint(u.left, scope, depth + 1), hostTaint(u.right, scope, depth + 1));
    if (u.type === 'ConditionalExpression') return Math.max(hostTaint(u.consequent, scope, depth + 1), hostTaint(u.alternate, scope, depth + 1));
    if (u.type === 'AwaitExpression') return hostTaint(u.argument, scope, depth + 1);
    if (isMember(u) && (propName(u) === 'href' || propName(u) === 'toString')) return hostTaint(u.object, scope, depth + 1);
    if (isCall(u) && isMember(u.callee) && propName(u.callee) === 'toString') return hostTaint(u.callee.object, scope, depth + 1);
    return taintOf(u, scope);
  }

  function isAuthCall(call: AstNode, scope: Scope): boolean {
    const name = calleeName(call);
    if (!name) return false;
    const callee = unwrap(call.callee);
    const objPath = isMember(callee) ? memberPath(callee.object) : null;
    let hit = AUTH_FN.test(name);
    if (!hit && crossFile && callee.type === 'Identifier') {
      const src = importedFrom(callee.name);
      if (src && crossFile.isAuthHelper(src, callee.name)) hit = true;
    }
    if (!hit && name === 'verify' && objPath && /^(?:jwt|jsonwebtoken|jose|JWT)$/.test(objPath[objPath.length - 1])) hit = true;
    if (!hit && objPath && objPath.includes('auth') && /^(?:getUser|getSession|getClaims|api)$/.test(name)) hit = true;
    if (!hit) return false;
    // getUser(params.id) is a lookup, not authentication
    return !(call.arguments || []).some((a: AstNode) => taintOf(a, scope) > 0 && !reqKindOf(a, scope));
  }

  function isUserExpr(e: AstNode | null | undefined, scope: Scope, depth = 0): boolean {
    if (!e || depth > 20) return false;
    const u = unwrap(e);
    switch (u.type) {
      case 'Identifier': return !!scope.lookup(u.name)?.user;
      case 'AwaitExpression': return isUserExpr(u.argument, scope, depth + 1);
      case 'LogicalExpression': return isUserExpr(u.left, scope, depth + 1) || isUserExpr(u.right, scope, depth + 1);
      case 'ConditionalExpression': return isUserExpr(u.consequent, scope, depth + 1) || isUserExpr(u.alternate, scope, depth + 1);
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const obj = unwrap(u.object);
        const prop = propName(u) || '';
        const rk = reqKindOf(obj, scope);
        if ((rk === 'express' || rk === 'next') && USER_PROP.test(prop)) return true;
        if (obj.type === 'Identifier' && scope.lookup(obj.name)?.authCtx && USER_PROP.test(prop)) return true;
        return isUserExpr(obj, scope, depth + 1);
      }
      case 'CallExpression':
      case 'OptionalCallExpression': {
        if (callCache.get(u)?.user) return true;
        if (isAuthCall(u, scope)) return true;
        const callee = unwrap(u.callee);
        if (isMember(callee)) {
          const obj = unwrap(callee.object);
          const m = propName(callee);
          if (m === 'get' && reqKindOf(obj, scope) === 'hono') {
            const k = stringValue(u.arguments[0]);
            return !!k && /user|jwt|session|auth|claims/i.test(k);
          }
          return isUserExpr(obj, scope, depth + 1);
        }
        return false;
      }
      default: return false;
    }
  }

  function clientKind(e: AstNode, scope: Scope): 'rls' | 'admin' | undefined {
    const u = unwrapAwait(e);
    if (u.type === 'Identifier') {
      const b = scope.lookup(u.name);
      if (b?.client) return b.client;
      if (/admin|service/i.test(u.name)) return 'admin';
      const src = importedFrom(u.name);
      if (src && /admin|service/i.test(src)) return 'admin';
      return undefined;
    }
    if (isCall(u)) {
      const name = calleeName(u) || '';
      if (!/^create\w*(?:Client|Supabase\w*)$|^get\w*Supabase\w*$|^supabase\w*$/i.test(name)) return undefined;
      if (/admin|service/i.test(name)) return 'admin';
      const callee = unwrap(u.callee);
      const src = callee.type === 'Identifier' ? importedFrom(callee.name) : undefined;
      if (src && /admin|service/i.test(src)) return 'admin';
      let service = false;
      for (const a of u.arguments || []) walk(a, (n) => {
        if (isMember(n) && /SERVICE_ROLE|SERVICE_KEY|SECRET_KEY|SUPABASE_SECRET/i.test(propName(n) || '')) service = true;
        if (n.type === 'StringLiteral' && /service_role/i.test(n.value)) service = true;
      });
      if (service) return 'admin';
      // @supabase/supabase-js createClient with a non-service key and no user session runs as anon (RLS applies)
      return 'rls';
    }
    return undefined;
  }

  function evalBinding(init: AstNode | null | undefined, scope: Scope): Binding {
    if (!init) return CLEAN;
    const u = unwrap(init);
    const b: Binding = { t: taintOf(u, scope) };
    const h = hostTaint(u, scope);
    if (h !== b.t) b.h = h;
    if (isUserExpr(u, scope)) b.user = true;
    if (isReqUrlObj(u, scope)) b.url = true;
    const ck = clientKind(u, scope);
    if (ck) b.client = ck;
    if (queryNodes.has(unwrapAwait(u))) b.row = true;
    else {
      const ua = unwrapAwait(u);
      if (ua.type === 'Identifier' && scope.lookup(ua.name)?.row) b.row = true;
      if (isMember(ua) && (() => { const r = unwrapAwait(ua.object); return r.type === 'Identifier' && !!scope.lookup(r.name)?.row; })()) b.row = true;
    }
    if (u.type === 'Identifier') {
      const src = scope.lookup(u.name);
      if (src?.req) b.req = src.req;
      if (src?.ctx) b.ctx = true;
      if (src?.authCtx) b.authCtx = true;
      if (src?.fn) b.fn = src.fn;
    }
    if (isFunction(u)) b.fn = u;
    return b;
  }

  function bindPattern(pat: AstNode | null | undefined, b: Binding, scope: Scope, assign: boolean): void {
    if (!pat) return;
    const set = (name: string, v: Binding) => (assign ? scope.assign(name, v) : scope.declare(name, v));
    switch (pat.type) {
      case 'Identifier': set(pat.name, b); return;
      case 'AssignmentPattern': bindPattern(pat.left, b, scope, assign); return;
      case 'RestElement': bindPattern(pat.argument, { t: b.t, user: b.user, row: b.row }, scope, assign); return;
      case 'TSParameterProperty': bindPattern(pat.parameter, b, scope, assign); return;
      case 'ArrayPattern':
        for (const el of pat.elements) if (el) bindPattern(el, { t: b.t, user: b.user, row: b.row }, scope, assign);
        return;
      case 'ObjectPattern':
        for (const p of pat.properties) {
          if (p.type === 'RestElement') { bindPattern(p.argument, { t: b.t, user: b.user, row: b.row }, scope, assign); continue; }
          const k = keyName(p) || '';
          let sub: Binding;
          if (b.url) sub = { t: k === 'searchParams' ? 2 : 0 };
          else if (b.ctx && (k === 'params' || k === 'searchParams')) sub = { t: 2 };
          else if (b.trpcOpts && k === 'input') sub = { t: 2 };
          else if (b.trpcOpts && k === 'ctx') sub = { t: 0, authCtx: true };
          else if (b.req === 'express' && (k === 'params' || k === 'query' || k === 'body')) sub = { t: 2 };
          else if (b.req && USER_PROP.test(k)) sub = { t: 0, user: true };
          else if (b.authCtx && USER_PROP.test(k)) sub = { t: 0, user: true };
          else if (b.req === 'next' && k === 'nextUrl') sub = { t: 0, url: true };
          else sub = { t: b.t, user: b.user, row: b.row, h: b.h };
          bindPattern(p.value, sub, scope, assign);
        }
        return;
      default: return;
    }
  }

  // ---------- DB query recognition ----------

  /** Flattened call chain `root.a(..).b(..)` -> root + [{name,args,node}] in source order. */
  function chainOf(call: AstNode): { root: AstNode; links: { name: string; args: AstNode[]; node: AstNode }[] } {
    const links: { name: string; args: AstNode[]; node: AstNode }[] = [];
    let cur: AstNode = call;
    while (isCall(cur) && isMember(unwrap(cur.callee))) {
      const callee = unwrap(cur.callee);
      links.unshift({ name: propName(callee) || '', args: cur.arguments || [], node: cur });
      cur = unwrapAwait(callee.object);
    }
    return { root: cur, links };
  }

  function ownedIn(n: AstNode | null | undefined, scope: Scope): boolean {
    if (!n) return false;
    let owned = false;
    walk(n, (x) => {
      if (owned || isFunction(x) && x !== n) return false;
      if (x.type === 'ObjectProperty' && OWNER_KEY.test(keyName(x) || '')) owned = true;
      else if (isMember(x) && OWNER_KEY.test(propName(x) || '')) owned = true;
      else if ((x.type === 'Identifier' || isMember(x) || isCall(x)) && isUserExpr(x, scope)) owned = true;
      else if (x.type === 'StringLiteral' && OWNER_KEY.test(x.value)) owned = true;
      return !owned;
    });
    return owned;
  }

  /** Does a Prisma/Mongoose-style filter object select by a request-controlled id? */
  function idTaintedFilter(obj: AstNode | null | undefined, scope: Scope): boolean {
    const o = obj ? unwrap(obj) : null;
    if (!o || o.type !== 'ObjectExpression') return false;
    for (const p of o.properties) {
      if (p.type !== 'ObjectProperty') continue;
      const k = keyName(p) || '';
      if (IDISH_KEY.test(k) && !OWNER_KEY.test(k) && taintOf(p.value, scope) > 0 && !SECRET_VALUE.test(valueName(p.value))) return true;
      if ((k === 'AND' || k === 'OR') && unwrap(p.value).type === 'ArrayExpression') {
        if (unwrap(p.value).elements.some((el: AstNode) => el && idTaintedFilter(el, scope))) return true;
      }
    }
    return false;
  }

  function counterOnly(data: AstNode | null | undefined): boolean {
    const d = data ? unwrap(data) : null;
    if (!d || d.type !== 'ObjectExpression' || d.properties.length === 0) return false;
    return d.properties.every((p: AstNode) => {
      if (p.type !== 'ObjectProperty') return false;
      const v = unwrap(p.value);
      return v.type === 'ObjectExpression' && v.properties.length === 1 && /^(?:increment|decrement)$/.test(keyName(v.properties[0]) || '');
    });
  }

  function detectQuery(call: AstNode, scope: Scope): DbQuery | null {
    const { root, links } = chainOf(call);
    if (!links.length) return null;
    const line = lineOf(call);
    const first = links[0];
    // Prisma: <db>.<model>.<op>({ where })
    if (isMember(root)) {
      const rp = memberPath(root);
      if (rp && rp.length >= 2 && DB_ROOT.test(rp[rp.length - 2]) && (PRISMA_READ.has(first.name) || PRISMA_WRITE.has(first.name))) {
        const arg = first.args[0] ? unwrap(first.args[0]) : null;
        if (!arg || arg.type !== 'ObjectExpression') return null;
        const whereP = arg.properties.find((p: AstNode) => keyName(p) === 'where');
        const dataP = arg.properties.find((p: AstNode) => keyName(p) === 'data');
        const where = whereP?.value;
        return {
          node: call, line, lib: 'prisma', model: rp[rp.length - 1], op: first.name, write: PRISMA_WRITE.has(first.name),
          idTainted: idTaintedFilter(where, scope), owned: ownedIn(where, scope), counterOnly: counterOnly(dataP?.value),
        };
      }
      // Drizzle relational: db.query.<table>.findFirst({ where: eq(t.id, id) })
      if (rp && rp.length >= 3 && rp[rp.length - 2] === 'query' && (first.name === 'findFirst' || first.name === 'findMany') && usesDrizzle) {
        const arg = first.args[0] ? unwrap(first.args[0]) : null;
        const whereP = arg?.type === 'ObjectExpression' ? arg.properties.find((p: AstNode) => keyName(p) === 'where') : null;
        if (!whereP) return null;
        return { node: call, line, lib: 'drizzle', model: rp[rp.length - 1], op: first.name, write: false, idTainted: drizzleIdTainted(whereP.value, scope), owned: ownedIn(whereP.value, scope) };
      }
    }
    // Supabase: client.from('t').select|update|delete|upsert(...).eq('id', id)
    const fromIdx = links.findIndex((l) => l.name === 'from' && stringValue(l.args[0]) !== null);
    if (fromIdx !== -1) {
      const opLink = links.slice(fromIdx + 1).find((l) => ['select', 'update', 'delete', 'upsert', 'insert'].includes(l.name));
      if (!opLink || opLink.name === 'insert') return null;
      const rootPath = memberPath(root);
      if (rootPath && rootPath[rootPath.length - 1] === 'storage') return null;
      const filters = links.slice(fromIdx + 1).filter((l) => ['eq', 'match', 'in', 'filter', 'or', 'neq', 'is', 'contains'].includes(l.name));
      let idTainted = false;
      let owned = false;
      for (const f of filters) {
        if (f.name === 'eq') {
          const col = stringValue(f.args[0]) || '';
          if (IDISH_KEY.test(col) && !OWNER_KEY.test(col) && taintOf(f.args[1], scope) > 0 && !SECRET_VALUE.test(valueName(f.args[1]))) idTainted = true;
          if (OWNER_KEY.test(col) || isUserExpr(f.args[1], scope)) owned = true;
        } else if (f.name === 'match') {
          if (idTaintedFilter(f.args[0], scope)) idTainted = true;
          if (ownedIn(f.args[0], scope)) owned = true;
        } else if (f.args.some((a) => ownedIn(a, scope))) owned = true;
      }
      const ck = clientKind(root, scope);
      return {
        node: call, line, lib: 'supabase', model: stringValue(links[fromIdx].args[0]) || '', op: opLink.name,
        write: opLink.name !== 'select', idTainted, owned, client: ck ?? 'unknown',
      };
    }
    // Drizzle core: db.select().from(t).where(...), db.update(t).set().where(...), db.delete(t).where(...)
    if (usesDrizzle && root.type === 'Identifier' && DB_ROOT.test(root.name)) {
      const head = first.name;
      if (head === 'select' || head === 'update' || head === 'delete') {
        const whereLink = links.find((l) => l.name === 'where');
        if (!whereLink) return null;
        const tableArg = head === 'select' ? links.find((l) => l.name === 'from')?.args[0] : first.args[0];
        const model = tableArg ? (memberPath(tableArg) || ['']).join('.') : '';
        return { node: call, line, lib: 'drizzle', model, op: head, write: head !== 'select', idTainted: drizzleIdTainted(whereLink.args[0], scope), owned: ownedIn(whereLink.args[0], scope) };
      }
    }
    // Mongoose / Sequelize: Model.findById(id), Model.findOne({ _id: id }), Model.destroy({ where: { id } })
    if (root.type === 'Identifier' && /^[A-Z]/.test(root.name) && !/^(?:Object|Array|JSON|Math|Promise|Date|Number|String|Reflect|Buffer|URL|Response|NextResponse)$/.test(root.name)) {
      if ((usesMongoose || first.name.startsWith('findById')) && first.name in MONGOOSE_OPS) {
        const byId = first.name.startsWith('findById');
        const filter = first.args[0];
        return {
          node: call, line, lib: 'mongoose', model: root.name, op: first.name, write: MONGOOSE_OPS[first.name],
          idTainted: byId ? taintOf(filter, scope) > 0 : idTaintedFilter(filter, scope),
          owned: byId ? false : ownedIn(filter, scope),
        };
      }
      if (usesSequelize && (first.name in SEQUELIZE_OPS)) {
        const byPk = first.name === 'findByPk';
        const opts = first.args[0] ? unwrap(first.args[0]) : null;
        const where = !byPk && opts?.type === 'ObjectExpression' ? opts.properties.find((p: AstNode) => keyName(p) === 'where')?.value : null;
        return {
          node: call, line, lib: 'sequelize', model: root.name, op: first.name, write: SEQUELIZE_OPS[first.name],
          idTainted: byPk ? taintOf(first.args[0], scope) > 0 : idTaintedFilter(where, scope), owned: byPk ? false : ownedIn(where, scope),
        };
      }
    }
    return null;
  }

  function drizzleIdTainted(where: AstNode | null | undefined, scope: Scope): boolean {
    if (!where) return false;
    let hit = false;
    walk(where, (x) => {
      if (hit) return false;
      if (isCall(x) && calleeName(x) === 'eq' && x.arguments.length === 2) {
        const col = unwrap(x.arguments[0]);
        const colName = isMember(col) ? propName(col) || '' : '';
        if (IDISH_KEY.test(colName) && !OWNER_KEY.test(colName) && taintOf(x.arguments[1], scope) > 0 && !SECRET_VALUE.test(valueName(x.arguments[1]))) hit = true;
      }
      return !hit;
    });
    return hit;
  }

  // ---------- sinks ----------

  function fsFnName(call: AstNode): string | null {
    const callee = unwrap(call.callee);
    if (callee.type === 'Identifier') {
      const src = importedFrom(callee.name);
      return src && FS_MODULES.test(src) && FS_PATH_FNS.has(callee.name) ? callee.name : null;
    }
    if (isMember(callee)) {
      const m = propName(callee) || '';
      if (!FS_PATH_FNS.has(m)) return null;
      const p = memberPath(callee.object);
      if (!p) return null;
      const rootSrc = importedFrom(p[0]);
      if ((rootSrc && FS_MODULES.test(rootSrc)) || /^(?:fs|fsp|fsPromises|fse)$/.test(p[0])) return m;
    }
    return null;
  }

  function isChildProcess(name: string): boolean {
    const src = importedFrom(name);
    return !!src && /^(?:node:)?child_process$/.test(src);
  }

  function checkSinks(call: AstNode, scope: Scope, ctx: Ctx): void {
    const callee = unwrap(call.callee);
    const args: AstNode[] = call.arguments || [];
    const name = calleeName(call) || '';
    const line = lineOf(call);
    const objPath = isMember(callee) ? memberPath(callee.object) : null;
    const objLast = objPath ? objPath[objPath.length - 1] : '';
    const t0 = () => taintOf(args[0], scope);
    const hit = (code: SinkCode, detail: string) => sinks.push({ code, line, detail, ctx });

    // AST-03 SQL built from request input
    if (name === '$queryRawUnsafe' || name === '$executeRawUnsafe') { if (t0() >= 2) hit('AST-03', `${name} with a query string built from request input`); return; }
    if (isMember(callee) && name === 'raw' && /^(?:knex|db|trx|tx|sql|Prisma|database|k|pg)$/.test(objLast)) { if (t0() >= 2) hit('AST-03', `${objLast}.raw() with request input`); return; }
    if (isMember(callee) && name === 'unsafe' && /^(?:sql|db|pg|postgres)$/.test(objLast)) { if (t0() >= 2) hit('AST-03', `${objLast}.unsafe() with request input`); return; }
    if (isMember(callee) && SQL_RAW_METHODS.has(name)) { if (t0() >= 2) hit('AST-03', `${name}() with request input`); return; }
    if (isMember(callee) && (name === 'query' || name === 'execute') && SQL_QUERY_OBJ.test(objLast)) {
      const a0 = args[0] ? unwrap(args[0]) : null;
      if (a0 && a0.type !== 'TaggedTemplateExpression' && a0.type !== 'ObjectExpression' && t0() >= 2) hit('AST-03', `${objLast}.${name}() with a SQL string built from request input`);
      return;
    }

    // AST-04 command injection
    const cpCall = (callee.type === 'Identifier' && isChildProcess(callee.name)) || (objPath && objPath.length === 1 && (isChildProcess(objPath[0]) || /^(?:child_process|childProcess|cp)$/.test(objPath[0])));
    if (cpCall) {
      if ((name === 'exec' || name === 'execSync') && t0() >= 2) { hit('AST-04', `${name}() runs a shell command built from request input`); return; }
      if (['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(name)) {
        const cmd = stringValue(args[0]);
        if (cmd === null && t0() >= 2) { hit('AST-04', `${name}() runs a request-chosen binary`); return; }
        const opts = args.find((a) => unwrap(a).type === 'ObjectExpression');
        const shell = !!opts && unwrap(opts).properties.some((p: AstNode) => keyName(p) === 'shell' && !(unwrap(p.value).type === 'BooleanLiteral' && unwrap(p.value).value === false));
        const shellBin = cmd !== null && /^(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh)$/.test(cmd);
        if ((shell || shellBin) && args[1] && taintOf(args[1], scope) >= 2) { hit('AST-04', `${name}() passes request input to a shell`); return; }
      }
      return;
    }
    if ((name === 'execaCommand' || name === 'execaCommandSync') && t0() >= 2) { hit('AST-04', `${name}() runs a command string built from request input`); return; }

    // AST-05 path traversal in fs calls
    const fsName = fsFnName(call);
    if (fsName) {
      const twoPaths = /^(?:copyFile|rename)/.test(fsName);
      if (t0() >= 2 || (twoPaths && taintOf(args[1], scope) >= 2)) hit('AST-05', `fs.${fsName}() on a path built from request input`);
      return;
    }

    // AST-06 SSRF
    const httpFn = callee.type === 'Identifier' && (HTTP_CLIENT_FNS.has(callee.name) || /^(?:node-fetch|undici|cross-fetch|axios|got|ky|ofetch)$/.test(importedFrom(callee.name) || ''));
    const httpMethod = isMember(callee) && HTTP_CLIENT_METHODS.has(name) && objPath && objPath.length === 1
      && (HTTP_CLIENT_OBJ.test(objPath[0]) || /^(?:axios|got|ky|undici|ofetch|(?:node:)?https?)$/.test(importedFrom(objPath[0]) || ''));
    if (httpFn || httpMethod) {
      let target: AstNode | undefined = args[0];
      const a0 = target ? unwrap(target) : null;
      if (a0?.type === 'ObjectExpression') target = a0.properties.find((p: AstNode) => keyName(p) === 'url' || keyName(p) === 'baseURL')?.value;
      if (target && hostTaint(target, scope) >= 2) hit('AST-06', `outbound ${httpFn ? callee.name : objPath!.join('.') + '.' + name}() to a request-supplied URL`);
      return;
    }

    // AST-07 open redirect
    const isNextRedirect = callee.type === 'Identifier' && (name === 'redirect' || name === 'permanentRedirect') && /^next\/navigation$/.test(importedFrom(name) || '');
    const isResponseRedirect = isMember(callee) && name === 'redirect' && objPath && objPath.length === 1 && (/^(?:NextResponse|Response)$/.test(objPath[0]) || RESPONSE_OBJ.test(objPath[0]));
    const isLocationNav = isMember(callee) && (name === 'assign' || name === 'replace') && objPath && /^(?:window\.|document\.)?location$/.test(objPath.join('.'));
    if (isNextRedirect || isResponseRedirect || isLocationNav) {
      const target = isResponseRedirect && RESPONSE_OBJ.test(objPath![0]) && args.length > 1 ? args[args.length - 1] : args[0];
      if (target && hostTaint(target, scope) >= 2) hit('AST-07', `redirect to a request-supplied URL`);
      return;
    }
    // AST-08 DOM HTML sinks
    if (isMember(callee) && objPath && objPath.join('.') === 'document' && (name === 'write' || name === 'writeln') && t0() >= 2) { hit('AST-08', 'document.write() of request/URL input'); return; }
    if (isMember(callee) && name === 'insertAdjacentHTML' && args[1] && taintOf(args[1], scope) >= 2) { hit('AST-08', 'insertAdjacentHTML() with request/URL input'); return; }
  }

  // ---------- statement walk ----------

  function recordMix(node: AstNode, refsFrom: AstNode[], scope: Scope, ctx: Ctx): void {
    if (!ctx.spec) return;
    let user = false;
    let data = false;
    for (const r of refsFrom) {
      walk(r, (x) => {
        if (isFunction(x)) return false;
        if (!user && (x.type === 'Identifier' || isMember(x) || isCall(x)) && isUserExpr(x, scope)) user = true;
        if (!data && (x.type === 'Identifier' || isMember(x) || isCall(x))) {
          if (taintOf(x, scope) > 0) data = true;
          else if (x.type === 'Identifier' && scope.lookup(x.name)?.row) data = true;
        }
        return !(user && data);
      });
    }
    if (user && data) ctx.mixes.push(node);
  }

  function analyzeFunction(fn: AstNode, params: Binding[], parentScope: Scope, ctx: Ctx): Frame {
    parsedFunctions++;
    const scope = new Scope(parentScope);
    (fn.params || []).forEach((p: AstNode, i: number) => bindPattern(p, params[i] ?? CLEAN, scope, false));
    if (fn.id?.type === 'Identifier' && fn.type !== 'FunctionDeclaration') scope.declare(fn.id.name, { t: 0, fn });
    const frame: Frame = { ret: 0, retUser: false };
    const body = fn.body;
    if (!body) return frame;
    if (body.type === 'BlockStatement') {
      hoist(body.body, scope);
      for (const s of body.body) visit(s, scope, ctx, frame, null);
    } else {
      visit(body, scope, ctx, frame, null);
      frame.ret = Math.max(frame.ret, taintOf(body, scope));
      frame.retUser = frame.retUser || isUserExpr(body, scope);
    }
    return frame;
  }

  function hoist(stmts: AstNode[], scope: Scope): void {
    for (const s of stmts) {
      const d = s.type === 'ExportNamedDeclaration' || s.type === 'ExportDefaultDeclaration' ? s.declaration : s;
      if (d?.type === 'FunctionDeclaration' && d.id) scope.declare(d.id.name, { t: 0, fn: d });
    }
  }

  function paramBindingsFor(spec: HandlerSpec, fn: AstNode): Binding[] {
    switch (spec.kind) {
      case 'route': return [{ t: 0, req: 'next' }, { t: 0, ctx: true }];
      case 'page': return [{ t: 0, ctx: true }];
      // FormData fields are free text (level 2); typed arguments still choose records but rarely reach sinks
      case 'action': return (fn.params || []).map((p: AstNode) => {
        const id = p.type === 'AssignmentPattern' ? p.left : p;
        const typeName = id?.typeAnnotation?.typeAnnotation?.typeName?.name;
        return { t: typeName === 'FormData' || (id?.type === 'Identifier' && /form/i.test(id.name)) ? 2 : 1 };
      });
      case 'express': case 'controller': return [{ t: 0, req: 'express' }];
      case 'hono': return [{ t: 0, req: 'hono' }];
      case 'trpc': return [{ t: 0, trpcOpts: true }];
      case 'graphql': return [CLEAN, { t: 2 }, { t: 0, authCtx: true }];
      default: return [];
    }
  }

  function enterFunction(fn: AstNode, scope: Scope, ctx: Ctx): void {
    let spec = specs.get(fn) ?? null;
    if (!spec && !ctx.spec) {
      const [p0, p1] = fn.params || [];
      if (p0?.type === 'Identifier' && /^req(?:uest)?$/.test(p0.name) && p1?.type === 'Identifier' && /^(?:res|response|reply)$/.test(p1.name)) {
        spec = { kind: 'controller', name: fn.id?.name || 'handler' };
      }
    }
    if (spec) {
      const hctx = newCtx(spec, lineOf(fn));
      if (spec.wrapped || spec.middlewareAuth || (crossFile?.middlewareAuthed && (spec.kind === 'route' || spec.kind === 'controller'))) hctx.authed = true;
      if (spec.adminProc) hctx.adminCheck = true;
      handlers.push(hctx);
      analyzeFunction(fn, paramBindingsFor(spec, fn), scope, hctx);
      return;
    }
    // Nested callback or plain function: parameters are clean (their callers are analyzed at call sites)
    analyzeFunction(fn, [], scope, ctx === moduleCtx ? newCtx(null, lineOf(fn)) : ctx);
  }

  function handleLocalCall(call: AstNode, scope: Scope, ctx: Ctx): void {
    const callee = unwrap(call.callee);
    if (callee.type !== 'Identifier') return;
    const fn = scope.lookup(callee.name)?.fn ?? localFns.get(callee.name);
    if (!fn || active.has(fn) || active.size >= 3 || budget <= 0) return;
    const argB = (call.arguments || []).map((a: AstNode) => (a.type === 'SpreadElement' ? { t: taintOf(a.argument, scope) } : evalBinding(a, scope)));
    if (!argB.some((b: Binding) => b.t > 0 || b.user || b.req || b.ctx) && !ctx.spec) return;
    budget--;
    active.add(fn);
    const frame = analyzeFunction(fn, argB, moduleScope, ctx);
    active.delete(fn);
    callCache.set(call, { t: frame.ret, user: frame.retUser });
  }

  function visit(node: AstNode | null | undefined, scope: Scope, ctx: Ctx, frame: Frame, parent: AstNode | null): void {
    if (!node) return;
    if (isFunction(node)) {
      if (node.type === 'FunctionDeclaration' && node.id) scope.declare(node.id.name, { t: 0, fn: node });
      enterFunction(node, scope, ctx);
      return;
    }
    switch (node.type) {
      case 'ImportDeclaration': case 'TSTypeAliasDeclaration': case 'TSInterfaceDeclaration': case 'TSEnumDeclaration': case 'TSModuleDeclaration': case 'TSDeclareFunction':
        return;
      case 'VariableDeclaration':
        for (const d of node.declarations) {
          visit(d.init, scope, ctx, frame, d);
          bindPattern(d.id, evalBinding(d.init, scope), scope, false);
        }
        return;
      case 'AssignmentExpression': {
        visit(node.right, scope, ctx, frame, node);
        if (node.left.type !== 'Identifier' && node.left.type !== 'ObjectPattern' && node.left.type !== 'ArrayPattern') visit(node.left, scope, ctx, frame, node);
        const nb = evalBinding(node.right, scope);
        if (node.operator === '=') bindPattern(node.left, nb, scope, true);
        else if (node.left.type === 'Identifier') {
          const prev = scope.lookup(node.left.name) ?? CLEAN;
          scope.assign(node.left.name, { ...prev, t: Math.max(prev.t, nb.t) });
        }
        // DOM sinks / navigation by assignment
        const lp = isMember(node.left) ? propName(node.left) : null;
        if ((lp === 'innerHTML' || lp === 'outerHTML') && taintOf(node.right, scope) >= 2) sinks.push({ code: 'AST-08', line: lineOf(node), detail: `${lp} assigned request/URL input`, ctx });
        const lpath = memberPath(node.left)?.join('.') || '';
        if (/^(?:window\.|document\.)?location(?:\.href)?$/.test(lpath) && hostTaint(node.right, scope) >= 2) sinks.push({ code: 'AST-07', line: lineOf(node), detail: 'location set to a URL from request/URL input', ctx });
        return;
      }
      case 'ReturnStatement':
        visit(node.argument, scope, ctx, frame, node);
        if (node.argument) {
          frame.ret = Math.max(frame.ret, taintOf(node.argument, scope));
          frame.retUser = frame.retUser || isUserExpr(node.argument, scope);
        }
        return;
      case 'BinaryExpression':
        visit(node.left, scope, ctx, frame, node);
        visit(node.right, scope, ctx, frame, node);
        if (COMPARE_OPS.has(node.operator)) {
          recordMix(node, [node.left, node.right], scope, ctx);
          if (ctx.spec || ctx !== moduleCtx) {
            const envSide = [node.left, node.right].some((s) => { const p = memberPath(s); return !!p && p[0] === 'process' && p[1] === 'env'; });
            if (envSide) ctx.guarded = true;
          }
        }
        return;
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        visit(node.object, scope, ctx, frame, node);
        if (node.computed) visit(node.property, scope, ctx, frame, node);
        const prop = propName(node) || '';
        if (ctx !== moduleCtx) {
          if (USER_PROP.test(prop) && isUserExpr(node, scope)) ctx.authed = true;
          if (ADMIN_PROP.test(prop) && isUserExpr(node.object, scope)) ctx.adminCheck = true;
          if (prop === 'hostname' || prop === 'host' || (prop === 'origin' && !isReqUrlObj(node.object, scope))) ctx.urlGuard = true;
        }
        return;
      }
      case 'JSXAttribute': {
        visit(node.value, scope, ctx, frame, node);
        if (node.name?.name === 'dangerouslySetInnerHTML') {
          const v = node.value?.type === 'JSXExpressionContainer' ? unwrap(node.value.expression) : null;
          const html = v?.type === 'ObjectExpression' ? v.properties.find((p: AstNode) => keyName(p) === '__html')?.value : null;
          if (html && taintOf(html, scope) >= 2) sinks.push({ code: 'AST-08', line: lineOf(node), detail: 'dangerouslySetInnerHTML with request/URL input', ctx });
        }
        return;
      }
      case 'CallExpression':
      case 'OptionalCallExpression':
      case 'NewExpression': {
        visit(node.callee, scope, ctx, frame, node);
        for (const a of node.arguments || []) visit(a, scope, ctx, frame, node);
        if (node.type === 'NewExpression') return;
        handleCall(node, scope, ctx, parent);
        return;
      }
      default:
        for (const { child } of children(node)) visit(child, scope, ctx, frame, node);
    }
  }

  function handleCall(call: AstNode, scope: Scope, ctx: Ctx, parent: AstNode | null): void {
    const name = calleeName(call) || '';
    const callee = unwrap(call.callee);
    if (ctx !== moduleCtx) {
      if (isAuthCall(call, scope)) ctx.authed = true;
      if (GUARD_FN.test(name)) ctx.guarded = true;
      if (/^(?:cookies|headers)$/.test(name) || (name === 'get' && call.arguments[0] && /^(?:authorization|x-api-key|x-cron-secret|x-webhook-secret|cookie|x-signature)$/i.test(stringValue(call.arguments[0]) || ''))) ctx.guarded = true;
      if (ADMIN_FN.test(name) && /^(?:require|assert|ensure|check|is|has|verify|get)/.test(name)) ctx.adminCheck = true;
      if (name === 'startsWith' || (name === 'includes' && stringValue(call.arguments[0]) === '..') || /^isPathInside|^isSubPath|^isWithin/.test(name)) ctx.pathGuard = true;
      // /^[\w-]+$/.test(input): input validated against a pattern
      if (name === 'test' && isMember(callee) && unwrap(callee.object).type === 'RegExpLiteral' && taintOf(call.arguments[0], scope) > 0) { ctx.pathGuard = true; ctx.redirectGuard = true; }
      if (/allow|whitelist|valid|safe|isPrivate|isInternal|ssrf|checkUrl|verifyUrl|assertUrl|isPublicUrl|isExternal/i.test(name)) ctx.urlGuard = true;
      if (name === 'startsWith' || /safe|valid|allow|sanitiz|isRelative|isLocal|isInternal|isSameOrigin/i.test(name)) ctx.redirectGuard = true;
    }
    handleLocalCall(call, scope, ctx);
    const outermost = !(parent && isMember(parent) && unwrap(parent.object) === call);
    let isQuery = false;
    if (outermost) {
      const q = detectQuery(call, scope);
      if (q) {
        isQuery = true;
        queryNodes.add(call);
        if (ctx.spec && !ctx.queries.some((x) => x.node === call)) ctx.queries.push(q);
        if (ctx.spec) recordMix(call, call.arguments || [], scope, ctx);
      }
    }
    if (!isQuery && ctx.spec) {
      const isLocal = callee.type === 'Identifier' && (!!scope.lookup(callee.name)?.fn || localFns.has(callee.name));
      const m = isMember(callee) ? propName(callee) || '' : '';
      const objRoot = isMember(callee) ? (memberPath(callee.object) || [''])[0] : '';
      const logging = LOGGING_CALL.test(name) || (/^(?:console|logger|log|posthog|analytics|Sentry)$/.test(objRoot) && !ARRAY_MEMBERSHIP.has(m));
      // Any non-logging call handed both the user and the request id / fetched row is treated as the access check
      if (MIX_FN.test(name) || isLocal || ARRAY_MEMBERSHIP.has(m) || !logging) recordMix(call, [...(isMember(callee) ? [callee.object] : []), ...(call.arguments || [])], scope, ctx);
    }
    checkSinks(call, scope, ctx);
  }

  // Module level: bind top-level clients and helpers, then walk everything (handlers are entered as found)
  hoist(program.body, moduleScope);
  const moduleFrame: Frame = { ret: 0, retUser: false };
  for (const s of program.body) visit(s, moduleScope, moduleCtx, moduleFrame, null);

  // Dedupe sinks per code+line (helpers can be analyzed once per call site)
  const seen = new Set<string>();
  const uniqueSinks = sinks.filter((s) => { const k = `${s.code}:${s.line}`; if (seen.has(k)) return false; seen.add(k); return true; });
  return { handlers, sinks: uniqueSinks, parsedFunctions };
}

// ---------- module facts and handler discovery ----------

function isAllowListTest(test: AstNode): boolean {
  const t = unwrap(test);
  if (!isCall(t) || !isMember(unwrap(t.callee))) return false;
  const m = propName(unwrap(t.callee));
  const obj = unwrap(unwrap(t.callee).object);
  if (m !== 'includes' && m !== 'has') return false;
  if (obj.type === 'ArrayExpression') return obj.elements.every((e: AstNode) => e && (e.type === 'StringLiteral' || e.type === 'NumericLiteral'));
  return obj.type === 'Identifier' && /allow|valid|whitelist|permitted|supported|accepted|^[A-Z_]+$/i.test(obj.name);
}

/** Variable or property name an expression reads (`token`, `body.csrfToken` -> csrfToken). */
function valueName(e: AstNode | null | undefined): string {
  const u = e ? unwrapAwait(e) : null;
  if (!u) return '';
  if (u.type === 'Identifier') return u.name;
  if (isMember(u)) return propName(u) || '';
  if (isCall(u)) return calleeName(u) === 'get' ? stringValue(u.arguments[0]) || '' : '';
  return '';
}

function collectModuleFacts(program: AstNode, imports: Map<string, string>, localFns: Map<string, AstNode>): void {
  for (const s of program.body) {
    if (s.type === 'ImportDeclaration') {
      for (const sp of s.specifiers || []) if (sp.local?.name) imports.set(sp.local.name, s.source.value);
      continue;
    }
    const d = s.type === 'ExportNamedDeclaration' || s.type === 'ExportDefaultDeclaration' ? s.declaration : s;
    if (!d) continue;
    if (d.type === 'FunctionDeclaration' && d.id) localFns.set(d.id.name, d);
    if (d.type === 'VariableDeclaration') {
      for (const dec of d.declarations) {
        const init = dec.init ? unwrap(dec.init) : null;
        if (!init) continue;
        if (dec.id.type === 'Identifier' && isFunction(init)) localFns.set(dec.id.name, init);
        // const fs = require('fs') / const { exec } = require('child_process')
        const req = unwrapAwait(init);
        const reqSrc = isCall(req) && (calleeName(req) === 'require' || req.callee?.type === 'Import') ? stringValue(req.arguments[0]) : null;
        if (reqSrc) {
          if (dec.id.type === 'Identifier') imports.set(dec.id.name, reqSrc);
          else if (dec.id.type === 'ObjectPattern') {
            for (const p of dec.id.properties) {
              const local = p.type === 'ObjectProperty' && p.value?.type === 'Identifier' ? p.value.name : null;
              if (local) imports.set(local, reqSrc);
            }
          }
        }
      }
    }
  }
}

const ROUTE_FILE = /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/;
const PAGE_FILE = /(?:^|\/)app\/(?:.*\/)?page\.[jt]sx?$/;
const PAGES_API = /(?:^|\/)pages\/api\//;
const BENIGN_USE = /^(?:json|urlencoded|static|raw|text|cors|helmet|morgan|compression|cookieParser|bodyParser|logger|express|serveStatic|favicon|rateLimit|limiter|methodOverride|responseTime|requestId|errorHandler|notFound|timeout|prettyJSON|secureHeaders|poweredBy|csrf|csurf|session|expressSession|i18n|multer|upload|router|routes|api|v1|apiRouter|swaggerUi|serve|setup)$/i;

function hasUseDirective(body: AstNode | null | undefined): boolean {
  return !!body && body.type === 'BlockStatement' && (body.directives || []).some((d: AstNode) => d.value?.value === 'use server');
}

function findHandlers(program: AstNode, path: string, imports: Map<string, string>): Map<AstNode, HandlerSpec> {
  const specs = new Map<AstNode, HandlerSpec>();
  const useServerFile = (program.directives || []).some((d: AstNode) => d.value?.value === 'use server');
  const routeFile = ROUTE_FILE.test(path);
  const pageFile = PAGE_FILE.test(path);
  const pagesApi = PAGES_API.test(path);

  const fnFromInit = (init: AstNode | null | undefined): { fn: AstNode | null; wrapped: boolean } => {
    const u = init ? unwrap(init) : null;
    if (!u) return { fn: null, wrapped: false };
    if (isFunction(u)) return { fn: u, wrapped: false };
    if (isCall(u)) {
      const inner = (u.arguments || []).map((a: AstNode) => unwrap(a)).find((a: AstNode) => isFunction(a));
      return { fn: inner ?? null, wrapped: true };
    }
    return { fn: null, wrapped: false };
  };

  for (const s of program.body) {
    if (s.type === 'ExportNamedDeclaration' && s.declaration) {
      const d = s.declaration;
      const entries: { name: string; fn: AstNode | null; wrapped: boolean }[] = [];
      if (d.type === 'FunctionDeclaration' && d.id) entries.push({ name: d.id.name, fn: d, wrapped: false });
      if (d.type === 'VariableDeclaration') for (const dec of d.declarations) if (dec.id.type === 'Identifier') entries.push({ name: dec.id.name, ...fnFromInit(dec.init) });
      for (const e of entries) {
        if (!e.fn) continue;
        if (routeFile && HTTP_METHODS.has(e.name)) specs.set(e.fn, { kind: 'route', name: e.name, method: e.name, wrapped: e.wrapped });
        else if ((useServerFile || hasUseDirective(e.fn.body)) && e.fn.async) specs.set(e.fn, { kind: 'action', name: e.name, method: 'POST', wrapped: e.wrapped });
      }
    } else if (s.type === 'FunctionDeclaration' && s.id && hasUseDirective(s.body)) {
      specs.set(s, { kind: 'action', name: s.id.name, method: 'POST' });
    } else if (s.type === 'ExportDefaultDeclaration') {
      const { fn, wrapped } = fnFromInit(s.declaration);
      if (fn && pageFile) specs.set(fn, { kind: 'page', name: 'Page', method: 'GET', wrapped });
      else if (fn && pagesApi) specs.set(fn, { kind: 'controller', name: 'handler', wrapped });
    }
  }

  // App instances created in this file, and whether any app.use() could add auth
  let createsApp = false;
  let authUse = false;
  walk(program, (n) => {
    if (isCall(n)) {
      const cn = calleeName(n) || '';
      const callee = unwrap(n.callee);
      if (callee.type === 'Identifier' && (cn === 'express' || /^(?:express|fastify)$/.test(imports.get(cn) || '') || cn === 'Fastify')) createsApp = true;
      if (isMember(callee) && (cn === 'use' || cn === 'addHook' || cn === 'register')) {
        const mwArgs = (n.arguments || []).filter((a: AstNode) => stringValue(a) === null);
        const benign = mwArgs.every((a: AstNode) => {
          const u = unwrap(a);
          const nm = isCall(u) ? (memberPath(u.callee) || []).join('.') : (memberPath(u) || []).join('.');
          const last = nm.split('.').pop() || '';
          return !!last && BENIGN_USE.test(last) && !/auth|jwt|session|passport|clerk|guard|protect|verify|bearer/i.test(nm);
        });
        if (!benign) authUse = true;
      }
    }
    if (n.type === 'NewExpression' && n.callee?.type === 'Identifier' && n.callee.name === 'Hono') createsApp = true;
    return true;
  });

  walk(program, (n) => {
    if (isCall(n) && isMember(unwrap(n.callee))) {
      const callee = unwrap(n.callee);
      const verb = propName(callee) || '';
      const args: AstNode[] = (n.arguments || []).map((a: AstNode) => unwrap(a));
      // Express / Hono / Fastify / Koa-router: app.post('/path', ...mw, handler)
      if (ROUTE_VERBS.has(verb) && args.length >= 2 && isFunction(args[args.length - 1])) {
        const p0 = args[0];
        const pathStr = stringValue(p0) ?? (p0.type === 'TemplateLiteral' ? p0.quasis[0]?.value?.cooked ?? '' : null);
        const chained = isCall(unwrap(callee.object)) && calleeName(unwrap(callee.object)) === 'route';
        if ((pathStr !== null && pathStr.startsWith('/')) || chained) {
          const fn = args[args.length - 1];
          const between = args.slice(chained ? 0 : 1, -1);
          const fastifyGuard = between.some((a) => a.type === 'ObjectExpression' && a.properties.some((p: AstNode) => /^(?:preHandler|onRequest|preValidation|preParsing|beforeHandler|config)$/.test(keyName(p) || '')));
          const middleware = between.some((a) => a.type !== 'ObjectExpression') || fastifyGuard;
          const params = fn.params || [];
          const kind: HandlerKind = params.length === 1 && params[0].type === 'Identifier' && /^(?:c|ctx|context)$/.test(params[0].name) && !/^(?:req|request)$/.test(params[0].name) ? 'hono' : 'express';
          if (!specs.has(fn)) specs.set(fn, { kind, name: `${verb.toUpperCase()} ${pathStr ?? ''}`, method: verb === 'del' ? 'DELETE' : verb.toUpperCase(), middlewareAuth: middleware, standaloneApp: createsApp && !authUse });
        }
      }
      // tRPC: someProcedure.input(...).query|mutation(({ ctx, input }) => ...)
      if ((verb === 'query' || verb === 'mutation') && args.length === 1 && isFunction(args[0])) {
        let cur = unwrap(callee.object);
        while (isCall(cur) && isMember(unwrap(cur.callee))) cur = unwrap(unwrap(cur.callee).object);
        const rootName = cur.type === 'Identifier' ? cur.name : isMember(cur) ? propName(cur) || '' : '';
        if (/Procedure$/.test(rootName)) {
          const isPublic = /^public/i.test(rootName);
          specs.set(args[0], {
            kind: 'trpc', name: rootName, method: verb === 'mutation' ? 'POST' : 'GET', middlewareAuth: !isPublic, publicProc: isPublic,
            adminProc: /admin|staff|superuser|internal|system/i.test(rootName),
          });
        }
      }
    }
    // GraphQL resolvers: { Mutation: { deleteUser: (parent, args, ctx) => ... } }
    if (n.type === 'ObjectExpression') {
      for (const p of n.properties) {
        const k = keyName(p);
        if ((k !== 'Mutation' && k !== 'Query') || p.type !== 'ObjectProperty') continue;
        const v = unwrap(p.value);
        if (v.type !== 'ObjectExpression') continue;
        for (const r of v.properties) {
          const fn = r.type === 'ObjectMethod' ? r : r.type === 'ObjectProperty' ? unwrap(r.value) : null;
          if (fn && isFunction(fn) && (fn.params || []).length >= 2) specs.set(fn, { kind: 'graphql', name: `${k}.${keyName(r)}`, method: k === 'Mutation' ? 'POST' : 'GET', publicProc: true });
        }
      }
    }
    return true;
  });
  return specs;
}
