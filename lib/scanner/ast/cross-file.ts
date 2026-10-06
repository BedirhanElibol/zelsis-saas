/**
 * Cross-file facts for the AST flow rules, built once per scan:
 *  - exported helpers that authenticate the caller (`requireTeamMember()` in lib/auth.ts calls auth()),
 *    so a handler that imports and calls them counts as authenticated;
 *  - the routes a Next.js middleware.ts authenticates before any route handler runs.
 * Both only ever turn "unauthenticated" into "authenticated", so a miss here keeps the old per-file result.
 */
import type { CodeFile } from '../types';
import { isParsablePath, parseSource } from './parse';
import { calleeName, isCall, isFunction, isMember, memberPath, unwrap, walk, type AstNode } from './walk';
import { AUTH_FN } from './flow';

export interface CrossFileAuth {
  /** Module key (repo path without extension) -> exported function names that authenticate. */
  authHelpers: Map<string, Set<string>>;
  /** Route path predicate from middleware.ts, or null when no middleware authenticates. */
  middleware: MiddlewareAuth | null;
}

export interface MiddlewareAuth {
  /** Paths the middleware runs on (config.matcher); empty = every path. */
  matchers: RegExp[];
  /** Clerk createRouteMatcher: protect only these (protectOnly) or everything except these (publicExcept). */
  protectOnly: RegExp[] | null;
  publicExcept: RegExp[] | null;
  /** Literal prefixes the middleware lets through (pathname.startsWith('/api/public')). */
  skipPrefixes: string[];
}

export const emptyCrossFileAuth = (): CrossFileAuth => ({ authHelpers: new Map(), middleware: null });

const AUTHISH = /auth|session|user|token|jwt|clerk|supabase|lucia|kinde|iron/i;
const SKIP_PATH = /(?:^|\/)(?:__tests__|tests?|spec|e2e|cypress|playwright|stories|examples?|fixtures?)\/|\.(?:test|spec|stories)\.[cm]?[jt]sx?$/;

/** `lib/auth.ts` / `lib/auth/index.tsx` -> `lib/auth`. */
export function moduleKey(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.?\//, '').replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '');
}

/** Candidate module keys for an import specifier seen in `fromPath`; bare packages resolve to nothing. */
export function resolveImport(fromPath: string, spec: string): string[] {
  if (/^[@~#]\//.test(spec)) {
    const rest = spec.slice(2);
    return [moduleKey(rest), moduleKey(`src/${rest}`), moduleKey(`app/${rest}`)];
  }
  if (!spec.startsWith('.')) return [];
  const parts = fromPath.replace(/\\/g, '/').split('/').slice(0, -1);
  for (const seg of spec.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg !== '.' && seg !== '') parts.push(seg);
  }
  return [moduleKey(parts.join('/'))];
}

function directAuthCall(call: AstNode): boolean {
  const name = calleeName(call);
  if (!name) return false;
  if (AUTH_FN.test(name)) return true;
  const callee = unwrap(call.callee);
  const objPath = isMember(callee) ? memberPath(callee.object) : null;
  if (name === 'verify' && objPath && /^(?:jwt|jsonwebtoken|jose|JWT)$/.test(objPath[objPath.length - 1])) return true;
  return !!objPath && objPath.includes('auth') && /^(?:getUser|getSession|getClaims)$/.test(name);
}

interface ModuleInfo {
  key: string;
  path: string;
  /** exported name -> function node */
  exported: Map<string, AstNode>;
  /** every top-level function by local name (exported or not) */
  locals: Map<string, AstNode>;
  /** local import name -> specifier */
  imports: Map<string, string>;
}

function fnOf(init: AstNode | null | undefined): AstNode | null {
  const u = init ? unwrap(init) : null;
  if (!u) return null;
  if (isFunction(u)) return u;
  // export const getUser = cache(async () => { ... })
  if (isCall(u)) return (u.arguments || []).map((a: AstNode) => unwrap(a)).find((a: AstNode) => isFunction(a)) ?? null;
  return null;
}

function readModule(file: CodeFile): ModuleInfo | null {
  const path = file.path.replace(/\\/g, '/');
  if (!isParsablePath(path) || SKIP_PATH.test(path) || !AUTHISH.test(file.content || '')) return null;
  const program = parseSource(path, file.content || '');
  if (!program) return null;
  const info: ModuleInfo = { key: moduleKey(path), path, exported: new Map(), locals: new Map(), imports: new Map() };
  const exportedLocals: [string, string][] = [];
  for (const s of program.body as AstNode[]) {
    if (s.type === 'ImportDeclaration') {
      for (const sp of s.specifiers || []) if (sp.local?.name) info.imports.set(sp.local.name, s.source.value);
      continue;
    }
    const exported = s.type === 'ExportNamedDeclaration';
    const d = exported ? s.declaration : s;
    if (d?.type === 'FunctionDeclaration' && d.id) {
      info.locals.set(d.id.name, d);
      if (exported) info.exported.set(d.id.name, d);
    } else if (d?.type === 'VariableDeclaration') {
      for (const dec of d.declarations) {
        const fn = dec.id.type === 'Identifier' ? fnOf(dec.init) : null;
        if (!fn) continue;
        info.locals.set(dec.id.name, fn);
        if (exported) info.exported.set(dec.id.name, fn);
      }
    } else if (exported && !s.declaration && !s.source) {
      for (const sp of s.specifiers || []) if (sp.local?.name && sp.exported?.name) exportedLocals.push([sp.local.name, sp.exported.name]);
    }
  }
  for (const [local, name] of exportedLocals) {
    const fn = info.locals.get(local);
    if (fn) info.exported.set(name, fn);
  }
  return info.exported.size ? info : null;
}

export function buildAuthHelperIndex(files: CodeFile[]): Map<string, Set<string>> {
  const modules = new Map<string, ModuleInfo>();
  for (const f of files) {
    const m = readModule(f);
    if (m) modules.set(m.key, m);
  }
  const authed = new Map<string, Set<string>>();
  const isAuthedExport = (key: string, name: string) => !!authed.get(key)?.has(name);
  const localAuthed = new Map<ModuleInfo, Set<AstNode>>();

  const fnAuthenticates = (m: ModuleInfo, fn: AstNode): boolean => {
    let hit = false;
    walk(fn.body, (n) => {
      if (hit) return false;
      if (!isCall(n)) return;
      if (directAuthCall(n)) { hit = true; return false; }
      const callee = unwrap(n.callee);
      if (callee.type !== 'Identifier') return;
      const local = m.locals.get(callee.name);
      if (local && localAuthed.get(m)?.has(local)) { hit = true; return false; }
      const spec = m.imports.get(callee.name);
      if (spec && resolveImport(m.path, spec).some((k) => isAuthedExport(k, callee.name))) { hit = true; return false; }
    });
    return hit;
  };

  // Fixed point: helpers that call helpers (same file or imported) that authenticate. Depth is small in practice.
  for (let round = 0; round < 4; round++) {
    let changed = false;
    for (const m of modules.values()) {
      const done = localAuthed.get(m) ?? new Set<AstNode>();
      localAuthed.set(m, done);
      for (const fn of m.locals.values()) {
        if (!done.has(fn) && fnAuthenticates(m, fn)) { done.add(fn); changed = true; }
      }
      for (const [name, fn] of m.exported) {
        if (done.has(fn) && !isAuthedExport(m.key, name)) {
          if (!authed.has(m.key)) authed.set(m.key, new Set());
          authed.get(m.key)!.add(name);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return authed;
}

// ---------- Next.js middleware ----------

/** Next matcher (path-to-regexp subset) -> RegExp; null when it cannot be converted safely. */
export function matcherToRegExp(pattern: string): RegExp | null {
  const src = pattern
    .replace(/\/:\w+\*/g, '(?:/.*)?')
    .replace(/\/:\w+\+/g, '/.+')
    .replace(/\/:\w+\?/g, '(?:/[^/]+)?')
    // only "/:param" segments: "(?:html?|css)" inside a regex group must stay untouched
    .replace(/\/:\w+/g, '/[^/]+');
  try {
    return new RegExp(`^${src}$`);
  } catch {
    return null;
  }
}

function stringArray(text: string): string[] {
  return [...text.matchAll(/(['"`])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2].replace(/\\\\/g, '\\'));
}

const MIDDLEWARE_FILE = /^(?:src\/)?middleware\.[cm]?[jt]s$/;

export function readMiddlewareAuth(files: CodeFile[]): MiddlewareAuth | null {
  const file = files.find((f) => MIDDLEWARE_FILE.test(f.path.replace(/\\/g, '/').replace(/^\.\//, '')));
  if (!file) return null;
  const src = file.content || '';
  const nextAuth = /export\s*\{\s*default\s*\}\s*from\s*['"]next-auth\/middleware['"]|export\s+default\s+(?:withAuth|auth)\b/.test(src);
  const clerk = /clerkMiddleware\s*\(/.test(src) && /\.protect\s*\(/.test(src);
  // Hand-written: reads the session and redirects / rejects when it is missing
  const manual = /\b(?:getUser|getSession|getToken|auth|verify\w*|jwtVerify)\s*\(/.test(src)
    && /NextResponse\.redirect\s*\(|status\s*:\s*401|new\s+(?:Next)?Response\s*\([^)]*401/.test(src);
  if (!nextAuth && !clerk && !manual) return null;

  const auth: MiddlewareAuth = { matchers: [], protectOnly: null, publicExcept: null, skipPrefixes: [] };
  const cfg = /\bmatcher\s*:\s*(\[[\s\S]*?\]|(['"`])[^'"`]*\2)/.exec(src);
  if (cfg) {
    for (const p of stringArray(cfg[1])) {
      const re = matcherToRegExp(p);
      if (!re) return null; // a matcher we cannot read: do not guess which routes are covered
      auth.matchers.push(re);
    }
  }
  if (clerk) {
    for (const m of src.matchAll(/(?:const|let)\s+(\w+)\s*=\s*createRouteMatcher\s*\(\s*(\[[\s\S]*?\])\s*\)/g)) {
      const res = stringArray(m[2]).map(matcherToRegExp);
      if (res.some((r) => !r)) return null;
      const negated = new RegExp(String.raw`!\s*${m[1]}\s*\(`).test(src);
      if (negated) auth.publicExcept = res as RegExp[];
      else auth.protectOnly = res as RegExp[];
    }
    // clerkMiddleware() with protect() only inside an unknown condition: unclear coverage
    if (!auth.protectOnly && !auth.publicExcept && !/clerkMiddleware\s*\(\s*(?:async\s*)?\(\s*auth[^)]*\)\s*=>\s*\{?\s*(?:await\s+)?auth\s*(?:\(\s*\))?\.protect\s*\(/.test(src)) return null;
  }
  for (const m of src.matchAll(/pathname\.startsWith\(\s*(['"`])([^'"`]+)\1/g)) auth.skipPrefixes.push(m[2]);
  return auth;
}

/** `app/(dash)/api/teams/[id]/route.ts` -> `/api/teams/x`; `pages/api/me.ts` -> `/api/me`. */
export function routePathOf(filePath: string): string | null {
  const p = filePath.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^src\//, '');
  let m = /^app\/(.*?)\/?route\.[cm]?[jt]sx?$/.exec(p);
  let route = m ? m[1] : null;
  if (route === null) {
    m = /^pages\/(api\/.*?)(?:\/index)?\.[cm]?[jt]sx?$/.exec(p);
    route = m ? m[1] : null;
  }
  if (route === null) return null;
  const segs = route.split('/').filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'))
    .map((s) => (/^\[.*\]$/.test(s) ? 'x' : s));
  return `/${segs.join('/')}`;
}

export function middlewareAuthenticates(auth: MiddlewareAuth | null, routePath: string | null): boolean {
  if (!auth || !routePath) return false;
  if (auth.matchers.length && !auth.matchers.some((r) => r.test(routePath))) return false;
  if (auth.skipPrefixes.some((p) => routePath.startsWith(p))) return false;
  if (auth.protectOnly && !auth.protectOnly.some((r) => r.test(routePath))) return false;
  if (auth.publicExcept && auth.publicExcept.some((r) => r.test(routePath))) return false;
  return true;
}

export function buildCrossFileAuth(files: CodeFile[]): CrossFileAuth {
  return { authHelpers: buildAuthHelperIndex(files), middleware: readMiddlewareAuth(files) };
}
