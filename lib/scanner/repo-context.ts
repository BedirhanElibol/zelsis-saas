import type { CodeFile } from './types';

/**
 * Facts that span files, computed once before per-file rules run
 * (per-file rules cannot see that a later migration fixed an earlier one).
 */
export interface RepoContext {
  /** SQL functions given an explicit search_path anywhere in the repo (ALTER FUNCTION or a redefinition with SET search_path). */
  hardenedSqlFunctions: Set<string>;
  /** Tables with ROW LEVEL SECURITY enabled in any migration. */
  rlsEnabledTables: Set<string>;
  /**
   * The database is reachable directly from clients (Supabase / PostgREST, or grants to anon/authenticated),
   * so tables without RLS are exposed. Apps that only reach Postgres through their own server do not need RLS.
   */
  exposesDatabaseToClients: boolean;
  /** Some file serves a health / liveness / readiness route, so per-file "missing health check" rules stay quiet. */
  hasHealthEndpoint: boolean;
  /**
   * Major version of `next` pinned in the repo's package.json files (the lowest one when several apps disagree),
   * or null when no package.json pins a numeric version (single-file scans, `latest`, no Next.js).
   */
  nextMajorVersion: number | null;
  /** Modules whose first statement is 'use client', as repo paths without extension (`components/user-card`, plus the folder for index files). */
  clientComponentModules: Set<string>;
  /**
   * Secret-bearing columns per model / table (Prisma models and @@map names, SQL CREATE TABLE, Drizzle tables),
   * keyed by lower-cased model, table and Drizzle variable name: `user` -> ['passwordHash'].
   */
  sensitiveColumnsByModel: Map<string, string[]>;
}

/** Normalises `"public"."fn"` / `public.fn` / `fn` to `fn`. */
export const normalizeSqlName = (name: string): string => name.replace(/"/g, '').toLowerCase().split('.').pop() ?? '';

/** A route string such as '/health', '/api/healthz', '/livez' or '/readyz'. */
const HEALTH_ROUTE = /['"`]\/(?:api\/)?(?:health(?:z|check)?|livez?|liveness|readyz?|readiness)\b/i;

export function buildRepoContext(files: CodeFile[]): RepoContext {
  const hardenedSqlFunctions = new Set<string>();
  const rlsEnabledTables = new Set<string>();
  let exposesDatabaseToClients = false;
  let hasHealthEndpoint = false;
  let nextMajorVersion: number | null = null;
  for (const file of files) {
    if (!hasHealthEndpoint && HEALTH_ROUTE.test(file.content || '')) hasHealthEndpoint = true;
    const path = (file.path || '').replace(/\\/g, '/');
    if (/(?:^|\/)supabase\/(?:config\.toml|migrations\/)/i.test(path) || /postgrest\.conf$/i.test(path) ||
        (/(?:^|\/)package\.json$/.test(path) && /"@supabase\/(?:supabase-js|ssr|auth-helpers-\w+)"/.test(file.content || ''))) {
      exposesDatabaseToClients = true;
    }
    if (/(?:^|\/)package\.json$/.test(path) && !/node_modules\//.test(path)) {
      const pin = /"next"\s*:\s*"(?:npm:next@)?[\^~>=v\s]*(\d+)\b/.exec(file.content || '');
      if (pin) nextMajorVersion = nextMajorVersion === null ? Number(pin[1]) : Math.min(nextMajorVersion, Number(pin[1]));
    }
    if (/\.sql$/i.test(path)) {
      const sql = file.content || '';
      if (/GRANT[^;]*\bTO\s+(?:anon|authenticated|web_anon)\b/i.test(sql)) exposesDatabaseToClients = true;
      for (const m of sql.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)) {
        rlsEnabledTables.add(normalizeSqlName(m[1]));
      }
    }
    if (!/\.sql$/i.test(file.path || '')) continue;
    for (const m of (file.content || '').matchAll(/ALTER\s+FUNCTION\s+([\w."]+)\s*(?:\([^)]*\))?\s+SET\s+search_path/gi)) {
      hardenedSqlFunctions.add(normalizeSqlName(m[1]));
    }
    // A later CREATE OR REPLACE that sets search_path also hardens the function
    for (const m of (file.content || '').matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)[\s\S]*?(?:\$\$|\$\w+\$)[\s\S]*?(?:\$\$|\$\w+\$)[^;]*;?/gi)) {
      if (/SET\s+search_path/i.test(m[0])) hardenedSqlFunctions.add(normalizeSqlName(m[1]));
    }
  }
  return { hardenedSqlFunctions, rlsEnabledTables, exposesDatabaseToClients, hasHealthEndpoint, nextMajorVersion, ...collectServerClientFacts(files) };
}

/** Column names that hold credentials or secrets (password hashes, tokens, API keys, TOTP seeds). */
const SENSITIVE_COLUMN = /^(?:\w*(?:password|passwd|secret|token|api_?key|private_?key)|password_?(?:hash|digest|salt)|hash(?:ed)?_?password|hash|salt|totp(?:_?(?:seed|key))?)$/i;

const stripModuleExt = (p: string): string => p.replace(/\.(?:[cm]?[jt]sx?)$/i, '');

/** 'use client' as the first statement (after leading comments / blank lines). */
const startsWithUseClient = (content: string): boolean =>
  /^\s*['"]use client['"]/.test(content.replace(/^(?:\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/))*/, ''));

function collectServerClientFacts(files: CodeFile[]): Pick<RepoContext, 'clientComponentModules' | 'sensitiveColumnsByModel'> {
  const clientComponentModules = new Set<string>();
  const sensitiveColumnsByModel = new Map<string, string[]>();
  const addSensitive = (keys: string[], cols: string[]) => {
    if (!cols.length) return;
    for (const k of keys) {
      const key = k.toLowerCase();
      sensitiveColumnsByModel.set(key, [...new Set([...(sensitiveColumnsByModel.get(key) || []), ...cols])]);
    }
  };
  for (const file of files) {
    const path = (file.path || '').replace(/\\/g, '/');
    const content = file.content || '';
    if (/node_modules\//.test(path)) continue;
    if (/\.[cm]?[jt]sx?$/i.test(path) && startsWithUseClient(content)) {
      const mod = stripModuleExt(path);
      clientComponentModules.add(mod);
      if (/\/index$/.test(mod)) clientComponentModules.add(mod.replace(/\/index$/, ''));
    }
    if (/\.prisma$/i.test(path)) {
      for (const m of content.matchAll(/^\s*model\s+(\w+)\s*\{([\s\S]*?)^\s*\}/gm)) {
        const cols = [...m[2].matchAll(/^\s*(\w+)\s+(?:String|Bytes)\??(?:\s|$)/gm)].map((c) => c[1]).filter((c) => SENSITIVE_COLUMN.test(c));
        const mapped = /@@map\(\s*(?:name\s*:\s*)?["'](\w+)["']/.exec(m[2]);
        addSensitive(mapped ? [m[1], mapped[1]] : [m[1]], cols);
      }
    } else if (/\.sql$/i.test(path)) {
      for (const m of content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(([\s\S]*?)\)\s*;/gi)) {
        const cols = [...m[2].matchAll(/(?:^|,)\s*"?(\w+)"?\s+[a-z]/gim)].map((c) => c[1]).filter((c) => SENSITIVE_COLUMN.test(c));
        addSensitive([normalizeSqlName(m[1])], cols);
      }
      for (const m of content.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?/gi)) {
        if (SENSITIVE_COLUMN.test(m[2])) addSensitive([normalizeSqlName(m[1])], [m[2]]);
      }
    } else if (/\.[cm]?[jt]s$/i.test(path) && /(?:pg|mysql|sqlite)Table\s*\(/.test(content)) {
      for (const m of content.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(?:pg|mysql|sqlite)Table\s*\(\s*['"](\w+)['"]\s*,\s*\{([\s\S]*?)\n\s*\}/g)) {
        const cols = [...m[3].matchAll(/^\s*(\w+)\s*:/gm)].map((c) => c[1]).filter((c) => SENSITIVE_COLUMN.test(c));
        addSensitive([m[1], m[2]], cols);
      }
    }
  }
  return { clientComponentModules, sensitiveColumnsByModel };
}

/** Without repo-wide knowledge, assume the database may be exposed (single-file scans keep RLS checks on). */
export const emptyRepoContext = (): RepoContext => ({ hardenedSqlFunctions: new Set(), rlsEnabledTables: new Set(), exposesDatabaseToClients: true, hasHealthEndpoint: false, nextMajorVersion: null, clientComponentModules: new Set(), sensitiveColumnsByModel: new Map() });
