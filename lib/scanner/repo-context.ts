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
}

/** Normalises `"public"."fn"` / `public.fn` / `fn` to `fn`. */
export const normalizeSqlName = (name: string): string => name.replace(/"/g, '').toLowerCase().split('.').pop() ?? '';

export function buildRepoContext(files: CodeFile[]): RepoContext {
  const hardenedSqlFunctions = new Set<string>();
  const rlsEnabledTables = new Set<string>();
  let exposesDatabaseToClients = false;
  for (const file of files) {
    const path = (file.path || '').replace(/\\/g, '/');
    if (/(?:^|\/)supabase\/(?:config\.toml|migrations\/)/i.test(path) || /postgrest\.conf$/i.test(path) ||
        (/(?:^|\/)package\.json$/.test(path) && /"@supabase\/(?:supabase-js|ssr|auth-helpers-\w+)"/.test(file.content || ''))) {
      exposesDatabaseToClients = true;
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
  return { hardenedSqlFunctions, rlsEnabledTables, exposesDatabaseToClients };
}

/** Without repo-wide knowledge, assume the database may be exposed (single-file scans keep RLS checks on). */
export const emptyRepoContext = (): RepoContext => ({ hardenedSqlFunctions: new Set(), rlsEnabledTables: new Set(), exposesDatabaseToClients: true });
