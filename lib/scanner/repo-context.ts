import type { CodeFile } from './types';

/**
 * Facts that span files, computed once before per-file rules run
 * (per-file rules cannot see that a later migration fixed an earlier one).
 */
export interface RepoContext {
  /** SQL functions given an explicit search_path anywhere in the repo (ALTER FUNCTION or a redefinition with SET search_path). */
  hardenedSqlFunctions: Set<string>;
}

/** Normalises `"public"."fn"` / `public.fn` / `fn` to `fn`. */
export const normalizeSqlName = (name: string): string => name.replace(/"/g, '').toLowerCase().split('.').pop() ?? '';

export function buildRepoContext(files: CodeFile[]): RepoContext {
  const hardenedSqlFunctions = new Set<string>();
  for (const file of files) {
    if (!/\.sql$/i.test(file.path || '')) continue;
    for (const m of (file.content || '').matchAll(/ALTER\s+FUNCTION\s+([\w."]+)\s*(?:\([^)]*\))?\s+SET\s+search_path/gi)) {
      hardenedSqlFunctions.add(normalizeSqlName(m[1]));
    }
    // A later CREATE OR REPLACE that sets search_path also hardens the function
    for (const m of (file.content || '').matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)[\s\S]*?(?:\$\$|\$\w+\$)[\s\S]*?(?:\$\$|\$\w+\$)[^;]*;?/gi)) {
      if (/SET\s+search_path/i.test(m[0])) hardenedSqlFunctions.add(normalizeSqlName(m[1]));
    }
  }
  return { hardenedSqlFunctions };
}

export const emptyRepoContext = (): RepoContext => ({ hardenedSqlFunctions: new Set() });
