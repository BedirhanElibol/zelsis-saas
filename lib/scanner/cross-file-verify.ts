/**
 * Second look before a route-level "no authentication" finding is reported: the check may live in another file.
 * - middleware.ts / proxy.ts authenticates the route (config.matcher, Clerk route matchers, skipped prefixes);
 * - the handler calls an imported helper that authenticates (requireUser() in lib/auth.ts calls auth()).
 * A guarded finding is dropped and the reason is kept, so the report can say what was verified.
 * Only ever removes findings of the rules below; everything else passes through unchanged.
 */
import type { CrossFileAuth } from './ast/cross-file';
import { middlewareAuthenticates, resolveImport, routePathOf } from './ast/cross-file';

/** Rules that report a route as reachable without authentication. */
export const ROUTE_AUTH_RULES: ReadonlySet<number> = new Set([
  15, // Unauthenticated API mutation route handler
  23006, // SAAS-06: cron endpoint without a secret check
]);

export interface CrossFileVerification {
  ruleId: number;
  filePath: string;
  reason: string;
}

const IMPORT_RE = /import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g;

/** Name of an imported helper that authenticates and is called in this file, or null. */
export function calledAuthHelper(filePath: string, content: string, cross: CrossFileAuth): { name: string; from: string } | null {
  for (const m of content.matchAll(IMPORT_RE)) {
    const keys = resolveImport(filePath, m[2]);
    if (keys.length === 0) continue;
    for (const part of m[1].split(',')) {
      const [imported, local = imported] = part.trim().split(/\s+as\s+/).map((s) => s.trim());
      if (!imported) continue;
      if (!keys.some((k) => cross.authHelpers.get(k)?.has(imported))) continue;
      if (new RegExp(String.raw`\b${local.replace(/\$/g, '\\$')}\s*\(`).test(content.slice(m.index! + m[0].length))) {
        return { name: local, from: m[2] };
      }
    }
  }
  return null;
}

/** Why this route-level finding is guarded elsewhere, or null when nothing was found. */
export function guardElsewhere(ruleId: number, filePath: string, content: string, cross: CrossFileAuth): string | null {
  if (!ROUTE_AUTH_RULES.has(ruleId)) return null;
  const route = routePathOf(filePath);
  if (middlewareAuthenticates(cross.middleware, route)) return `middleware authenticates ${route} before the handler runs`;
  const helper = calledAuthHelper(filePath, content, cross);
  if (helper) return `the handler calls ${helper.name}() from ${helper.from}, which authenticates the caller`;
  return null;
}
