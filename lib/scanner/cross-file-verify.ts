/**
 * Second look before a route-level "no authentication" finding is reported: the check may live in another file.
 * - middleware.ts / proxy.ts authenticates the route (config.matcher, Clerk route matchers, skipped prefixes);
 * - the handler calls an imported helper that authenticates (requireUser() in lib/auth.ts calls auth()).
 * A guarded finding is dropped and the reason is kept, so the report can say what was verified.
 * - the webhook handler hands the payload to an imported module that verifies the signature.
 * Only ever removes findings of the rules below; everything else passes through unchanged.
 */
import type { CrossFileAuth } from './ast/cross-file';
import { middlewareAuthenticates, resolveImport, routePathOf } from './ast/cross-file';

/** Rules that report a route as reachable without authentication: middleware or an imported auth helper clears them. */
export const ROUTE_AUTH_RULES: ReadonlySet<number> = new Set([
  15, // Unauthenticated API mutation route handler
  23006, // SAAS-06: cron endpoint without a secret check
  28002, // NEXT-SB-02: route handler writes with the service-role client without verifying the caller
  8143, // ZERO-AUTH-43: a route that signs the user in is a webhook settings screen, not a third-party receiver
]);

/** Webhook rules cleared when the handler passes the payload to an imported module that verifies the signature. */
export const WEBHOOK_VERIFY_RULES: ReadonlySet<number> = new Set([
  9704, // FINTECH-04: payment webhook without signature verification
  8143, // ZERO-AUTH-43: webhook receiver without identity verification
]);

/** Mass-assignment rules cleared when the handler passes req.body to an imported module that validates with a strict Joi/Zod schema. */
export const SCHEMA_VALIDATED_RULES: ReadonlySet<number> = new Set([
  25001, // SEC-API-01: Mass Assignment via Unvalidated Request Body
]);

/**
 * Rules where only an imported auth helper counts. Server Actions post to the page's own URL, so a middleware
 * matcher written for /api routes says nothing about them.
 */
export const HELPER_AUTH_RULES: ReadonlySet<number> = new Set([
  28001, // NEXT-SB-01: Server Action writes with the service-role client without verifying the caller
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

const DEFAULT_IMPORT_RE = /import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"]([^'"]+)['"]/g;
const CJS_REQUIRE_RE = /(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^}]*\})\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

/** An imported binding from a module that verifies webhook signatures, called here (BillingService.handleWebhook(body, sig)). */
export function calledWebhookVerifier(filePath: string, content: string, cross: CrossFileAuth): { name: string; from: string } | null {
  for (const re of [IMPORT_RE, DEFAULT_IMPORT_RE]) {
    for (const m of content.matchAll(re)) {
      if (!resolveImport(filePath, m[2]).some((k) => cross.webhookVerifiers.has(k))) continue;
      const names = re === IMPORT_RE ? m[1].split(',').map((p) => p.trim().split(/\s+as\s+/).pop()!.trim()) : [m[1]];
      const rest = content.slice(m.index! + m[0].length);
      const local = names.find((n) => n && new RegExp(String.raw`\b${n.replace(/\$/g, '\\$')}\s*(?:\.\s*\w+\s*)?\(`).test(rest));
      if (local) return { name: local, from: m[2] };
    }
  }
  return null;
}

/** An imported binding from a module that validates payloads with a strict Joi/Zod schema, called with req.body/body (userCtrl.insert(req.body)). */
export function calledSchemaValidator(filePath: string, content: string, cross: CrossFileAuth): { name: string; from: string } | null {
  if (!cross.schemaValidators || cross.schemaValidators.size === 0) return null;
  for (const re of [IMPORT_RE, DEFAULT_IMPORT_RE, CJS_REQUIRE_RE]) {
    for (const m of content.matchAll(re)) {
      const spec = m[2];
      if (!resolveImport(filePath, spec).some((k) => cross.schemaValidators.has(k))) continue;
      const rawBinding = m[1].trim();
      const names = rawBinding.startsWith('{') || re === IMPORT_RE
        ? rawBinding.replace(/^\{|\}$/g, '').split(',').map((p) => p.trim().split(/\s+(?:as|:)\s+/).pop()!.trim())
        : [rawBinding];
      const rest = content.slice(m.index! + m[0].length);
      const local = names.find((n) => n && new RegExp(String.raw`\b${n.replace(/\$/g, '\\$')}\s*(?:\.\s*\w+\s*)?\(\s*(?:req\.body|body|await\s+(?:req|request)\.json\(\))`).test(rest));
      if (local) return { name: local, from: spec };
    }
  }
  return null;
}

/** Why this route-level finding is guarded elsewhere, or null when nothing was found. */
export function guardElsewhere(ruleId: number, filePath: string, content: string, cross: CrossFileAuth): string | null {
  if (SCHEMA_VALIDATED_RULES.has(ruleId)) {
    const validator = calledSchemaValidator(filePath, content, cross);
    if (validator) return `the handler passes the request body to ${validator.name} from ${validator.from}, which validates the payload with a schema`;
  }
  if (WEBHOOK_VERIFY_RULES.has(ruleId)) {
    const verifier = calledWebhookVerifier(filePath, content, cross);
    if (verifier) return `the handler passes the request to ${verifier.name} from ${verifier.from}, which verifies the webhook signature`;
  }
  const routeRule = ROUTE_AUTH_RULES.has(ruleId);
  if (!routeRule && !HELPER_AUTH_RULES.has(ruleId)) return null;
  const route = routePathOf(filePath);
  if (routeRule && middlewareAuthenticates(cross.middleware, route)) return `middleware authenticates ${route} before the handler runs`;
  const helper = calledAuthHelper(filePath, content, cross);
  if (helper) return `the handler calls ${helper.name}() from ${helper.from}, which authenticates the caller`;
  return null;
}
