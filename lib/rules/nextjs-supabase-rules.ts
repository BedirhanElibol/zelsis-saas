/**
 * Next.js App Router, Server Actions, middleware and Supabase auth/storage misuse (NEXT-SB-xx, Rule IDs 28001-28099).
 *
 * Sources: Next.js advisories (CVE-2025-57822 middleware header SSRF, CVE-2025-66478 / CVE-2025-55182 React2Shell),
 * Next.js docs (images.remotePatterns, dangerouslyAllowSVG, serverActions.allowedOrigins, cookies()),
 * Supabase docs and database linter (rls_references_user_metadata, security_definer_view, storage ownership,
 * service-role keys must never run on behalf of an unverified caller).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { AUTH_GUARD, WEBHOOK_VERIFY } from './shared/stack-signals';
import { emptyRepoContext, normalizeSqlName, type RepoContext } from '../scanner/repo-context';

interface Hit {
  ruleId: number;
  code: string;
  title: string;
  severity: Finding['severity'];
  type: Finding['type'];
  category: string;
  lineIdx: number;
  why: string;
  fix: string;
}

const isCodeFile = (p: string) => /\.[cm]?[jt]sx?$/i.test(p);
const isRouteHandler = (p: string) => /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]s$|(?:^|\/)pages\/api\//i.test(p);
const hasUseServerDirective = (c: string) => /^\s*['"]use server['"]/m.test(c.split('\n').filter((l) => l.trim()).slice(0, 3).join('\n'));
const hasUseClientDirective = (c: string) => /^\s*['"]use client['"]/m.test(c.split('\n').filter((l) => l.trim()).slice(0, 3).join('\n'));
const isServerCode = (p: string, c: string) =>
  isRouteHandler(p) || /(?:^|\/)(?:middleware|proxy)\.[jt]s$/i.test(p) || /['"]use server['"]/.test(c) ||
  ((/(?:^|\/)app\//i.test(p) || /(?:^|\/)(?:lib|utils|server)\//i.test(p)) && !hasUseClientDirective(c));

const lineAt = (content: string, offset: number) => content.slice(0, Math.max(0, offset)).split('\n').length - 1;

/** Blank out SQL `--` comments while keeping line numbers. */
const stripSqlComments = (sql: string) => sql.replace(/--[^\n]*/g, '');

// ─── Function body extraction (regex scanner, no AST) ──────────────────────────────────────

/** Index of the bracket that closes the one at `open`, skipping string and template literals. */
function matchClose(src: string, open: number, o: string, c: string): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const q = ch;
      for (i++; i < src.length && src[i] !== q; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (ch === o) depth++;
    else if (ch === c && --depth === 0) return i;
  }
  return -1;
}

interface FnBlock { name: string; declOffset: number; body: string; bodyOffset: number }

/** Exported functions (and inline 'use server' functions) with their bodies. */
function functionBlocks(src: string, opts: { exportedOnly: boolean }): FnBlock[] {
  const out: FnBlock[] = [];
  const decl = /(export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(\w*)\s*(?:<[^>(]*>)?\s*\(|(export\s+)?const\s+(\w+)\s*(?::[^=]+)?=\s*async\s*(?:\w+\s*=>|\()/g;
  for (const m of src.matchAll(decl)) {
    const exported = Boolean(m[1] || m[3]);
    const name = m[2] || m[4] || 'default';
    let cursor: number;
    if (m[0].endsWith('(')) {
      const close = matchClose(src, m.index! + m[0].length - 1, '(', ')');
      if (close === -1) continue;
      cursor = close + 1;
    } else {
      cursor = m.index! + m[0].length; // `async x =>`
    }
    // Skip a return type annotation (may contain generics like Promise<{ ok: boolean }>)
    let angle = 0;
    let bodyOpen = -1;
    for (let i = cursor; i < src.length; i++) {
      const ch = src[i];
      if (ch === '=' && src[i + 1] === '>') { i++; continue; }
      if (ch === '<') angle++;
      else if (ch === '>') angle--;
      else if (ch === '{' && angle <= 0) { bodyOpen = i; break; }
      else if (ch === ';' && angle <= 0) break;
    }
    if (bodyOpen === -1) continue;
    const bodyClose = matchClose(src, bodyOpen, '{', '}');
    if (bodyClose === -1) continue;
    const body = src.slice(bodyOpen + 1, bodyClose);
    const inlineAction = /^\s*['"]use server['"]/.test(body);
    if (opts.exportedOnly ? (exported || inlineAction) : true) {
      out.push({ name, declOffset: m.index!, body, bodyOffset: bodyOpen + 1 });
    }
  }
  return out;
}

// ─── Shared signals ───────────────────────────────────────────────────────────────────────

/** Caller verification inside a handler body: provider calls, local auth helpers, signed webhooks, cron secrets. */
const CALLER_CHECK = new RegExp([
  AUTH_GUARD.source,
  WEBHOOK_VERIFY.source,
  String.raw`\b(?:get|require|ensure|assert|verify|check|validate|protect|authorize|with)\w*(?:User|Auth|Session|Admin|Owner|Member|Role|Permission|Access|Viewer|Claims)\w*\s*\(`,
  String.raw`CRON_SECRET|headers\.get\(\s*['"](?:authorization|x-api-key)['"]|headers\[\s*['"](?:authorization|x-api-key)['"]\s*\]`
].join('|'), 'i');

const ADMIN_FACTORY = String.raw`(?:createAdminClient|createServiceRoleClient|createServiceClient|createSupabaseAdmin\w*|getSupabaseAdmin|getServiceSupabase|getAdminClient|supabaseAdminClient)\s*\(\s*\)`;
const SERVICE_KEY = String.raw`process\.env\.(?:\w*SERVICE_ROLE\w*|SUPABASE_SECRET_KEY|SUPABASE_SERVICE_KEY)`;

/** Identifiers bound to a Supabase client that bypasses RLS. */
function adminClientNames(src: string): Set<string> {
  const names = new Set<string>(['supabaseAdmin', 'adminSupabase', 'supabaseServiceRole', 'serviceSupabase', 'supabaseAdminClient']);
  for (const m of src.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:createClient(?:<[^>]*>)?\s*\([^,]+,\s*` + SERVICE_KEY + '|' + ADMIN_FACTORY + ')', 'g'))) {
    names.add(m[1]);
  }
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"][^'"]*\/admin['"]/g)) {
    for (const part of m[1].split(',')) {
      const local = part.split(/\s+as\s+/).pop()?.trim();
      if (local && /^\w+$/.test(local) && /admin|service/i.test(local) && !/^create|^get/.test(local)) names.add(local);
    }
  }
  return names;
}

/** Offset of a privileged (RLS-bypassing) write in `body`, or -1. */
function privilegedWrite(body: string, admins: Set<string>): number {
  const ids = [...admins].join('|');
  const client = String.raw`(?:\b(?:` + ids + String.raw`)\b|` + ADMIN_FACTORY + ')';
  const patterns = [
    new RegExp(client + String.raw`\s*\.\s*from\s*\([^)]*\)\s*\.\s*(?:insert|update|upsert|delete)\s*\(`),
    new RegExp(client + String.raw`\s*\.\s*storage\s*\.\s*from\s*\([^)]*\)\s*\.\s*(?:remove|upload|move|update)\s*\(`),
    new RegExp(client + String.raw`\s*\.\s*rpc\s*\(`),
    /\.auth\.admin\.(?:deleteUser|updateUserById|createUser|inviteUserByEmail|generateLink|signOut|mfa\.deleteFactor)\s*\(/
  ];
  let best = -1;
  for (const re of patterns) {
    const m = re.exec(body);
    if (m && (best === -1 || m.index < best)) best = m.index;
  }
  return best;
}

/** Local names bound to request input (`await req.json()`, `formData.get()`, `searchParams.get()`). */
function requestBoundNames(src: string): { names: Set<string>; objects: Set<string> } {
  const names = new Set<string>();
  const objects = new Set<string>();
  const source = String.raw`(?:await\s+)?(?:req|request)\.(?:json|formData)\(\)|Object\.fromEntries\(\s*formData\s*\)`;
  for (const m of src.matchAll(new RegExp(String.raw`(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:` + source + ')', 'g'))) {
    for (const part of m[1].split(',')) {
      const local = part.split('=')[0].split(':').pop()?.trim();
      if (local && /^\w+$/.test(local)) names.add(local);
    }
  }
  for (const m of src.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*(?:` + source + ')', 'g'))) objects.add(m[1]);
  for (const m of src.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*(?:String\(\s*|Number\(\s*)?(?:\w+\.)?(?:formData|searchParams)\.get\(/g)) names.add(m[1]);
  return { names, objects };
}

const isRequestExpr = (expr: string, req: ReturnType<typeof requestBoundNames>) => {
  const e = expr.trim().replace(/\s+as\s+\w+$/, '');
  const root = e.split(/[.\s[(?!]/)[0];
  return req.names.has(e) || (req.objects.has(root) && e !== root) ||
    /^(?:String\(|Number\()?\s*(?:\w+\.)?(?:formData|searchParams)\.get\(|^(?:req|request)\.(?:body|query)\./.test(e);
};

// ─── React2Shell (CVE-2025-66478 / CVE-2025-55182) ────────────────────────────────────────

/** First patched patch release per 15.x / 16.0 minor line. */
const REACT2SHELL_FIXED: Record<string, number> = { '15.0': 5, '15.1': 9, '15.2': 6, '15.3': 6, '15.4': 8, '15.5': 7, '16.0': 7 };

function react2ShellVulnerable(version: string): boolean {
  const m = version.match(/(\d+)\.(\d+)\.(\d+)(?:-canary\.(\d+))?/);
  if (!m) return false;
  const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const canary = m[4] !== undefined ? Number(m[4]) : null;
  if (canary !== null) {
    if (major === 14 && minor === 3) return canary >= 77;
    if (major === 15 && minor === 6) return canary < 58;
    if (major === 16 && minor === 1) return canary < 12;
  }
  const fixed = REACT2SHELL_FIXED[`${major}.${minor}`];
  return fixed !== undefined && patch < fixed;
}

// ─── Engine ───────────────────────────────────────────────────────────────────────────────

export function evaluateNextjsSupabaseRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context: RepoContext = emptyRepoContext()): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const lowerPath = path.toLowerCase();
  if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) return { findings, logs };
  const hits: Hit[] = [];

  if (isCodeFile(path)) {
    const isNextConfig = /(?:^|\/)next\.config\.[cm]?[jt]s$/i.test(path);
    const admins = adminClientNames(cleanContent);
    const useServerFile = hasUseServerDirective(cleanContent);

    // NEXT-SB-01: Server Action writes with the service-role client without verifying the caller
    if (useServerFile || /['"]use server['"]/.test(cleanContent)) {
      for (const fn of functionBlocks(cleanContent, { exportedOnly: true })) {
        const isAction = useServerFile ? true : /^\s*['"]use server['"]/.test(fn.body);
        if (!isAction) continue;
        const writeAt = privilegedWrite(fn.body, admins);
        if (writeAt === -1 || CALLER_CHECK.test(fn.body)) continue;
        hits.push({
          ruleId: 28001, code: 'NEXT-SB-01', severity: 'CRITICAL', type: 'SECURITY', category: 'Access Control',
          title: 'Server Action Uses the Service-Role Client Without Verifying the Caller',
          lineIdx: lineAt(cleanContent, fn.bodyOffset + writeAt),
          why: `Server Action \`${fn.name}\` is a public POST endpoint (its ID is in the client bundle) and writes through a client that bypasses Row Level Security, but never checks who is calling. Anyone can invoke it with arbitrary arguments.`,
          fix: `Call supabase.auth.getUser() (or your auth helper) at the top of \`${fn.name}\`, return early when there is no user, and scope the write to that user; prefer the cookie-based SSR client so RLS still applies.`
        });
        break;
      }
    }

    // NEXT-SB-02: Route handler writes with the service-role client / auth.admin without verifying the caller
    if (isRouteHandler(lowerPath)) {
      for (const fn of functionBlocks(cleanContent, { exportedOnly: true })) {
        if (!/^(?:GET|POST|PUT|PATCH|DELETE|default|handler)$/.test(fn.name)) continue;
        const writeAt = privilegedWrite(fn.body, admins);
        if (writeAt === -1 || CALLER_CHECK.test(fn.body)) continue;
        hits.push({
          ruleId: 28002, code: 'NEXT-SB-02', severity: 'CRITICAL', type: 'SECURITY', category: 'Access Control',
          title: 'Route Handler Uses the Service-Role Client Without Verifying the Caller',
          lineIdx: lineAt(cleanContent, fn.bodyOffset + writeAt),
          why: `The ${fn.name} handler performs a privileged write (service-role client or auth.admin) that bypasses Row Level Security, with no session, signature or secret check, so any anonymous request can modify data or user accounts.`,
          fix: 'Verify the caller first (supabase.auth.getUser(), a webhook signature, or a constant-time secret check) and reject unauthenticated requests before using the admin client.'
        });
        break;
      }
    }

    // NEXT-SB-03: authorization decided from user_metadata (user-editable)
    if (isServerCode(lowerPath, cleanContent)) {
      const metaRole = /\buser_metadata\s*\??\.\s*\??\[?\s*['"]?(role|roles|is_admin|isAdmin|admin|is_super_admin|permissions|plan|tier|subscription_tier|is_pro|isPro|is_premium|isPremium|credits)\b/;
      const idx = lines.findIndex((l) => metaRole.test(l) && /===|!==|==|!=|\.includes\(|\bif\s*\(|&&|\|\||^\s*return\b|\?[^.?]/.test(l));
      if (idx !== -1) {
        const key = lines[idx].match(metaRole)?.[1] ?? 'role';
        hits.push({
          ruleId: 28003, code: 'NEXT-SB-03', severity: 'HIGH', type: 'SECURITY', category: 'Authorization',
          title: 'Authorization Decision Based on Supabase user_metadata',
          lineIdx: idx,
          why: `user_metadata.${key} is writable by the signed-in user (supabase.auth.updateUser({ data: { ${key}: ... } })), so any user can grant themselves this privilege.`,
          fix: 'Store roles/plans in app_metadata (only settable with the service role) or in a table the user cannot update, and authorize from that.'
        });
      }
    }

    // NEXT-SB-08: request headers passed as response headers in middleware (CVE-2025-57822)
    {
      const headerVars = new Set<string>();
      for (const m of cleanContent.matchAll(/(?:const|let)\s+(\w+)\s*=\s*new\s+Headers\(\s*(?:req|request)\.headers\s*\)/g)) headerVars.add(m[1]);
      const src = String.raw`(?:(?:req|request)\.headers|new\s+Headers\(\s*(?:req|request)\.headers\s*\)` + (headerVars.size ? '|' + [...headerVars].join('|') : '') + String.raw`)\b`;
      const re = new RegExp(String.raw`NextResponse\.(?:next|rewrite)\s*\((?:[^(){}]*,)?\s*\{[^{}]*?\bheaders\s*:\s*` + src);
      const m = re.exec(cleanContent);
      if (m) {
        hits.push({
          ruleId: 28008, code: 'NEXT-SB-08', severity: 'HIGH', type: 'SECURITY', category: 'Server-Side Request Forgery',
          title: 'Middleware Passes Request Headers as Response Headers (CVE-2025-57822)',
          lineIdx: lineAt(cleanContent, m.index + m[0].search(/\bheaders\s*:/)),
          why: 'NextResponse.next({ headers: request.headers }) copies every client-supplied header (including Location and cookies) onto the response; on self-hosted Next.js a forged Location header triggers a server-side fetch (SSRF), and it reflects request headers back to the client.',
          fix: 'Forward modified headers upstream with NextResponse.next({ request: { headers: requestHeaders } }) and upgrade to next 14.2.32+ / 15.4.7+.'
        });
      }
    }

    // NEXT-SB-09 / 10 / 11: next.config hardening
    if (isNextConfig) {
      const anyHostIdx = lines.findIndex((l) => /\bhostname\s*:\s*['"]\*\*['"]|new\s+URL\(\s*['"]https?:\/\/\*\*/.test(l));
      if (anyHostIdx !== -1 && /remotePatterns/.test(cleanContent)) {
        hits.push({
          ruleId: 28009, code: 'NEXT-SB-09', severity: 'MEDIUM', type: 'SECURITY', category: 'Server-Side Request Forgery',
          title: "Image Optimizer Allows Any Remote Host (remotePatterns hostname '**')",
          lineIdx: anyHostIdx,
          why: "With hostname '**' /_next/image fetches and re-serves images from any server on the internet, turning your deployment into an open image proxy (bandwidth/cost abuse, content served from your domain) and maximising exposure to image-optimizer CVEs.",
          fix: "List the exact hosts you serve images from (e.g. { protocol: 'https', hostname: '<project>.supabase.co', pathname: '/storage/v1/object/public/**' }), or render untrusted URLs with unoptimized."
        });
      }
      const svgIdx = lines.findIndex((l) => /dangerouslyAllowSVG\s*:\s*true/.test(l));
      if (svgIdx !== -1 && !/contentSecurityPolicy\s*:/.test(cleanContent)) {
        hits.push({
          ruleId: 28010, code: 'NEXT-SB-10', severity: 'MEDIUM', type: 'SECURITY', category: 'Cross-Site Scripting',
          title: 'dangerouslyAllowSVG Enabled Without an Image Content-Security-Policy',
          lineIdx: svgIdx,
          why: 'SVG files can embed scripts; served by the image optimizer from your origin without a restrictive CSP they execute as stored XSS when the image URL is opened directly.',
          fix: "Add images.contentSecurityPolicy: \"default-src 'self'; script-src 'none'; sandbox;\" and contentDispositionType: 'attachment', or keep dangerouslyAllowSVG off."
        });
      }
      const originsIdx = lines.findIndex((l) => /allowedOrigins\s*:\s*\[[^\]]*['"]\*{1,2}['"]/.test(l));
      const multiLineOrigins = /allowedOrigins\s*:\s*\[[^\]]*['"]\*{1,2}['"]/.exec(cleanContent);
      if ((originsIdx !== -1 || multiLineOrigins) && /serverActions/.test(cleanContent)) {
        hits.push({
          ruleId: 28011, code: 'NEXT-SB-11', severity: 'MEDIUM', type: 'SECURITY', category: 'CSRF',
          title: 'Server Actions allowedOrigins Accepts Any Origin',
          lineIdx: originsIdx !== -1 ? originsIdx : lineAt(cleanContent, multiLineOrigins!.index),
          why: "A '*' entry in serverActions.allowedOrigins switches off Next.js's Origin/Host check for Server Actions, so any website can submit actions on behalf of a signed-in visitor (CSRF).",
          fix: "List the exact proxy/front-end domains (e.g. ['app.example.com', '*.example.com']) instead of a bare wildcard."
        });
      }
    }

    // NEXT-SB-12: auth/session cookie set without httpOnly
    {
      const authName = /^(?:__(?:Secure|Host)-)?(?:[\w.-]*[-_.])?(?:access[-_]?token|refresh[-_]?token|auth[-_]?token|id[-_]?token|session(?:[-_]?(?:id|token))?|sessionid|sid|jwt|token)$/i;
      const setCall = /(?:cookies\(\)\s*\)?|cookieStore|\bcookies|\.cookies)\s*\.\s*set\s*\(/g;
      for (const m of cleanContent.matchAll(setCall)) {
        const open = m.index! + m[0].length - 1;
        const close = matchClose(cleanContent, open, '(', ')');
        if (close === -1) continue;
        const args = cleanContent.slice(open + 1, close);
        const name = args.match(/^\s*['"`]([^'"`]+)['"`]/)?.[1] ?? args.match(/\bname\s*:\s*['"`]([^'"`]+)['"`]/)?.[1];
        if (!name || !authName.test(name) || /csrf|xsrf|^sb-/i.test(name)) continue;
        if (/httpOnly/i.test(args) || /\.\.\./.test(args)) continue;
        // Only flag calls that pass a value (deleting a cookie with maxAge 0 is fine)
        if (/maxAge\s*:\s*0\b|expires\s*:\s*new\s+Date\(\s*0\s*\)/.test(args)) continue;
        hits.push({
          ruleId: 28012, code: 'NEXT-SB-12', severity: 'MEDIUM', type: 'SECURITY', category: 'Session Management',
          title: 'Auth Token Cookie Set Without httpOnly',
          lineIdx: lineAt(cleanContent, m.index!),
          why: `cookies().set('${name}', ...) defaults to httpOnly: false, so any XSS (or third-party script) can read document.cookie and steal the session token.`,
          fix: `Pass { httpOnly: true, secure: true, sameSite: 'lax', path: '/' } when setting '${name}'.`
        });
        break;
      }
    }

    // NEXT-SB-13: open redirect through ${origin}${next} or a form/page value handed to redirect()
    if (isServerCode(lowerPath, cleanContent) && /redirect\s*\(/.test(cleanContent)) {
      const sameOriginGuard = /isSafe\w*|isRelative\w*|isValidRedirect|safeRedirect|sanitizeRedirect|allowedRedirect|isSameOrigin|\.origin\s*[!=]==|[!=]==\s*\w+\.origin\b/;
      const req = requestBoundNames(cleanContent);
      let idx = -1;
      let target = '';
      for (const m of cleanContent.matchAll(/redirect\s*\(\s*`\$\{\s*[\w.]*origin\s*\}\$\{\s*(\w+)\s*\}/gi)) {
        const v = m[1];
        const guarded = new RegExp(String.raw`\b` + v + String.raw`\??\.startsWith\(\s*['"]\/['"]`).test(cleanContent);
        if (req.names.has(v) && !guarded) { idx = lineAt(cleanContent, m.index!); target = v; break; }
      }
      if (idx === -1) {
        const direct = /\bredirect\s*\(\s*(?:String\(\s*)?(?:formData\.get\(\s*['"](\w+)['"]|\(?\s*(?:await\s+)?searchParams\s*\)?\s*\??\.(?!get\b)(\w+))/;
        const i = lines.findIndex((l) => direct.test(l));
        if (i !== -1 && !/startsWith\(\s*['"]\/['"]/.test(cleanContent)) {
          const mm = lines[i].match(direct)!;
          idx = i; target = mm[1] || mm[2];
        }
      }
      if (idx !== -1 && !sameOriginGuard.test(cleanContent)) {
        hits.push({
          ruleId: 28013, code: 'NEXT-SB-13', severity: 'MEDIUM', type: 'SECURITY', category: 'Open Redirect',
          title: 'Open Redirect Through a Request-Controlled Redirect Target',
          lineIdx: idx,
          why: `\`${target}\` comes from the request and is used as the redirect destination without checking it is a same-site path; ?${target}=@evil.com turns \`\${origin}\${${target}}\` into https://your.app@evil.com, and an absolute URL is followed as-is, sending users (often right after login) to a phishing page.`,
          fix: `Only accept relative paths: if (!${target}.startsWith('/') || ${target}.startsWith('//')) ${target} = '/'; before redirecting.`
        });
      }
    }

    // NEXT-SB-14: ownership column filled from client input instead of the session
    if (isRouteHandler(lowerPath) || /['"]use server['"]/.test(cleanContent)) {
      const guard = /isAdmin|is_admin|requireAdmin|assertAdmin|hasRole|app_metadata|role\s*[!=]==?\s*['"]admin['"]|\.id\s*!==?\s*\w*user_?id\b|\b\w*user_?id\s*!==?\s*\w+\.id\b/i;
      const trustedCaller = new RegExp(WEBHOOK_VERIFY.source + String.raw`|CRON_SECRET|x-api-key|headers\.get\(\s*['"]authorization['"]`, 'i');
      if (!guard.test(cleanContent) && !trustedCaller.test(cleanContent)) {
        const req = requestBoundNames(cleanContent);
        const col = String.raw`(?:user_id|owner_id|author_id|created_by|profile_id|userId|ownerId)`;
        const eqRe = new RegExp(String.raw`\.(?:eq|match)\s*\(\s*['"]` + col + String.raw`['"]\s*,\s*([^),]+(?:\([^)]*\))?[^),]*)`);
        const objRe = new RegExp(String.raw`(?:^|[{,])\s*` + col + String.raw`\s*:\s*([^,}\n]+)`);
        const writes = /\.(?:insert|upsert|update)\s*\(/.test(cleanContent);
        const idx = lines.findIndex((l) => {
          const e = l.match(eqRe);
          if (e && isRequestExpr(e[1], req)) return true;
          const o = l.match(objRe);
          return Boolean(writes && o && isRequestExpr(o[1], req));
        });
        if (idx !== -1 && /\.from\s*\(/.test(cleanContent)) {
          hits.push({
            ruleId: 28014, code: 'NEXT-SB-14', severity: 'HIGH', type: 'SECURITY', category: 'Broken Access Control',
            title: 'Record Owner Taken From the Request Instead of the Session',
            lineIdx: idx,
            why: 'The user/owner id used to scope or attribute this write comes from the form or request body, so a caller can act on (or create records as) another user by sending their id.',
            fix: 'Read the user with supabase.auth.getUser() on the server and use user.id; never accept user_id from the client.'
          });
        }
      }
    }

    // NEXT-SB-17: Supabase signed URL that effectively never expires
    {
      const m = /\.createSignedUrls?\s*\(\s*(?:[^,()]+|\[[^\]]*\]|\w+\([^)]*\))\s*,\s*([\d_\s*]+)\s*[,)]/.exec(cleanContent);
      if (m) {
        const seconds = m[1].split('*').map((p) => Number(p.replace(/[_\s]/g, ''))).reduce((a, b) => a * b, 1);
        if (Number.isFinite(seconds) && seconds >= 60 * 60 * 24 * 365) {
          hits.push({
            ruleId: 28017, code: 'NEXT-SB-17', severity: 'LOW', type: 'SECURITY', category: 'Data Exposure',
            title: 'Supabase Signed URL Valid for a Year or More',
            lineIdx: lineAt(cleanContent, m.index),
            why: `The signed URL stays valid for ${Math.round(seconds / 86400)} days and cannot be revoked, so once it is shared, logged or cached the private file is effectively public.`,
            fix: 'Issue short-lived signed URLs (minutes to hours) on demand after checking the requester may access the file.'
          });
        }
      }
    }
  }

  // NEXT-SB-15: Next.js release vulnerable to React2Shell RCE
  if (/(?:^|\/)package\.json$/i.test(path)) {
    try {
      const pkg = JSON.parse(file.content || cleanContent || '{}');
      const spec: unknown = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
      if (typeof spec === 'string' && react2ShellVulnerable(spec)) {
        const exact = /^\s*=?\s*v?\d/.test(spec);
        hits.push({
          ruleId: 28015, code: 'NEXT-SB-15', severity: exact ? 'CRITICAL' : 'MEDIUM', type: 'SECURITY', category: 'Dependency Vulnerability',
          title: 'Next.js Version Vulnerable to React2Shell RCE (CVE-2025-66478 / CVE-2025-55182)',
          lineIdx: Math.max(0, lines.findIndex((l) => /"next"\s*:/.test(l))),
          why: `next@${spec} ships a React Server Components decoder that lets an unauthenticated request execute code on the server in App Router apps.${exact ? '' : ' The range may resolve to a patched release; check the lockfile.'}`,
          fix: 'Upgrade next to 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7 or later (and the latest patch for the follow-up RSC advisories), then rotate secrets if the app was exposed.'
        });
      }
    } catch {
      // not JSON
    }
  }

  // ─── Supabase SQL migrations ────────────────────────────────────────────────────────────
  if (/\.sql$/i.test(path) && context.exposesDatabaseToClients) {
    const sql = stripSqlComments(cleanContent);
    const sqlLines = sql.split('\n');
    const firstLine = (re: RegExp, from = 0) => {
      const i = sqlLines.findIndex((l, k) => k >= from && re.test(l));
      return i === -1 ? from : i;
    };

    // NEXT-SB-04: user_metadata in policies, or privileges copied from signup metadata
    {
      let at = -1;
      for (const m of sql.matchAll(/CREATE\s+POLICY[\s\S]*?;/gi)) {
        if (/user_metadata|raw_user_meta_data/i.test(m[0])) { at = lineAt(sql, m.index! + m[0].search(/user_metadata|raw_user_meta_data/i)); break; }
      }
      const priv = /(?:raw_user_meta_data|user_metadata['"]?\s*\)?)\s*->>?\s*'(role|roles|is_admin|admin|is_super_admin|plan|tier|credits|permissions|is_pro|is_premium|org_role|subscription_\w+)'/i;
      if (at === -1) {
        // Inside function bodies (signup triggers, authz helpers); one-off data fixes that filter on metadata are fine
        for (const fn of sql.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION[\s\S]*?(\$\w*\$)([\s\S]*?)\1/gi)) {
          const pm = priv.exec(fn[2]);
          if (pm) { at = lineAt(sql, fn.index! + fn[0].length - fn[1].length - fn[2].length + pm.index); break; }
        }
      }
      if (at !== -1) {
        hits.push({
          ruleId: 28004, code: 'NEXT-SB-04', severity: 'HIGH', type: 'SECURITY', category: 'Authorization',
          title: 'Database Authorization Trusts User-Editable user_metadata',
          lineIdx: at,
          why: 'raw_user_meta_data / auth.jwt() -> user_metadata is set by the user at sign-up (options.data) and via auth.updateUser(), so policies or role columns derived from it can be self-granted.',
          fix: "Derive privileges from auth.jwt() -> 'app_metadata' or a roles table only the service role can write; copy only profile fields (name, avatar) from user metadata."
        });
      }
    }

    // NEXT-SB-05: storage.objects UPDATE/DELETE policy scoped only by bucket
    for (const m of sql.matchAll(/CREATE\s+POLICY\s+[\s\S]*?\bON\s+(?:"?storage"?\s*\.\s*"?objects"?)\b([\s\S]*?);/gi)) {
      const rest = m[1];
      if (!/\bFOR\s+(?:UPDATE|DELETE|ALL)\b/i.test(rest) && /\bFOR\s+\w+/i.test(rest)) continue;
      if (!/bucket_id/i.test(rest) || /\bTO\s+service_role\b/i.test(rest)) continue;
      if (/auth\.(?:uid|jwt|email)\s*\(|\bowner(?:_id)?\b|foldername|\bselect\b|\b(?:is|has|can)_\w+\s*\(/i.test(rest)) continue;
      hits.push({
        ruleId: 28005, code: 'NEXT-SB-05', severity: 'HIGH', type: 'SECURITY', category: 'Broken Access Control',
        title: 'Storage Policy Lets Any User Overwrite or Delete Every File in the Bucket',
        lineIdx: lineAt(sql, m.index!),
        why: 'The UPDATE/DELETE policy on storage.objects only checks bucket_id, so any client holding the anon key (or any signed-in user) can replace or delete other users\' files.',
        fix: "Scope the policy to the owner: USING (bucket_id = 'avatars' AND auth.uid() = owner_id) or (storage.foldername(name))[1] = auth.uid()::text."
      });
      break;
    }

    // NEXT-SB-06: view in the API schema that bypasses RLS
    for (const m of sql.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?)\s*(WITH\s*\(([^)]*)\))?/gi)) {
      const schema = (m[2] || 'public').toLowerCase();
      const name = m[3];
      if (schema !== 'public') continue;
      if (/security_invoker/i.test(m[5] || '')) continue;
      const hardened = new RegExp(String.raw`ALTER\s+VIEW\s+(?:IF\s+EXISTS\s+)?(?:"?public"?\.)?"?` + name + String.raw`"?\s+SET\s*\(\s*security_invoker`, 'i').test(sql) ||
        new RegExp(String.raw`REVOKE[^;]*\bON\s+(?:TABLE\s+)?(?:"?public"?\.)?"?` + name + String.raw`"?[^;]*\bFROM\b[^;]*\banon\b`, 'i').test(sql);
      if (hardened) continue;
      hits.push({
        ruleId: 28006, code: 'NEXT-SB-06', severity: 'MEDIUM', type: 'INFRA_DATABASE', category: 'Row Level Security',
        title: 'Public View Bypasses Row Level Security (Missing security_invoker)',
        lineIdx: lineAt(sql, m.index!),
        why: `View ${name} runs with its owner's privileges, so selecting through /rest/v1/${name} ignores the RLS policies of the tables it reads and exposes every row to anon/authenticated clients.`,
        fix: `Create it WITH (security_invoker = true) (Postgres 15+), move it to a non-exposed schema, or REVOKE SELECT ON ${name} FROM anon, authenticated.`
      });
      break;
    }

    // NEXT-SB-07: SECURITY DEFINER RPC that writes without checking the caller
    for (const m of sql.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)\s*\(([^)]*)\)([\s\S]*?)(\$\w*\$)([\s\S]*?)\4([^;]*);?/gi)) {
      const fullName = m[1].replace(/"/g, '');
      const schema = fullName.includes('.') ? fullName.split('.')[0].toLowerCase() : 'public';
      const header = m[3] + ' ' + m[6];
      const body = m[5];
      if (schema !== 'public') continue;
      if (!/SECURITY\s+DEFINER/i.test(header) || /RETURNS\s+(?:event_)?trigger\b/i.test(header)) continue;
      if (!/\b(?:INSERT\s+INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM)\b/i.test(body)) continue;
      if (/auth\.(?:uid|jwt|role)\s*\(|current_user|session_user|request\.jwt|current_setting\s*\(/i.test(body)) continue;
      const short = normalizeSqlName(fullName);
      if (new RegExp(String.raw`REVOKE[^;]*\bON\s+(?:FUNCTION\s+[\w."]*\b` + short + String.raw`\b|ALL\s+FUNCTIONS\s+IN\s+SCHEMA\s+"?public"?)`, 'i').test(sql)) continue;
      const hasParams = m[2].trim().length > 0;
      hits.push({
        ruleId: 28007, code: 'NEXT-SB-07', severity: 'MEDIUM', type: 'SECURITY', category: 'Database Privilege',
        title: 'SECURITY DEFINER Function Writes Data Without Checking the Caller',
        lineIdx: lineAt(sql, m.index!),
        why: `public.${short} bypasses RLS (SECURITY DEFINER) and is executable by anon and authenticated through supabase.rpc('${short}'), yet never checks auth.uid(), so anyone with the public anon key can run its writes${hasParams ? ' with arguments they choose' : ''}.`,
        fix: `Check auth.uid() inside ${short} (and that it owns the target rows), or REVOKE EXECUTE ON FUNCTION public.${short} FROM public, anon, authenticated and call it only from the server.`
      });
      break;
    }

    // NEXT-SB-16: users may UPDATE their own row while it holds privilege/billing columns
    for (const t of sql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"?public"?\.)?"?(\w+)"?)\s*\(([\s\S]*?)\n\s*\)\s*;/gi)) {
      const table = t[2];
      const privCol = t[3].match(/^\s*"?(role|is_admin|is_super_admin|credits|credit_balance|balance|plan|tier|subscription_status|subscription_tier|is_pro|is_premium|stripe_customer_id)"?\s+\w/im)?.[1];
      if (!privCol) continue;
      const tableRef = String.raw`(?:"?public"?\.)?"?` + table + String.raw`"?`;
      const policy = new RegExp(String.raw`CREATE\s+POLICY[^;]*?\bON\s+` + tableRef + String.raw`\b[^;]*?\bFOR\s+(?:UPDATE|ALL)\b[^;]*?auth\.uid\(\)[^;]*;`, 'i').exec(sql);
      if (!policy) continue;
      const columnGuard = new RegExp(String.raw`REVOKE\s+(?:UPDATE|ALL)[^;]*\bON\s+(?:TABLE\s+)?` + tableRef + String.raw`\b|GRANT\s+UPDATE\s*\([^)]*\)\s*ON\s+(?:TABLE\s+)?` + tableRef + String.raw`\b|CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER[^;]*BEFORE\s+(?:INSERT\s+OR\s+)?UPDATE[^;]*\bON\s+` + tableRef + String.raw`\b`, 'i');
      if (columnGuard.test(sql)) continue;
      hits.push({
        ruleId: 28016, code: 'NEXT-SB-16', severity: 'HIGH', type: 'SECURITY', category: 'Privilege Escalation',
        title: 'Users Can Update Their Own Privilege or Billing Column Through RLS',
        lineIdx: firstLine(/CREATE\s+POLICY/i, lineAt(sql, policy.index)),
        why: `The UPDATE policy on ${table} lets a user modify their whole row, including \`${privCol}\`, so from the browser they can run supabase.from('${table}').update({ ${privCol}: ... }) and grant themselves the privilege or balance.`,
        fix: `Restrict writable columns (REVOKE UPDATE ON ${table} FROM authenticated; GRANT UPDATE (full_name, avatar_url) ON ${table} TO authenticated), move \`${privCol}\` to a table users cannot update, or guard it with a BEFORE UPDATE trigger.`
      });
      break;
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `nextsb${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type,
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
    logs.push(`[${ts}] [NEXT-SUPABASE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
