/**
 * Zelsis SaaS Core Rules (SAAS-01..08, Rule IDs 23001-23008).
 * High-impact mistakes in Next.js + Supabase + Stripe/Polar + LLM SaaS codebases:
 * tenant data exposure, billing manipulation, auth trust errors and prompt injection.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface SaasCoreRuleResult {
  findings: Finding[];
  logs: string[];
}

interface RuleHit {
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

const isSqlFile = (p: string) => /\.sql$/i.test(p);
const isCodeFile = (p: string) => /\.[cm]?[jt]sx?$/i.test(p);
const isServerFile = (p: string, content: string) =>
  /(?:^|\/)(?:middleware|proxy)\.[jt]s$|\/route\.[cm]?[jt]s$|(?:^|\/)pages\/api\//i.test(p) ||
  /^\s*['"]use server['"]/m.test(content) ||
  (/(?:^|\/)app\/.*\.[jt]sx?$/i.test(p) && !/^\s*['"]use client['"]/m.test(content));

/** Local names bound to the parsed request body (`const { a, b: c } = await req.json()` / `const body = ...`). */
function requestBindings(content: string): { names: Set<string>; objects: Set<string> } {
  const names = new Set<string>();
  const objects = new Set<string>();
  const source = String.raw`(?:await\s+)?(?:req|request)\.(?:json|formData)\(\)`;
  for (const m of content.matchAll(new RegExp(String.raw`(?:const|let|var)\s*\{([^}]+)\}\s*=\s*` + source, 'g'))) {
    for (const part of m[1].split(',')) {
      const local = part.split('=')[0].split(':').pop()?.trim();
      if (local && /^\w+$/.test(local)) names.add(local);
    }
  }
  for (const m of content.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*` + source, 'g'))) {
    objects.add(m[1]);
  }
  return { names, objects };
}

const isRequestDerived = (expr: string, req: ReturnType<typeof requestBindings>) => {
  const root = expr.trim().split(/[.\s[(]/)[0];
  return req.names.has(expr.trim()) || req.objects.has(root) || /searchParams\.get\(|\breq\.(?:body|query)\b/.test(expr);
};

const lineOf = (lines: string[], test: (l: string) => boolean) => Math.max(0, lines.findIndex(test));

/** Next.js releases fixing CVE-2025-29927 (middleware bypass via x-middleware-subrequest). */
const NEXT_MIDDLEWARE_FIXED: Record<number, [number, number]> = { 12: [3, 5], 13: [5, 9], 14: [2, 25], 15: [2, 3] };

function isVulnerableNext(version: string): boolean {
  const m = version.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const [major, minor, patch] = m.slice(1).map(Number);
  if (major === 11) return minor > 1 || (minor === 1 && patch >= 4);
  const fixed = NEXT_MIDDLEWARE_FIXED[major];
  if (!fixed) return false;
  return minor < fixed[0] || (minor === fixed[0] && patch < fixed[1]);
}

export function evaluateSaasCoreRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): SaasCoreRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const lowerPath = path.toLowerCase();
  if (lowerPath.includes('data/catalogs/') || lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
    return { findings, logs };
  }
  const hits: RuleHit[] = [];

  if (isSqlFile(path)) {
    // SAAS-01: every signed-in user can read/write every row
    const anyAuthenticated = /CREATE\s+POLICY[^;]*?\b(?:USING|WITH\s+CHECK)\s*\(\s*(?:\(\s*)?(?:auth\.uid\(\)\s+IS\s+NOT\s+NULL|auth\.role\(\)\s*=\s*'authenticated'|\(\s*select\s+auth\.uid\(\)\s*\)\s+IS\s+NOT\s+NULL)\s*\)?\s*\)/i;
    if (anyAuthenticated.test(cleanContent)) {
      hits.push({
        ruleId: 23001, code: 'SAAS-01', severity: 'HIGH', type: 'SECURITY', category: 'Multi-Tenant Isolation',
        title: 'RLS Policy Grants Every Signed-In User Access to All Rows',
        lineIdx: lineOf(lines, (l) => /auth\.uid\(\)\s*\)?\s+IS\s+NOT\s+NULL|auth\.role\(\)\s*=\s*'authenticated'/i.test(l)),
        why: 'The policy only checks that a user is signed in, so any customer (including a free sign-up) can read or modify other tenants\' rows.',
        fix: 'Scope the policy to the owner or tenant, e.g. USING (auth.uid() = user_id) or a membership check on org_id.'
      });
    }

    // SAAS-03: SECURITY DEFINER without a pinned search_path
    for (const m of cleanContent.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION[\s\S]*?(?:\$\$|\$\w+\$)[\s\S]*?(?:\$\$|\$\w+\$)[^;]*;?/gi)) {
      const fn = m[0];
      if (/SECURITY\s+DEFINER/i.test(fn) && !/SET\s+search_path/i.test(fn)) {
        const name = fn.match(/FUNCTION\s+([\w."]+)/i)?.[1] ?? 'function';
        hits.push({
          ruleId: 23003, code: 'SAAS-03', severity: 'HIGH', type: 'INFRA_DATABASE', category: 'Database Privilege',
          title: 'SECURITY DEFINER Function Without a Fixed search_path',
          lineIdx: lineOf(lines, (l) => l.includes(name.replace(/"/g, ''))),
          why: `${name} runs with its owner's privileges but resolves unqualified names through the caller's search_path, so a caller can shadow tables or functions and escalate privileges.`,
          fix: `Add SET search_path = '' (or pg_catalog, public) to ${name} and schema-qualify every object it references.`
        });
        break;
      }
    }
  }

  if (isCodeFile(path)) {
    const req = requestBindings(cleanContent);

    // SAAS-02: Supabase getSession() trusted on the server
    if (isServerFile(lowerPath, cleanContent) && /\.auth\.getSession\s*\(/.test(cleanContent) && !/\.auth\.(?:getUser|getClaims)\s*\(/.test(cleanContent)) {
      hits.push({
        ruleId: 23002, code: 'SAAS-02', severity: 'HIGH', type: 'SECURITY', category: 'Authentication',
        title: 'Server Authorization Based on Supabase getSession()',
        lineIdx: lineOf(lines, (l) => /\.auth\.getSession\s*\(/.test(l)),
        why: 'getSession() reads the session from cookies without revalidating the JWT, so server-side checks can be satisfied with a forged or revoked session.',
        fix: 'On the server use supabase.auth.getUser() (or getClaims()) to verify the user before authorizing.'
      });
    }

    // SAAS-04: price or amount taken from the client
    if (/stripe|paymentIntents|checkout\.sessions|lemonsqueezy|polar\.checkouts|createCheckout/i.test(cleanContent)) {
      const priceAllowlist = /ALLOWED_PRICE|PRICE_IDS|PRICES\s*\[|priceMap|PLANS?\s*\[|PRODUCTS?\s*\[|\.includes\(\s*\w*price|z\.enum\(/i;
      let hitIdx = -1;
      let field = '';
      lines.forEach((l, i) => {
        if (hitIdx !== -1) return;
        for (const m of l.matchAll(/\b(unit_amount|amount|price|price_id|priceId|productId|product_id)\s*:\s*([\w.[\]'"]+)/g)) {
          const isPriceRef = !/amount/i.test(m[1]);
          if (isRequestDerived(m[2], req) && !(isPriceRef && priceAllowlist.test(cleanContent))) { hitIdx = i; field = m[1]; return; }
        }
        const shorthand = l.match(/[{,]\s*(amount|unit_amount)\s*(?=[,}])/);
        if (shorthand && req.names.has(shorthand[1])) { hitIdx = i; field = shorthand[1]; }
      });
      if (hitIdx !== -1) {
        hits.push({
          ruleId: 23004, code: 'SAAS-04', severity: 'CRITICAL', type: 'SECURITY', category: 'Revenue Protection',
          title: 'Payment Amount or Price Controlled by the Client',
          lineIdx: hitIdx,
          why: `\`${field}\` comes straight from the request body, so a customer can pay any amount or check out with a cheaper price/product ID.`,
          fix: 'Accept only a plan key from the client and look up the price/amount server-side from an allowlist (e.g. PRICES[plan]).'
        });
      }
    }

    // SAAS-05: timing-unsafe comparison against a secret
    const secretEnv = String.raw`process\.env\.\w*(?:SECRET|TOKEN|API_KEY|KEY|PASSWORD)\w*`;
    const unsafeCompare = new RegExp(String.raw`(?:===|!==)\s*` + secretEnv + String.raw`\b|` + secretEnv + String.raw`\s*(?:===|!==)\s*(?![\s'"\x60]|undefined\b|null\b)`);
    const compareIdx = lines.findIndex((l) => unsafeCompare.test(l) && !/^\s*(?:\/\/|\*)/.test(l));
    if (compareIdx !== -1) {
      hits.push({
        ruleId: 23005, code: 'SAAS-05', severity: 'MEDIUM', type: 'SECURITY', category: 'Cryptographic & Auth Failures',
        title: 'Secret Compared With === Instead of a Constant-Time Check',
        lineIdx: compareIdx,
        why: 'String equality returns as soon as a character differs, leaking how much of the secret matched through response timing.',
        fix: 'Compare equal-length Buffers with crypto.timingSafeEqual, and reject when the secret is unset.'
      });
    }

    // SAAS-06: cron endpoint callable by anyone
    if (/(?:^|\/)(?:app|pages)\/api\/(?:.*\/)?cron\/.*\.[cm]?[jt]s$/i.test(lowerPath) && !/CRON_SECRET|authorization|x-vercel-signature|verifySignature|Receiver\(|upstash-signature|qstash/i.test(cleanContent)) {
      hits.push({
        ruleId: 23006, code: 'SAAS-06', severity: 'HIGH', type: 'SECURITY', category: 'Access Control',
        title: 'Cron Endpoint Without a Secret Check',
        lineIdx: lineOf(lines, (l) => /export\s+(?:async\s+)?function\s+(?:GET|POST)|export\s+default/.test(l)),
        why: 'Scheduled jobs are plain public routes; without verifying CRON_SECRET anyone can trigger them repeatedly (data jobs, emails, paid API calls).',
        fix: "Reject requests unless req.headers.get('authorization') === `Bearer ${process.env.CRON_SECRET}` (compared in constant time)."
      });
    }

    // SAAS-07: request data interpolated into the system prompt
    const systemTemplates = [
      /role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*`([^`]*)`/g,
      /content\s*:\s*`([^`]*)`\s*,\s*role\s*:\s*['"]system['"]/g,
      /\bsystem\s*:\s*`([^`]*)`/g
    ];
    let injectedVar = '';
    for (const re of systemTemplates) {
      for (const m of cleanContent.matchAll(re)) {
        for (const expr of m[1].matchAll(/\$\{([^}]+)\}/g)) {
          if (isRequestDerived(expr[1], req)) { injectedVar = expr[1].trim(); break; }
        }
        if (injectedVar) break;
      }
      if (injectedVar) break;
    }
    if (injectedVar) {
      hits.push({
        ruleId: 23007, code: 'SAAS-07', severity: 'HIGH', type: 'SECURITY', category: 'AI Safety',
        title: 'User Input Interpolated Into the System Prompt (Prompt Injection)',
        lineIdx: lineOf(lines, (l) => l.includes('${' + injectedVar)),
        why: `\`${injectedVar}\` from the request is placed inside the system prompt, which the model treats as trusted instructions, so users can override guardrails or extract hidden context.`,
        fix: 'Keep the system prompt static; pass user-provided values in a user message (delimited and length-limited).'
      });
    }
  }

  // SAAS-08: Next.js release vulnerable to CVE-2025-29927
  if (/(?:^|\/)package\.json$/i.test(path)) {
    try {
      const pkg = JSON.parse(file.content || '{}');
      const spec: string | undefined = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
      if (typeof spec === 'string' && isVulnerableNext(spec)) {
        const pinned = !/^\s*\^/.test(spec);
        hits.push({
          ruleId: 23008, code: 'SAAS-08', severity: pinned ? 'HIGH' : 'MEDIUM', type: 'SECURITY', category: 'Dependency Vulnerability',
          title: 'Next.js Version Vulnerable to Middleware Authorization Bypass (CVE-2025-29927)',
          lineIdx: lineOf(lines, (l) => /"next"\s*:/.test(l)),
          why: `next@${spec} lets a request skip middleware by sending the x-middleware-subrequest header, bypassing any auth enforced there.${pinned ? '' : ' The caret range may resolve to a fixed release; check the lockfile.'}`,
          fix: 'Upgrade to next 15.2.3+, 14.2.25+, 13.5.9+ or 12.3.5+, and verify auth in route handlers/server code, not only in middleware.'
        });
      }
    } catch {
      // Not valid JSON: nothing to check
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `saas${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [SAAS CORE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
