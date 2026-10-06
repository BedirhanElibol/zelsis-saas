/**
 * SaaS stack leaks common in AI-built apps (SAAS5-xx, Rule IDs 29401-29499).
 * Each rule needs an explicit name or setting on the matched line; see tests/rules/fixtures/saas-v5.ts.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

/** Env prefixes that bundlers inline into browser JavaScript. */
const PUBLIC_PREFIX = String.raw`(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)`;
/** Providers whose keys bill or act on the owner's account; none of them issues a browser-safe key. */
const PAID_PROVIDER = String.raw`(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_GENERATIVE_AI|GOOGLE_AI|GROQ|MISTRAL|COHERE|REPLICATE|HUGGINGFACE|HF|DEEPSEEK|PERPLEXITY|XAI|GROK|TOGETHER|FIREWORKS|OPENROUTER|ELEVENLABS|RESEND|SENDGRID|POSTMARK|MAILGUN|TWILIO|PINECONE|UPSTASH_REDIS_REST)`;
const CLIENT_SECRET_ENV = new RegExp(String.raw`\b${PUBLIC_PREFIX}(?:\w*_)?${PAID_PROVIDER}\w*?(?:API_?KEY|_KEY|TOKEN|SECRET)\b`);

const CLERK_EVENT = /['"`](?:user\.(?:created|updated|deleted)|organization(?:Membership)?\.(?:created|updated|deleted)|session\.created)['"`]|WebhookEvent\b[^;\n]*['"]@clerk\//;
const SVIX_VERIFY = /\bsvix\b|standardwebhooks|standard-webhooks|\bverifyWebhook\s*\(|\bnew\s+Webhook\s*\(|\.verify\s*\(/;

export function evaluateSaasV5Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/').toLowerCase();
  if (/(?:^|\/)node_modules\//.test(path)) return { findings, logs };
  const raw = (file.content || '').split('\n');
  const hits: Hit[] = [];
  const isCode = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/.test(path);
  const isEnv = /(?:^|\/)\.env(?:\.[\w-]+)?$/.test(path) || /(?:^|\/)env\.example$/.test(path);

  // SAAS5-01: paid API key behind a public env prefix ends up in the browser bundle
  if (isCode || isEnv) {
    const idx = raw.findIndex((l) => !/^\s*(?:#|\/\/)/.test(l) && CLIENT_SECRET_ENV.test(l));
    if (idx !== -1) {
      const name = (raw[idx].match(CLIENT_SECRET_ENV) || [''])[0];
      hits.push({
        ruleId: 29401, code: 'SAAS5-01', severity: 'HIGH', category: 'Secrets Management', lineIdx: idx,
        title: `Paid API Key Exposed to the Browser (${name})`,
        why: `${name} uses a prefix the bundler inlines into client JavaScript, so anyone can read the key from the page and run up usage, send mail/SMS or read data on your account.`,
        fix: 'Rename it without the public prefix, call the provider from a server route or Server Action, and rotate the key that already shipped.',
      });
    }
  }

  // SAAS5-02: Clerk webhook handled without verifying the svix signature
  if (isCode && /webhook/.test(path) && CLERK_EVENT.test(cleanContent) && /\b(?:req|request)\.(?:json|text|body)\b|await\s+\w+\.json\(\)/.test(cleanContent) && !SVIX_VERIFY.test(cleanContent)) {
    const idx = Math.max(0, lines.findIndex((l) => CLERK_EVENT.test(l)));
    hits.push({
      ruleId: 29402, code: 'SAAS5-02', severity: 'HIGH', category: 'Authentication & Access Control', lineIdx: idx,
      title: 'Clerk Webhook Accepted Without svix Signature Verification',
      why: 'The handler trusts the posted JSON, so anyone can send a forged user.created / user.updated event to create accounts, change roles or delete users in your database.',
      fix: "Verify every request with svix before parsing: new Webhook(process.env.CLERK_WEBHOOK_SECRET).verify(body, { 'svix-id', 'svix-timestamp', 'svix-signature' }) or verifyWebhook(req) from @clerk/nextjs/webhooks.",
    });
  }

  // SAAS5-03: production source maps published next to the bundle
  if (/(?:^|\/)next\.config\.[cm]?[jt]s$/.test(path)) {
    const idx = raw.findIndex((l) => /^\s*productionBrowserSourceMaps\s*:\s*true\b/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29403, code: 'SAAS5-03', severity: 'MEDIUM', category: 'Information Disclosure', lineIdx: idx,
      title: 'Production Browser Source Maps Enabled',
      why: 'Every visitor can download the original source of your client code, including comments, internal API paths and feature flags.',
      fix: 'Remove productionBrowserSourceMaps (default false); upload source maps privately to your error tracker instead.',
    });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `saas5${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [SAAS V5] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
