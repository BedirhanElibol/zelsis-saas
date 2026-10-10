/**
 * Full-size analysis of a live site's JavaScript bundles (the general rules only see the first 250 KB of each).
 * Vite/Lovable bundles are 0.4-2 MB and the Supabase client and API keys often sit past that point.
 * Pure functions: the website scanner fetches the bundles, this finds secrets in them, and
 * lib/rules/live-bundle-rules.ts turns the summary into findings.
 */

export interface BundleSecret {
  kind: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  /** First and last characters only; the full value never leaves the scanner. */
  preview: string;
  bundle: string;
  detail?: string;
}

export interface LiveBundleSummary {
  bundles: { url: string; sizeKb: number }[];
  supabaseProjects: string[];
  secrets: BundleSecret[];
  publicSourceMaps: string[];
}

const redact = (v: string) => (v.length <= 12 ? `${v.slice(0, 3)}...` : `${v.slice(0, 8)}...${v.slice(-4)}`);

/** Payload of a JWT, or null. */
function jwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split('.')[1];
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const KEY_PATTERNS: { kind: string; re: RegExp; severity: BundleSecret['severity']; detail: string; near?: RegExp }[] = [
  { kind: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, severity: 'CRITICAL', detail: 'Supabase secret keys bypass Row Level Security: anyone can read and change every table.' },
  { kind: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}/g, severity: 'CRITICAL', detail: 'Anyone can use your OpenAI account and run up your bill.' },
  { kind: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{30,}/g, severity: 'CRITICAL', detail: 'Anyone can use your Anthropic account and run up your bill.' },
  { kind: 'OpenRouter API key', re: /\bsk-or-v1-[a-f0-9]{40,}/g, severity: 'CRITICAL', detail: 'Anyone can spend your OpenRouter credits.' },
  { kind: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}/g, severity: 'HIGH', detail: 'Anyone can use your Groq account.' },
  { kind: 'Replicate API token', re: /\br8_[A-Za-z0-9]{30,}/g, severity: 'HIGH', detail: 'Anyone can run models on your Replicate account.' },
  { kind: 'Stripe secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g, severity: 'CRITICAL', detail: 'Full access to your Stripe account: refunds, payouts, customer data.' },
  { kind: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, severity: 'HIGH', detail: 'Anyone can send email from your domain.' },
  { kind: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, severity: 'HIGH', detail: 'Anyone can send email from your account.' },
  { kind: 'GitHub token', re: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})/g, severity: 'CRITICAL', detail: 'Access to your GitHub repositories.' },
  { kind: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'CRITICAL', detail: 'Access to your AWS account.' },
  { kind: 'Google Gemini API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'HIGH', near: /generativelanguage\.googleapis|gemini|GoogleGenerativeAI|GoogleGenAI/i, detail: 'Anyone can call Gemini on your Google Cloud bill.' },
];

/** Secrets and Supabase projects in the full bundle texts. */
export function analyzeBundles(bundles: { url: string; text: string }[]): Omit<LiveBundleSummary, 'publicSourceMaps'> {
  const secrets: BundleSecret[] = [];
  const projects = new Set<string>();
  const seen = new Set<string>();
  const add = (s: BundleSecret, raw: string) => { if (seen.has(raw)) return; seen.add(raw); secrets.push(s); };

  for (const { url, text } of bundles) {
    for (const m of text.matchAll(/https:\/\/([a-z0-9]{20})\.supabase\.co/g)) projects.add(m[1]);
    // Supabase keys are JWTs: the role claim says whether it is the public anon key or the service role
    for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g)) {
      const payload = jwtPayload(m[0]);
      if (payload?.role === 'service_role') {
        add({ kind: 'Supabase service_role key', severity: 'CRITICAL', preview: redact(m[0]), bundle: url,
          detail: 'The service role key skips every Row Level Security policy: anyone who opens your site can read, change and delete all data.' }, m[0]);
      }
    }
    for (const p of KEY_PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        if (p.near && !p.near.test(text.slice(Math.max(0, m.index! - 3000), m.index! + 3000))) continue;
        add({ kind: p.kind, severity: p.severity, preview: redact(m[0]), bundle: url, detail: p.detail }, m[0]);
      }
    }
  }
  return {
    bundles: bundles.map((b) => ({ url: b.url, sizeKb: Math.round(b.text.length / 1024) })),
    supabaseProjects: [...projects],
    secrets,
  };
}

/** Lazy chunks a bundle loads later (Vite /assets/*.js, Next.js /_next/static/chunks/*.js), resolved against the site origin. */
export function lazyChunkUrls(bundleText: string, origin: string): string[] {
  const out = new Set<string>();
  for (const m of bundleText.matchAll(/["'`]((?:\/|\.\/)?(?:assets|_next\/static\/chunks)\/[\w./-]+?\.js)["'`]/g)) {
    try {
      out.add(new URL(m[1].replace(/^\.\//, '/'), origin).toString());
    } catch {
      /* malformed path */
    }
  }
  return [...out];
}

/** sourceMappingURL of a bundle, resolved, or null. */
export function sourceMapUrl(bundleText: string, bundleUrl: string): string | null {
  const m = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+\.map)\s*$/m.exec(bundleText.slice(-500));
  if (!m) return null;
  try { return new URL(m[1], bundleUrl).toString(); } catch { return null; }
}
