import { randomBytes } from 'crypto';
import { safeFetch } from '@/lib/ssrf-guard';
import type { getSupabaseAdmin } from '@/lib/supabase-admin';

/**
 * Domain ownership proof for live-site scans. A user gets a token and publishes it either as
 * https://<host>/.well-known/zelsis-verify.txt or as a DNS TXT record "zelsis-verify=<token>".
 * Verifying a domain also covers its subdomains (example.com covers app.example.com).
 */

export const VERIFY_FILE_PATH = '/.well-known/zelsis-verify.txt';
export const DNS_PREFIX = 'zelsis-verify=';
const TOKEN_RE = /^[0-9a-f]{32}$/;

export type VerificationMethod = 'file' | 'dns';

export interface VerificationDeps {
  fetchText?: (url: string) => Promise<string | null>;
  resolveTxt?: (hostname: string) => Promise<string[][]>;
}

/** 32 random hex characters. */
export function createVerificationToken(): string {
  return randomBytes(16).toString('hex');
}

export function isVerificationToken(value: string): boolean {
  return TOKEN_RE.test(value);
}

/**
 * Lowercase public hostname from a domain or URL, or null for anything that is not a plain public
 * domain (IP literals, localhost, ports, single labels, credentials, paths that are not URLs).
 */
export function normalizeHostname(input: string): string | null {
  const raw = input.trim().toLowerCase();
  if (!raw || raw.length > 253) return null;
  let host = raw;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(raw)) {
    try {
      const u = new URL(raw);
      if (u.username || u.password || u.port) return null;
      host = u.hostname;
    } catch {
      return null;
    }
  } else if (/[/:@?#\s]/.test(raw)) {
    return null;
  }
  host = host.replace(/\.$/, '');
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':') || host.startsWith('[')) return null;
  if (host === 'localhost' || /\.(?:localhost|local|internal|test|invalid|example)$/.test(host)) return null;
  const labels = host.split('.');
  if (labels.length < 2 || !labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  if (!/[a-z]/.test(labels[labels.length - 1])) return null;
  return host;
}

/** The hostname and each parent domain it could be covered by (app.example.com -> app.example.com, example.com). */
export function coveringHostnames(hostname: string): string[] {
  const labels = hostname.split('.');
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join('.'));
  return out;
}

async function defaultFetchText(url: string): Promise<string | null> {
  try {
    const res = await safeFetch(url, { maxRedirects: 2, timeoutMs: 5000, headers: { 'User-Agent': 'Zelsis-Verification/1.0' } });
    if (!res.ok) return null;
    return (await res.text()).slice(0, 1024);
  } catch {
    return null;
  }
}

async function defaultResolveTxt(hostname: string): Promise<string[][]> {
  const dns = await import('node:dns/promises');
  return dns.resolveTxt(hostname);
}

/** Which method proved ownership, or null. Network failures count as "not verified". */
export async function verifyOwnership(hostname: string, token: string, deps: VerificationDeps = {}): Promise<VerificationMethod | null> {
  const host = normalizeHostname(hostname);
  if (!host || !isVerificationToken(token)) return null;
  const fetchText = deps.fetchText ?? defaultFetchText;
  const resolveTxt = deps.resolveTxt ?? defaultResolveTxt;

  const [body, records] = await Promise.all([
    fetchText(`https://${host}${VERIFY_FILE_PATH}`).catch(() => null),
    resolveTxt(host).catch(() => [] as string[][]),
  ]);
  if (body && body.split(/\s+/).includes(token)) return 'file';
  if (records.some((chunks) => chunks.join('').trim() === `${DNS_PREFIX}${token}`)) return 'dns';
  return null;
}

/** Whether userId has verified this hostname or one of its parent domains. */
export async function isSiteVerified(admin: ReturnType<typeof getSupabaseAdmin>, userId: string | null | undefined, siteUrlOrHost: string): Promise<boolean> {
  const host = normalizeHostname(siteUrlOrHost);
  if (!admin || !userId || !host) return false;
  try {
    const { data } = await admin
      .from('site_verifications')
      .select('hostname')
      .eq('user_id', userId)
      .in('hostname', coveringHostnames(host))
      .not('verified_at', 'is', null)
      .limit(1);
    return Boolean(data && data.length);
  } catch {
    return false;
  }
}
