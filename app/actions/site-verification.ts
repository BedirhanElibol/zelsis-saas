'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { SiteDomainSchema } from '@/lib/validations/api-schemas';
import { DNS_PREFIX, VERIFY_FILE_PATH, createProbeKey, createVerificationToken, normalizeHostname, verifyOwnership } from '@/lib/site-verification';
import { logger } from '@/lib/logger';
import type { SiteDomainSummary, SiteVerificationActionState } from '@/lib/site-verification-state';

/** Domains per account; each one is a proof of control, not a scan quota. */
const MAX_DOMAINS = 20;
/** Minimum seconds between two checks of the same domain (each check makes an HTTPS request and a DNS lookup). */
const CHECK_INTERVAL_S = 10;
const lastCheck = new Map<string, number>();

const fail = (message: string): SiteVerificationActionState => ({ status: 'error', message });

async function authenticate(accessToken: string): Promise<{ admin: SupabaseClient; user: User } | null> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceRoleKey) return null;
  const { data, error } = await createClient(url, anonKey, { auth: { persistSession: false } }).auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return { admin: createClient(url, serviceRoleKey, { auth: { persistSession: false } }), user: data.user };
}

const formObject = (formData: FormData) =>
  Object.fromEntries([...formData.entries()].filter(([, v]) => typeof v === 'string'));

async function parse(formData: FormData) {
  const parsed = SiteDomainSchema.safeParse(formObject(formData));
  if (!parsed.success) return { error: fail(parsed.error.issues[0]?.message ?? 'Invalid input') };
  const hostname = normalizeHostname(parsed.data.hostname);
  if (!hostname) return { error: fail('Enter a public domain such as example.com (no IP addresses, ports or localhost).') };
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return { error: fail('Your session expired. Sign in again.') };
  return { hostname, ...ctx };
}

/** The caller's domains with the token and where to publish it, plus the probe key once a domain is verified. */
export async function listSiteDomains(accessToken: string): Promise<SiteDomainSummary[]> {
  const ctx = await authenticate(accessToken);
  if (!ctx) return [];
  const { data } = await ctx.admin
    .from('site_verifications')
    .select('hostname, token, verified_at, verified_method, probe_key')
    .eq('user_id', ctx.user.id)
    .order('created_at', { ascending: false });
  const rows = data ?? [];
  // Domains verified before probe keys existed get one the first time the owner looks
  for (const d of rows) {
    if (!d.verified_at || d.probe_key) continue;
    const probeKey = createProbeKey();
    const { error } = await ctx.admin.from('site_verifications').update({ probe_key: probeKey })
      .eq('user_id', ctx.user.id).eq('hostname', d.hostname).is('probe_key', null);
    if (!error) d.probe_key = probeKey;
  }
  return rows.map((d) => ({
    hostname: d.hostname, token: d.token, verifiedAt: d.verified_at, verifiedMethod: d.verified_method,
    fileUrl: `https://${d.hostname}${VERIFY_FILE_PATH}`, dnsValue: `${DNS_PREFIX}${d.token}`,
    probeKey: d.verified_at ? d.probe_key ?? null : null,
  }));
}

/** Issues a verification token for a domain (idempotent: an existing domain keeps its token). */
export async function addSiteDomain(_prev: SiteVerificationActionState, formData: FormData): Promise<SiteVerificationActionState> {
  const p = await parse(formData);
  if ('error' in p) return p.error!;
  const { count } = await p.admin.from('site_verifications').select('id', { count: 'exact', head: true }).eq('user_id', p.user.id);
  if ((count ?? 0) >= MAX_DOMAINS) return fail(`You can add up to ${MAX_DOMAINS} domains. Remove one first.`);
  const { error } = await p.admin
    .from('site_verifications')
    .upsert({ user_id: p.user.id, hostname: p.hostname, token: createVerificationToken() }, { onConflict: 'user_id,hostname', ignoreDuplicates: true });
  if (error) {
    logger.error('[Site verification] Insert failed:', error.message);
    return fail('Could not add the domain. Try again.');
  }
  return { status: 'success', message: `Added ${p.hostname}. Publish the token below, then press Verify.` };
}

/** Looks for the token in the well-known file or DNS TXT record and records the proof. */
export async function verifySiteDomain(_prev: SiteVerificationActionState, formData: FormData): Promise<SiteVerificationActionState> {
  const p = await parse(formData);
  if ('error' in p) return p.error!;
  const key = `${p.user.id}:${p.hostname}`;
  const now = Date.now();
  if (now - (lastCheck.get(key) ?? 0) < CHECK_INTERVAL_S * 1000) return fail(`Wait ${CHECK_INTERVAL_S} seconds between checks.`);
  lastCheck.set(key, now);

  const { data: row } = await p.admin
    .from('site_verifications')
    .select('token, probe_key')
    .eq('user_id', p.user.id)
    .eq('hostname', p.hostname)
    .maybeSingle();
  if (!row) return fail('Add the domain first.');

  const method = await verifyOwnership(p.hostname, row.token);
  if (!method) return fail(`Token not found on ${p.hostname}. Check the file or TXT record (DNS changes can take a few minutes).`);
  const { error } = await p.admin
    .from('site_verifications')
    .update({ verified_at: new Date().toISOString(), verified_method: method, probe_key: row.probe_key ?? createProbeKey() })
    .eq('user_id', p.user.id)
    .eq('hostname', p.hostname);
  if (error) return fail('Verified, but saving failed. Try again.');
  return { status: 'success', message: `${p.hostname} verified by ${method === 'dns' ? 'DNS TXT record' : 'well-known file'}. Deep live checks now run on its scans; allow the probe header below in your firewall so they are not challenged.` };
}

export async function removeSiteDomain(_prev: SiteVerificationActionState, formData: FormData): Promise<SiteVerificationActionState> {
  const p = await parse(formData);
  if ('error' in p) return p.error!;
  const { error } = await p.admin.from('site_verifications').delete().eq('user_id', p.user.id).eq('hostname', p.hostname);
  if (error) return fail('Could not remove the domain.');
  return { status: 'success', message: `Removed ${p.hostname}.` };
}
