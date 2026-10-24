'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { TrustPageDisableSchema, TrustPageEnableSchema } from '@/lib/validations/api-schemas';
import { toTrustSummary, trustSlug } from '@/lib/trust-page';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { logger } from '@/lib/logger';
import type { TrustPageActionState } from '@/lib/trust-page-state';

const fail = (message: string): TrustPageActionState => ({ status: 'error', message });

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

/** Turns on (or returns) the public trust page for one of the caller's own projects. */
export async function enableTrustPage(_prev: TrustPageActionState, formData: FormData): Promise<TrustPageActionState> {
  const parsed = TrustPageEnableSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { projectId, displayName } = parsed.data;

  const { data: project } = await ctx.admin.from('projects').select('id').eq('id', projectId).eq('user_id', ctx.user.id).maybeSingle();
  if (!project) return fail('Project not found.');

  const { data: job } = await ctx.admin
    .from('scan_jobs')
    .select('result_data, updated_at, created_at')
    .eq('user_id', ctx.user.id)
    .eq('project_id', projectId)
    .eq('status', 'COMPLETED')
    .not('result_data', 'is', null)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  const summary = job ? toTrustSummary(job.result_data, job.updated_at || job.created_at) : null;
  if (!summary) return fail('Run a scan of this project first.');

  const { data: existing } = await ctx.admin
    .from('trust_pages')
    .select('slug')
    .eq('project_id', projectId)
    .is('revoked_at', null)
    .maybeSingle();
  let slug = existing?.slug as string | undefined;
  if (slug) {
    await ctx.admin.from('trust_pages').update({ display_name: displayName }).eq('project_id', projectId).is('revoked_at', null);
  } else {
    slug = trustSlug(displayName);
    const { error } = await ctx.admin.from('trust_pages').insert({ user_id: ctx.user.id, project_id: projectId, slug, display_name: displayName });
    if (error) {
      logger.error('[Trust page] Insert failed:', error.message);
      return fail('Could not create the page. Try again.');
    }
  }
  const message = summary.blockers === 0
    ? 'Your trust page is live. It updates after every scan.'
    : `Your trust page is live and says issues are being fixed. Fix the ${summary.blockers} critical/high issue${summary.blockers === 1 ? '' : 's'} and rescan to show a clear result.`;
  return { status: 'success', message, url: `${getConfiguredAppUrl()}/verified/${slug}`, blockers: summary.blockers };
}

/** Turns the project's public trust page off; the URL then shows "not available". */
export async function disableTrustPage(_prev: TrustPageActionState, formData: FormData): Promise<TrustPageActionState> {
  const parsed = TrustPageDisableSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { error } = await ctx.admin
    .from('trust_pages')
    .update({ revoked_at: new Date().toISOString() })
    .eq('user_id', ctx.user.id)
    .eq('project_id', parsed.data.projectId)
    .is('revoked_at', null);
  if (error) return fail('Could not turn the page off.');
  return { status: 'success', message: 'Trust page turned off.' };
}
