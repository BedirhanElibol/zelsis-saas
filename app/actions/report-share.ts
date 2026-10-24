'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { ReportShareCreateSchema, ReportShareRevokeSchema } from '@/lib/validations/api-schemas';
import { createShareToken } from '@/lib/report-share';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { logger } from '@/lib/logger';
import type { ReportShareActionState } from '@/lib/report-share-state';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = (message: string): ReportShareActionState => ({ status: 'error', message });

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

/**
 * Creates (or returns the existing active) read-only link for the caller's latest completed scan of a project.
 * Only the caller's own scan jobs are considered.
 */
export async function createReportShare(_prev: ReportShareActionState, formData: FormData): Promise<ReportShareActionState> {
  const parsed = ReportShareCreateSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { projectId, repoUrl } = parsed.data;

  const latestJob = async (column: 'project_id' | 'repo_url', value: string) => (await ctx.admin
    .from('scan_jobs')
    .select('id')
    .eq('user_id', ctx.user.id)
    .eq('status', 'COMPLETED')
    .not('result_data', 'is', null)
    .eq(column, value)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle()).data as { id: string } | null;
  const job = (UUID.test(projectId) ? await latestJob('project_id', projectId) : null) ?? await latestJob('repo_url', repoUrl);
  if (!job) return fail('No completed cloud scan of this project yet. Run a scan, then share it.');

  const { data: existing } = await ctx.admin
    .from('report_shares')
    .select('token')
    .eq('user_id', ctx.user.id)
    .eq('job_id', job.id)
    .is('revoked_at', null)
    .maybeSingle();
  let token = existing?.token as string | undefined;
  if (!token) {
    token = createShareToken();
    const { error } = await ctx.admin.from('report_shares').insert({ user_id: ctx.user.id, job_id: job.id, token });
    if (error) {
      logger.error('[Report share] Insert failed:', error.message);
      return fail('Could not create the link. Try again.');
    }
  }
  return { status: 'success', message: 'Anyone with this link can see the score and findings, without code.', url: `${getConfiguredAppUrl()}/r/${token}`, token };
}

/** Turns a link off; the page then shows "link revoked". */
export async function revokeReportShare(_prev: ReportShareActionState, formData: FormData): Promise<ReportShareActionState> {
  const parsed = ReportShareRevokeSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { error } = await ctx.admin
    .from('report_shares')
    .update({ revoked_at: new Date().toISOString() })
    .eq('user_id', ctx.user.id)
    .eq('token', parsed.data.token)
    .is('revoked_at', null);
  if (error) return fail('Could not revoke the link.');
  return { status: 'success', message: 'Link turned off. It no longer shows the report.', token: parsed.data.token };
}
