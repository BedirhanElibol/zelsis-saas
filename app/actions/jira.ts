'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { JiraConnectSchema, JiraDisconnectSchema, JiraIssueSchema } from '@/lib/validations/api-schemas';
import { createJiraIssue as postJiraIssue, normalizeJiraSite, verifyJiraConnection, type JiraConnection } from '@/lib/jira';
import { integrationKey, open, seal } from '@/lib/secret-box';
import { logger } from '@/lib/logger';
import type { JiraActionState, JiraConnectionSummary } from '@/lib/jira-state';

const fail = (message: string): JiraActionState => ({ status: 'error', message });
const NOT_CONFIGURED = 'Jira is not set up on this server yet.';

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

interface ConnectionRow { site_url: string; email: string; project_key: string; issue_type: string; token_ciphertext: string }

const toConnection = (row: ConnectionRow): JiraConnection => ({ site: row.site_url, email: row.email, projectKey: row.project_key, issueType: row.issue_type });

async function loadConnection(admin: SupabaseClient, userId: string): Promise<ConnectionRow | null> {
  const { data } = await admin.from('jira_connections').select('site_url, email, project_key, issue_type, token_ciphertext').eq('user_id', userId).maybeSingle();
  return (data as ConnectionRow | null) ?? null;
}

/** The caller's saved connection without the token, or null. */
export async function getJiraConnection(accessToken: string): Promise<JiraConnectionSummary | null> {
  const ctx = typeof accessToken === 'string' ? await authenticate(accessToken) : null;
  if (!ctx) return null;
  const row = await loadConnection(ctx.admin, ctx.user.id);
  return row ? { site: row.site_url, email: row.email, projectKey: row.project_key, issueType: row.issue_type } : null;
}

/** Verifies the credentials against Jira, then stores them with the token encrypted. */
export async function saveJiraConnection(_prev: JiraActionState, formData: FormData): Promise<JiraActionState> {
  const parsed = JiraConnectSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const key = integrationKey();
  if (!key) return fail(NOT_CONFIGURED);
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');

  const site = normalizeJiraSite(parsed.data.site);
  if (!site) return fail('Enter your Jira Cloud address, for example acme.atlassian.net.');
  const conn: JiraConnection = { site, email: parsed.data.email, projectKey: parsed.data.projectKey.toUpperCase(), issueType: parsed.data.issueType };

  try {
    const problem = await verifyJiraConnection(conn, parsed.data.apiToken);
    if (problem) return fail(problem);
  } catch (err) {
    logger.warn('[Jira] Verify failed:', err);
    return fail('Could not reach Jira. Check the site address and try again.');
  }

  const { error } = await ctx.admin.from('jira_connections').upsert({
    user_id: ctx.user.id,
    site_url: conn.site,
    email: conn.email,
    project_key: conn.projectKey,
    issue_type: conn.issueType,
    token_ciphertext: seal(parsed.data.apiToken, key),
    updated_at: new Date().toISOString(),
  });
  if (error) {
    logger.error('[Jira] Save failed:', error);
    return fail('Could not save the connection. Try again.');
  }
  return { status: 'success', message: `Connected to ${conn.site}, project ${conn.projectKey}.` };
}

export async function deleteJiraConnection(_prev: JiraActionState, formData: FormData): Promise<JiraActionState> {
  const parsed = JiraDisconnectSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { error } = await ctx.admin.from('jira_connections').delete().eq('user_id', ctx.user.id);
  if (error) return fail('Could not remove the connection. Try again.');
  return { status: 'success', message: 'Jira disconnected. The stored token was deleted.' };
}

/** Opens an issue in the caller's own Jira project for a finding. */
export async function createJiraIssue(_prev: JiraActionState, formData: FormData): Promise<JiraActionState> {
  const parsed = JiraIssueSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const key = integrationKey();
  if (!key) return fail(NOT_CONFIGURED);
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');

  const row = await loadConnection(ctx.admin, ctx.user.id);
  if (!row) return fail('Connect Jira in Settings first.');
  const token = open(row.token_ciphertext, key);
  if (!token) return fail('The saved Jira token can no longer be read. Connect Jira again in Settings.');

  try {
    const { key: issueKey, url } = await postJiraIssue(toConnection(row), token, parsed.data);
    return { status: 'success', message: `Created ${issueKey}.`, issueUrl: url };
  } catch (err) {
    logger.warn('[Jira] Create issue failed:', err);
    return fail(err instanceof Error ? err.message : 'Jira did not create the issue.');
  }
}
