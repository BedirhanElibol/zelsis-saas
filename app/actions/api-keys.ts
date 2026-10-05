'use server';

import crypto from 'crypto';
import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { ApiKeyCreateSchema, ApiKeyRevokeSchema } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';
import type { ApiKeyActionState, ApiKeySummary } from '@/lib/api-key-state';

/** Keys per account; the CI gate needs one per pipeline at most. */
const MAX_KEYS = 5;

const fail = (message: string): ApiKeyActionState => ({ status: 'error', message });

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

/** Lists the caller's keys (never the secret itself, only its prefix). */
export async function listApiKeys(accessToken: string): Promise<ApiKeySummary[]> {
  const ctx = await authenticate(accessToken);
  if (!ctx) return [];
  const { data } = await ctx.admin
    .from('api_keys')
    .select('id, key_name, prefix, last_used_at, created_at')
    .eq('user_id', ctx.user.id)
    .order('created_at', { ascending: false });
  return (data ?? []).map((k) => ({ id: k.id, name: k.key_name, prefix: k.prefix, lastUsedAt: k.last_used_at, createdAt: k.created_at }));
}

/** Creates a key for the CI release gate. The plaintext is returned once and only its SHA-256 hash is stored. */
export async function createApiKey(_prev: ApiKeyActionState, formData: FormData): Promise<ApiKeyActionState> {
  const parsed = ApiKeyCreateSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');

  const { count } = await ctx.admin.from('api_keys').select('id', { count: 'exact', head: true }).eq('user_id', ctx.user.id);
  if ((count ?? 0) >= MAX_KEYS) return fail(`You can have up to ${MAX_KEYS} keys. Revoke one first.`);

  const secret = `zls_live_${crypto.randomBytes(24).toString('base64url')}`;
  const { error } = await ctx.admin.from('api_keys').insert({
    user_id: ctx.user.id,
    key_name: parsed.data.name,
    key_hash: crypto.createHash('sha256').update(secret).digest('hex'),
    prefix: secret.slice(0, 13),
  });
  if (error) {
    logger.error('[API keys] Insert failed:', error.message);
    return fail('Could not create the key. Try again.');
  }
  return { status: 'success', message: 'Key created. Copy it now: it will not be shown again.', secret };
}

export async function revokeApiKey(_prev: ApiKeyActionState, formData: FormData): Promise<ApiKeyActionState> {
  const parsed = ApiKeyRevokeSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail('Invalid request');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');
  const { error } = await ctx.admin.from('api_keys').delete().eq('id', parsed.data.keyId).eq('user_id', ctx.user.id);
  if (error) return fail('Could not revoke the key.');
  return { status: 'success', message: 'Key revoked. Pipelines using it will stop passing the gate.' };
}
