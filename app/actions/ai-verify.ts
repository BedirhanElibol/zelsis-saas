'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { z } from 'zod';
import { getEffectivePlanTier } from '@/lib/organization';
import { logger } from '@/lib/logger';
import type { AiVerifySettings, AiVerifyActionState } from '@/lib/ai-verify-state';

const ToggleSchema = z.object({
  accessToken: z.string().min(1),
  enabled: z.enum(['true', 'false']),
});

async function getAuthedUser(accessToken: string): Promise<{ admin: SupabaseClient; user: User } | null> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceRoleKey) return null;
  const { data, error } = await createClient(url, anonKey, { auth: { persistSession: false } }).auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return { admin: createClient(url, serviceRoleKey, { auth: { persistSession: false } }), user: data.user };
}

async function settingsFor(admin: SupabaseClient, user: User): Promise<AiVerifySettings> {
  const tier = await getEffectivePlanTier(admin, user.id, user.email);
  return {
    enabled: user.app_metadata?.ai_verify === true,
    eligible: tier === 'Pro' || tier === 'Enterprise',
    available: Boolean(process.env.ANTHROPIC_API_KEY),
  };
}

/** The caller's AI double-check setting, or null when signed out. */
export async function getAiVerifySettings(accessToken: string): Promise<AiVerifySettings | null> {
  const ctx = await getAuthedUser(accessToken);
  return ctx ? settingsFor(ctx.admin, ctx.user) : null;
}

/** Turn the AI double-check on or off. Stored in app_metadata so only the server can change it. */
export async function setAiVerify(_prev: AiVerifyActionState, formData: FormData): Promise<AiVerifyActionState> {
  const parsed = ToggleSchema.safeParse({ accessToken: formData.get('accessToken'), enabled: formData.get('enabled') });
  if (!parsed.success) return { status: 'error', message: 'Invalid request.' };
  const ctx = await getAuthedUser(parsed.data.accessToken);
  if (!ctx) return { status: 'error', message: 'Your session expired. Sign in again.' };
  const enabled = parsed.data.enabled === 'true';
  const current = await settingsFor(ctx.admin, ctx.user);
  if (enabled && !current.eligible) return { status: 'error', message: 'The AI double-check is part of Pro and Team.' };
  const { error } = await ctx.admin.auth.admin.updateUserById(ctx.user.id, {
    app_metadata: { ...ctx.user.app_metadata, ai_verify: enabled },
  });
  if (error) {
    logger.error('AI verify setting not saved', error);
    return { status: 'error', message: 'Could not save the setting. Try again.' };
  }
  return { status: 'success', message: enabled ? 'AI double-check is on.' : 'AI double-check is off.' };
}
