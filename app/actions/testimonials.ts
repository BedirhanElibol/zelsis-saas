'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { TestimonialSchema } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';
import type { TestimonialActionState } from '@/lib/testimonial-state';

const fail = (message: string): TestimonialActionState => ({ status: 'error', message });

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

/** Whether the caller already sent a quote, so the prompt is not shown again. */
export async function hasSentTestimonial(accessToken: string): Promise<boolean> {
  const ctx = typeof accessToken === 'string' ? await authenticate(accessToken) : null;
  if (!ctx) return true;
  const { data } = await ctx.admin.from('testimonials').select('user_id').eq('user_id', ctx.user.id).maybeSingle();
  return !!data;
}

/** Saves the caller's quote for review. Sending again replaces it and puts it back in review. */
export async function submitTestimonial(_prev: TestimonialActionState, formData: FormData): Promise<TestimonialActionState> {
  const parsed = TestimonialSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx) return fail('Your session expired. Sign in again.');

  const { error } = await ctx.admin.from('testimonials').upsert({
    user_id: ctx.user.id,
    quote: parsed.data.quote,
    display_name: parsed.data.displayName,
    role: parsed.data.role || null,
    consent: true,
    status: 'pending',
    updated_at: new Date().toISOString(),
  });
  if (error) {
    logger.error('[Testimonials] Save failed:', error);
    return fail('Could not save it. Try again.');
  }
  return { status: 'success', message: 'Thank you. We read every one before it goes on the site.' };
}
