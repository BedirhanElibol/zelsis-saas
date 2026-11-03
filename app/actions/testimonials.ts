'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { revalidatePath } from 'next/cache';
import { TestimonialReviewSchema, TestimonialSchema } from '@/lib/validations/api-schemas';
import { isPlatformAdminEmail } from '@/lib/subscription-utils';
import { logger } from '@/lib/logger';
import type { ReviewTestimonial, TestimonialActionState } from '@/lib/testimonial-state';

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

/** Every quote for the owner to review, newest first. Null for anyone who is not a platform admin. */
export async function listTestimonialsForReview(accessToken: string): Promise<ReviewTestimonial[] | null> {
  const ctx = typeof accessToken === 'string' ? await authenticate(accessToken) : null;
  if (!ctx || !isPlatformAdminEmail(ctx.user.email)) return null;
  const { data, error } = await ctx.admin
    .from('testimonials')
    .select('user_id, quote, display_name, role, status, updated_at')
    .order('updated_at', { ascending: false })
    .limit(100);
  if (error) {
    logger.error('[Testimonials] Review list failed:', error);
    return [];
  }
  return (data ?? []).map((r) => ({
    userId: r.user_id,
    quote: r.quote,
    displayName: r.display_name,
    role: r.role,
    status: r.status,
    updatedAt: r.updated_at,
  }));
}

/** Approves, rejects or reopens one quote (platform admins only). Approved quotes show on the landing page. */
export async function reviewTestimonial(_prev: TestimonialActionState, formData: FormData): Promise<TestimonialActionState> {
  const parsed = TestimonialReviewSchema.safeParse(formObject(formData));
  if (!parsed.success) return fail(parsed.error.issues[0]?.message ?? 'Invalid input');
  const ctx = await authenticate(parsed.data.accessToken);
  if (!ctx || !isPlatformAdminEmail(ctx.user.email)) return fail('Only the site owner can review quotes.');

  const { error } = await ctx.admin
    .from('testimonials')
    .update({ status: parsed.data.status, updated_at: new Date().toISOString() })
    .eq('user_id', parsed.data.userId);
  if (error) {
    logger.error('[Testimonials] Review failed:', error);
    return fail('Could not update it. Try again.');
  }
  revalidatePath('/');
  return { status: 'success', message: `Marked ${parsed.data.status}.` };
}
