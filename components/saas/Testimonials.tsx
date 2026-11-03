import React from 'react';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import type { PublicTestimonial } from '@/lib/testimonial-state';

async function approvedTestimonials(): Promise<PublicTestimonial[]> {
  const admin = getSupabaseAdmin();
  if (!admin) return [];
  const { data, error } = await admin
    .from('testimonials')
    .select('quote, display_name, role')
    .eq('status', 'approved')
    .eq('consent', true)
    .order('updated_at', { ascending: false })
    .limit(6);
  if (error) {
    logger.warn('[Testimonials] Load failed:', error);
    return [];
  }
  return (data ?? []).map((r) => ({ quote: r.quote as string, displayName: r.display_name as string, role: (r.role as string | null) ?? null }));
}

/** Quotes users sent and the owner approved. Renders nothing until there is at least one. */
export async function Testimonials() {
  const quotes = await approvedTestimonials();
  if (quotes.length === 0) return null;

  return (
    <section id="testimonials" className="py-12 sm:py-14 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-7xl mx-auto flex flex-col gap-10">
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="text-xs uppercase tracking-widest text-emerald-400">From people who ship with it</div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">What it caught for them</h2>
        </div>
        <ul className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 list-none p-0 m-0">
          {quotes.map((q) => (
            <li key={`${q.displayName}-${q.quote.slice(0, 20)}`} className="flex flex-col gap-4 rounded-2xl border border-white/10 bg-[#121214] p-5">
              <blockquote className="text-base text-zinc-200 leading-relaxed m-0">{q.quote}</blockquote>
              <p className="mt-auto text-sm text-zinc-400 m-0">
                <span className="font-semibold text-white">{q.displayName}</span>
                {q.role ? `, ${q.role}` : ''}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
