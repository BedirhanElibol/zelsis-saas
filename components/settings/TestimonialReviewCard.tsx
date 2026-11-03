'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { listTestimonialsForReview, reviewTestimonial } from '@/app/actions/testimonials';
import { initialTestimonialState, type ReviewTestimonial } from '@/lib/testimonial-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

const STATUS_STYLE: Record<ReviewTestimonial['status'], string> = {
  pending: 'text-amber-300 border-amber-400/30',
  approved: 'text-emerald-300 border-emerald-400/30',
  rejected: 'text-zinc-400 border-white/10',
};

const ACTIONS: { status: ReviewTestimonial['status']; label: string }[] = [
  { status: 'approved', label: 'Approve' },
  { status: 'rejected', label: 'Reject' },
  { status: 'pending', label: 'Back to review' },
];

/** Owner-only list of quotes users sent from the dashboard. Approved ones appear on the landing page. */
export function TestimonialReviewCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [items, setItems] = useState<ReviewTestimonial[] | null>(null);
  const [state, action, pending] = useActionState(reviewTestimonial, initialTestimonialState);

  const refresh = useCallback(async () => {
    const { accessToken: token } = await getActiveUserAuth();
    setAccessToken(token);
    setItems(token ? await listTestimonialsForReview(token) : null);
  }, []);

  useEffect(() => { void refresh(); }, [refresh, state]);

  if (!accessToken || items === null) return null;
  const waiting = items.filter((t) => t.status === 'pending').length;

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-sm font-bold text-white">User quotes</h2>
        <span className="text-xs text-zinc-400">{waiting} waiting for review</span>
      </div>
      <p className="text-xs text-zinc-400">Only you see this. Approved quotes show on the landing page.</p>

      {items.length === 0 ? (
        <p className="text-xs text-zinc-500">No quotes yet.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {items.map((t) => (
            <li key={t.userId} className="border border-white/10 rounded-xl p-4 flex flex-col gap-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex flex-col gap-1 min-w-0">
                  <p className="text-sm text-zinc-200 break-words">&ldquo;{t.quote}&rdquo;</p>
                  <p className="text-xs text-zinc-400">
                    {t.displayName}{t.role ? `, ${t.role}` : ''} · {new Date(t.updatedAt).toLocaleDateString()}
                  </p>
                </div>
                <span className={`shrink-0 px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase ${STATUS_STYLE[t.status]}`}>{t.status}</span>
              </div>
              <form action={action} className="flex flex-wrap gap-2">
                <input type="hidden" name="accessToken" value={accessToken} />
                <input type="hidden" name="userId" value={t.userId} />
                {ACTIONS.filter((a) => a.status !== t.status).map((a) => (
                  <button
                    key={a.status}
                    type="submit"
                    name="status"
                    value={a.status}
                    disabled={pending}
                    className={`px-3 py-1.5 rounded-lg border text-xs disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 ${a.status === 'approved' ? 'border-emerald-400/40 text-emerald-300 hover:bg-emerald-400/10' : 'border-white/10 text-zinc-300 hover:text-white'}`}
                  >
                    {a.label}
                  </button>
                ))}
              </form>
            </li>
          ))}
        </ul>
      )}

      {pending && <Loader2 size={13} className="animate-spin text-zinc-400" aria-hidden="true" />}
      {state.status === 'error' && <p role="alert" className="text-xs text-red-400">{state.message}</p>}
    </section>
  );
}
