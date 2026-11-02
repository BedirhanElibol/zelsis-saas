'use client';

import React, { useActionState, useEffect, useState } from 'react';
import { Loader2, MessageSquareQuote, X } from 'lucide-react';
import { hasSentTestimonial, submitTestimonial } from '@/app/actions/testimonials';
import { initialTestimonialState } from '@/lib/testimonial-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

const DISMISS_KEY = 'zelsis:testimonial-dismissed';
const input = 'bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400';

/** Asks for a one-sentence quote once the user has a finished scan. Hidden after sending or dismissing. */
export function TestimonialPrompt({ hasScan }: { hasScan: boolean }) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [visible, setVisible] = useState(false);
  const [state, action, pending] = useActionState(submitTestimonial, initialTestimonialState);

  useEffect(() => {
    if (!hasScan) return;
    let dismissed = false;
    try {
      dismissed = localStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      /* storage blocked */
    }
    if (dismissed) return;
    void (async () => {
      const { accessToken: token } = await getActiveUserAuth();
      if (!token || (await hasSentTestimonial(token))) return;
      setAccessToken(token);
      setVisible(true);
    })();
  }, [hasScan]);

  if (!visible || !accessToken) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, '1');
    } catch {
      /* storage blocked */
    }
    setVisible(false);
  };

  return (
    <section aria-labelledby="testimonial-title" className="relative bg-[#141414] border border-white/10 rounded-2xl p-5 flex flex-col gap-3">
      <button type="button" onClick={dismiss} aria-label="Dismiss" className="absolute top-3 right-3 p-1 text-zinc-500 hover:text-white rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400">
        <X size={16} aria-hidden="true" />
      </button>
      <div className="flex items-center gap-2">
        <MessageSquareQuote size={16} className="text-emerald-400" aria-hidden="true" />
        <h2 id="testimonial-title" className="text-sm font-bold text-white m-0">Did Zelsis catch something real?</h2>
      </div>
      {state.status === 'success' ? (
        <p role="status" className="text-sm text-emerald-400 m-0">{state.message}</p>
      ) : (
        <form action={action} className="flex flex-col gap-2">
          <input type="hidden" name="accessToken" value={accessToken} />
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Tell us in one sentence
            <textarea name="quote" required minLength={10} maxLength={280} rows={2} placeholder="It found a webhook that would have charged customers twice." className={input} />
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Name shown<input name="displayName" required maxLength={80} placeholder="Jane D." className={input} /></label>
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Role and company (optional)<input name="role" maxLength={80} placeholder="CTO, Acme" className={input} /></label>
          </div>
          <label className="flex items-start gap-2 text-xs text-zinc-300">
            <input type="checkbox" name="consent" required className="mt-0.5 accent-emerald-500" />
            Zelsis may show this quote with the name and role above on zelsis.com.
          </label>
          <div className="flex items-center gap-3">
            <button type="submit" disabled={pending} className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 disabled:opacity-60 flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300">
              {pending && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
              Send
            </button>
            {state.status === 'error' && <p role="status" className="text-xs text-red-400 m-0">{state.message}</p>}
          </div>
        </form>
      )}
    </section>
  );
}
