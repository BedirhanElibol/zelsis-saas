'use client';

import React, { useState } from 'react';
import { Check, Copy, Terminal } from 'lucide-react';

const PROMPT = `Zelsis flagged NEXT-SB-01 in app/dashboard/projects/actions.ts.
The Server Action deleteProject() deletes with the Supabase service-role client, which bypasses RLS, and never checks who is calling.

Fix it so that:
1. The action gets the signed-in user with createServerClient() and auth.getUser(), and returns early when there is none.
2. The delete is scoped to rows the user owns (.eq('owner_id', user.id)), or uses the user's own client so RLS applies.
Keep the function signature and return shape unchanged.`;

/** Example of the fix prompt attached to every finding, ready to paste into an AI coding assistant. */
export function FixPromptsDemo() {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(PROMPT);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              A fix prompt for every finding.
            </h2>
            <p className="mt-4 text-lg text-zinc-400">
              Each finding comes with the file, the line and a precise instruction you can paste into Claude, ChatGPT or Cursor.
              Your assistant gets the context it needs, and you review the change like any other diff.
            </p>
          </div>

          <div className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden shadow-2xl min-w-0">
            <div className="bg-black/40 px-4 py-3 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-zinc-400">
                <Terminal className="w-4 h-4" aria-hidden="true" />
                <span>Fix prompt</span>
              </div>
              <button
                type="button"
                onClick={handleCopy}
                className="text-xs flex items-center gap-1.5 bg-white/5 hover:bg-white/10 text-zinc-300 px-3 py-1.5 rounded transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                <span aria-live="polite">{copied ? 'Copied' : 'Copy prompt'}</span>
              </button>
            </div>
            <pre className="p-5 font-mono text-xs sm:text-sm leading-relaxed text-zinc-300 whitespace-pre-wrap">{PROMPT}</pre>
          </div>
        </div>
      </div>
    </section>
  );
}
