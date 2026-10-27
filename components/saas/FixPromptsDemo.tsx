'use client';

import React, { useState } from 'react';
import { Check, Copy, Terminal } from 'lucide-react';

const PROMPT = `Zelsis flagged SAAS3-02 in app/api/stripe/webhook/route.ts.
The webhook adds credits on every checkout.session.completed event without remembering the event id, so a retried delivery pays the customer twice.

Fix it so that:
1. The handler stores event.id in a processed_events table with a unique constraint, and returns 200 without doing anything when the id is already there.
2. Recording the event and adding the credits happen in one transaction, so a crash in between cannot apply them twice.
Keep the route's signature verification and response codes unchanged.`;

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
    <section className="py-12 sm:py-14 bg-[#0A0A0A] border-t border-white/5">
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
