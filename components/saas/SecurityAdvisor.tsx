import React from 'react';
import { Database, FileCode2, Plus } from 'lucide-react';

/** Positions Zelsis next to Supabase Security Advisor: the Advisor inspects the live database, Zelsis the code. */
export function SecurityAdvisor() {
  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Use it with Supabase Security Advisor
        </h2>
        <p className="mt-4 text-lg text-zinc-400 max-w-2xl mx-auto">
          The Advisor inspects your live database. Zelsis reads your code and migrations before they ship, so a mistake is caught
          in the pull request instead of in production. They cover different halves of the stack.
        </p>

        <div className="mt-14 flex flex-col md:flex-row items-stretch justify-center gap-6 md:gap-10">
          <div className="bg-[#141414] border border-white/10 rounded-xl p-8 w-full max-w-sm flex flex-col items-center">
            <div className="w-14 h-14 rounded-full bg-white/5 flex items-center justify-center mb-5 text-zinc-300">
              <Database className="w-7 h-7" aria-hidden="true" />
            </div>
            <h3 className="text-xl font-bold text-white mb-1">Supabase Security Advisor</h3>
            <p className="text-xs font-mono text-zinc-500 mb-4">Your live database</p>
            <ul className="text-zinc-400 text-sm space-y-2">
              <li>Tables exposed without RLS</li>
              <li>SECURITY DEFINER functions and views callable via the API</li>
              <li>Functions with a mutable search_path</li>
              <li>Auth settings such as leaked-password protection</li>
            </ul>
          </div>

          <Plus className="w-7 h-7 text-zinc-600 self-center hidden md:block" aria-hidden="true" />

          <div className="bg-[#141414] border border-emerald-500/30 rounded-xl p-8 w-full max-w-sm flex flex-col items-center">
            <div className="w-14 h-14 rounded-full bg-emerald-500/15 flex items-center justify-center mb-5 text-emerald-400">
              <FileCode2 className="w-7 h-7" aria-hidden="true" />
            </div>
            <h3 className="text-xl font-bold text-white mb-1">Zelsis</h3>
            <p className="text-xs font-mono text-zinc-500 mb-4">Your code, before it ships</p>
            <ul className="text-zinc-400 text-sm space-y-2">
              <li>Service-role key used in Server Actions or client code</li>
              <li>Policies that trust user-editable metadata</li>
              <li>Webhooks without signature checks or idempotency</li>
              <li>Secrets committed or bundled into the browser</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
