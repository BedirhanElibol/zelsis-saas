'use client';

import React from 'react';
import { Database, FileCode2, Plus, Shield } from 'lucide-react';

export function SecurityAdvisor() {
  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5">
      <div className="max-w-7xl mx-auto px-6 lg:px-8 text-center">
        <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          The perfect companion to Supabase Security Advisor
        </h2>
        <p className="mt-4 text-lg text-zinc-400 max-w-2xl mx-auto">
          Supabase Security Advisor is fantastic at identifying Postgres misconfigurations. 
          Zelsis protects the other half of your stack: the application code. Use them together for end-to-end security.
        </p>

        <div className="mt-16 flex flex-col md:flex-row items-center justify-center gap-8 md:gap-12">
          {/* Supabase Advisor */}
          <div className="bg-[#141414] border border-white/10 rounded-xl p-8 w-full max-w-sm flex flex-col items-center">
            <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mb-6 text-emerald-400">
              <Database className="w-8 h-8" />
            </div>
            <h3 className="text-xl font-bold text-white mb-3">Supabase Advisor</h3>
            <ul className="text-zinc-400 text-sm space-y-2 text-center">
              <li>Postgres configuration</li>
              <li>Weak database passwords</li>
              <li>Unrestricted network access</li>
              <li>Database extensions</li>
            </ul>
          </div>

          <Plus className="w-8 h-8 text-zinc-600 hidden md:block" />

          {/* Zelsis */}
          <div className="bg-[#141414] border border-emerald-500/20 rounded-xl p-8 w-full max-w-sm flex flex-col items-center relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500/0 via-emerald-500 to-emerald-500/0 opacity-50" />
            <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mb-6 text-emerald-400">
              <FileCode2 className="w-8 h-8" />
            </div>
            <h3 className="text-xl font-bold text-white mb-3">Zelsis</h3>
            <ul className="text-zinc-400 text-sm space-y-2 text-center">
              <li>Next.js Server Actions</li>
              <li>RLS bypass in client code</li>
              <li>Service-role key leaks</li>
              <li>Webhook signatures</li>
            </ul>
          </div>
        </div>

        <div className="mt-12 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm font-medium">
          <Shield className="w-4 h-4" />
          Together, they form an impenetrable shield for your full stack.
        </div>
      </div>
    </section>
  );
}
