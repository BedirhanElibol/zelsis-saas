'use client';

import React from 'react';
import { Check, X, Minus } from 'lucide-react';
import Link from 'next/link';
import { priceLabel } from '@/data/pricing-plans';

export function CompetitorComparison() {
  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5" id="compare">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="max-w-3xl mb-16">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Honest pricing. Flat fee per account.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            Developer tools should scale with your product, not punish you for adding team members.
            Zelsis charges a flat rate per account, not per seat.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/10">
                <th className="py-4 px-6 font-medium text-white bg-[#141414] rounded-tl-xl w-1/4">Features</th>
                <th className="py-4 px-6 font-medium text-emerald-400 bg-emerald-500/5 border-x border-emerald-500/20 w-1/4">Zelsis</th>
                <th className="py-4 px-6 font-medium text-white bg-[#141414] w-1/6">Aikido</th>
                <th className="py-4 px-6 font-medium text-white bg-[#141414] w-1/6">Snyk</th>
                <th className="py-4 px-6 font-medium text-white bg-[#141414] rounded-tr-xl w-1/6">Semgrep</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-sm">
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-4 px-6 text-zinc-300 font-medium">Pricing Model</td>
                <td className="py-4 px-6 text-white bg-emerald-500/[0.02] border-x border-emerald-500/10">
                  Flat Fee (from {priceLabel('Pro')})
                </td>
                <td className="py-4 px-6 text-zinc-400">Per Seat (99 USD/mo)</td>
                <td className="py-4 px-6 text-zinc-400">Per Seat (25 USD/mo)</td>
                <td className="py-4 px-6 text-zinc-400">Per Developer (80 USD/mo)</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-4 px-6 text-zinc-300 font-medium">Free Tier</td>
                <td className="py-4 px-6 text-white bg-emerald-500/[0.02] border-x border-emerald-500/10">
                  Full SAST (3 repos)
                </td>
                <td className="py-4 px-6 text-zinc-400">Free (2 devs, basic limits)</td>
                <td className="py-4 px-6 text-zinc-400">Free (limits on tests)</td>
                <td className="py-4 px-6 text-zinc-400">Community Edition</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-4 px-6 text-zinc-300 font-medium">Next.js App Router Rules</td>
                <td className="py-4 px-6 text-white bg-emerald-500/[0.02] border-x border-emerald-500/10">
                  <Check className="w-5 h-5 text-emerald-500" />
                </td>
                <td className="py-4 px-6 text-zinc-500"><Minus className="w-5 h-5" /> Generic JS</td>
                <td className="py-4 px-6 text-zinc-500"><Minus className="w-5 h-5" /> Generic JS</td>
                <td className="py-4 px-6 text-zinc-500">Requires custom rules</td>
              </tr>
              <tr className="hover:bg-white/[0.02] transition-colors">
                <td className="py-4 px-6 text-zinc-300 font-medium">Supabase Auth/RLS Rules</td>
                <td className="py-4 px-6 text-white bg-emerald-500/[0.02] border-x border-emerald-500/10 rounded-b-xl">
                  <Check className="w-5 h-5 text-emerald-500" />
                </td>
                <td className="py-4 px-6 text-zinc-500"><X className="w-5 h-5" /></td>
                <td className="py-4 px-6 text-zinc-500"><X className="w-5 h-5" /></td>
                <td className="py-4 px-6 text-zinc-500">Requires custom rules</td>
              </tr>
            </tbody>
          </table>
        </div>
        
        <p className="mt-6 text-xs text-zinc-500">
          * Prices gathered from official websites as of October 2026. Snyk and Semgrep have excellent generic engines; Zelsis specializes specifically in the Next.js and Supabase ecosystem. <Link href="https://aikido.dev/pricing" target="_blank" className="underline hover:text-zinc-300">Aikido Pricing</Link> | <Link href="https://snyk.io/plans/" target="_blank" className="underline hover:text-zinc-300">Snyk Pricing</Link> | <Link href="https://semgrep.dev/pricing/" target="_blank" className="underline hover:text-zinc-300">Semgrep Pricing</Link>.
        </p>
      </div>
    </section>
  );
}
