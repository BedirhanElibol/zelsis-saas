import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { CONTACT_EMAIL, contactMailto } from '@/lib/contact';

export const metadata: Metadata = {
  title: 'Do Not Sell or Share My Personal Information',
  description: 'California Consumer Privacy Act (CCPA/CPRA) notice: Zelsis does not sell or share personal information or source code data.',
};

export default function DoNotSellPage() {
  return (
    <div className="min-h-screen bg-[#0D0D0D] text-[#F8FAFC] p-6 sm:p-12 font-sans">
      <div className="max-w-3xl mx-auto flex flex-col gap-8">
        <div className="flex items-center justify-between">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-xs font-mono text-[#888888] hover:text-[#FFFFFF] transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded"
          >
            <ArrowLeft size={14} />
            <span>Back to Home</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              href="/privacy"
              className="text-xs font-mono text-emerald-400 hover:underline focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded"
            >
              Privacy Policy
            </Link>
            <span className="text-[#333]">/</span>
            <Link
              href="/cookies"
              className="text-xs font-mono text-emerald-400 hover:underline focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded"
            >
              Cookie Policy
            </Link>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2.5 mb-2">
            <ShieldCheck size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Notice of Right to Opt-Out
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            California Consumer Privacy Act (CCPA/CPRA) &amp; Global Opt-Out Standards
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <div className="bg-[#141414] border border-emerald-500/20 rounded-xl p-4 sm:p-5 flex items-start gap-3.5">
            <CheckCircle2 size={20} className="text-emerald-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h2 className="text-sm font-bold text-white">Zelsis Zero-Data-Sale Guarantee</h2>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                Zelsis does not sell, rent, monetize, trade, or transfer your personal data, developer account metadata, or proprietary source code to data brokers or third parties for monetary or other valuable consideration.
              </p>
            </div>
          </div>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Understanding California Privacy Rights (CCPA / CPRA)</h2>
            <p>
              Under the California Consumer Privacy Act, as amended by the California Privacy Rights Act (CPRA), California residents have the right to direct businesses not to sell or share their personal information for cross-context behavioral advertising.
            </p>
            <p>
              While Zelsis does not sell personal information as traditionally understood, certain state privacy laws define &quot;sale&quot; and &quot;sharing&quot; broadly to encompass non-monetary exchanges such as cross-site analytics or retargeting pixels.
            </p>
          </section>

          <section className="flex flex-col gap-3">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. What Information Zelsis Processes</h2>
            <div className="bg-[#141414] border border-[#262626] rounded-xl p-4 text-xs font-mono space-y-2 text-[#A1A1AA]">
              <div><strong className="text-white">Source Code:</strong> Processed in-memory during release gate audits. Never persisted to disk, never shared, never sold.</div>
              <div><strong className="text-white">Audit Telemetry:</strong> Stored strictly in your account for release pass/fail histories and compliance reports.</div>
              <div><strong className="text-white">Third-Party Tracking:</strong> Zero third-party ad networks, data brokers, or cross-app tracking SDKs.</div>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. How to Submit an Opt-Out or Erasure Request</h2>
            <p>
              Even though Zelsis does not sell your information, you may submit a formal confirmation of your opt-out preference or request complete deletion of your account:
            </p>
            <ul className="list-disc list-inside space-y-1.5 text-[#AAAAAA]">
              <li>
                <strong>Email Request:</strong> Send an email to{' '}
                <a href={contactMailto()} className="text-emerald-400 font-mono underline focus-visible:ring-1 focus-visible:ring-emerald-500 rounded">
                  {CONTACT_EMAIL}
                </a>{' '}
                with the subject line <span className="font-mono text-zinc-300">&quot;CCPA Opt-Out / Data Erasure&quot;</span>.
              </li>
              <li>
                <strong>Self-Service Erasure:</strong> Authenticated developers may trigger immediate, permanent account and telemetry destruction directly within Dashboard Settings.
              </li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Global Privacy Control (GPC)</h2>
            <p>
              Zelsis honors universal opt-out preference signals including the Global Privacy Control (GPC). If your browser transmits a GPC signal, our system treats it as an automatic opt-out of non-essential tracking cookies.
            </p>
          </section>

          <section className="flex flex-col gap-2 border-t border-[#262626] pt-4">
            <div className="text-xs text-[#888888] font-mono">
              Contact: {CONTACT_EMAIL} // Compliance Officer: Bedirhan Elibol
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
