import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Cookie, Shield, Lock } from 'lucide-react';
import { CONTACT_EMAIL, contactMailto } from '@/lib/contact';

export const metadata: Metadata = {
  title: 'Cookie Policy',
  description: 'Zelsis Cookie Policy, technical session tokens, and privacy controls.',
};

export default function CookiePolicyPage() {
  return (
    <div className="min-h-screen bg-[#0D0D0D] text-[#F8FAFC] p-6 sm:p-12 font-sans">
      <div className="max-w-3xl mx-auto flex flex-col gap-8">
        <div className="flex items-center justify-between">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-xs font-mono text-[#888888] hover:text-[#FFFFFF] transition-colors"
          >
            <ArrowLeft size={14} />
            <span>Back to Home</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              href="/privacy"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Privacy Policy
            </Link>
            <span className="text-[#333]">/</span>
            <Link
              href="/terms"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Terms of Service
            </Link>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2.5 mb-2">
            <Cookie size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Cookie Policy
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 10, 2026 // Global Compliance (GDPR / ePrivacy / CCPA)
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. How We Use Cookies</h2>
            <p>
              Zelsis employs strictly essential, functional cookies and secure client storage to maintain authenticated developer sessions, preserve scan configuration preferences, and protect against Cross-Site Request Forgery (CSRF). We do not use intrusive third-party cross-site advertising or surveillance trackers.
            </p>
          </section>

          <section className="flex flex-col gap-3">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. Essential Cookies Matrix</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border border-white/10 rounded-xl overflow-hidden">
                <thead>
                  <tr className="border-b border-white/10 text-[#A1A1AA] bg-white/5">
                    <th className="py-2.5 px-3">Cookie Name</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Duration</th>
                    <th className="py-2.5 px-3">Purpose</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-[#D4D4D8]">
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_user</td>
                    <td className="py-3 px-3">Strictly Necessary</td>
                    <td className="py-3 px-3">30 Days</td>
                    <td className="py-3 px-3 font-sans text-xs">Stores active authenticated session state and license authorization level. Secured with SameSite=Lax and Secure flags.</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_cookie_consent</td>
                    <td className="py-3 px-3">Functional</td>
                    <td className="py-3 px-3">1 Year</td>
                    <td className="py-3 px-3 font-sans text-xs">Records your cookie acknowledgment and preference settings.</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_data_version</td>
                    <td className="py-3 px-3">Functional (Local)</td>
                    <td className="py-3 px-3">Persistent</td>
                    <td className="py-3 px-3 font-sans text-xs">Ensures local scanner catalog rule schemas are up to date.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Managing &amp; Disabling Cookies</h2>
            <p>
              Most web browsers permit you to control or block cookies through their system settings. Note that disabling strictly necessary cookies may restrict access to the authenticated dashboard or prevent saving custom repository release criteria.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Contact</h2>
            <p>
              For inquiries regarding our technical cookies or data handling practices, please contact our privacy desk at{' '}
              <a href={contactMailto()} className="text-emerald-400 underline font-mono">
                {CONTACT_EMAIL}
              </a>.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
