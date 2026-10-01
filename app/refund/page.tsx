import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck, ArrowLeft, RefreshCw } from 'lucide-react';
import { CONTACT_EMAIL } from '@/lib/contact';

export const metadata: Metadata = {
  title: 'Refund & Cancellation Policy',
  description: 'Zelsis 14-day money-back guarantee, subscription cancellation policy, and transparent refund workflows.',
};

export default function RefundPage() {
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
              href="/terms"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Terms of Service
            </Link>
            <span className="text-[#333]">/</span>
            <Link
              href="/privacy"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Privacy Policy
            </Link>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2.5 mb-2">
            <RefreshCw size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Refund &amp; Cancellation Policy
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 16, 2026 // Global Consumer &amp; Merchant Protection
          </p>
        </div>

        {/* Highlight Guarantee Box */}
        <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex flex-col sm:flex-row items-start sm:items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400">
            <ShieldCheck size={22} />
          </div>
          <div className="flex flex-col gap-1">
            <h2 className="text-sm font-bold text-white">14-Day Unconditional Money-Back Guarantee</h2>
            <p className="text-xs text-zinc-300 leading-relaxed">
              If Zelsis does not provide immediate value for your production release workflow, you can request a 100% full refund within 14 calendar days of your initial plan purchase. No questions asked.
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Overview &amp; Commitment</h2>
            <p>
              At Zelsis (&quot;we&quot;, &quot;our&quot;, or &quot;us&quot;), we stand behind our automated pre-flight security clearance and release gate software. We are committed to complete pricing transparency and consumer protection in accordance with global commercial standards and ad network merchant guidelines (including Google Ads and Meta Ads policies).
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. 14-Day Money-Back Guarantee</h2>
            <p>
              All first-time subscription purchases (Pro and Enterprise monthly plans) are backed by our 14-day money-back guarantee. If you are unsatisfied with the scanning results, rule coverage, or user experience for any reason, submit a request within 14 days of the transaction timestamp for a complete 100% refund.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Self-Service Subscription Cancellation</h2>
            <p>
              You maintain total control over your recurring subscription. You may cancel your subscription at any time without penalty or cancellation fees:
            </p>
            <ul className="list-disc pl-5 flex flex-col gap-1.5 text-zinc-300">
              <li>Navigate to <strong>Dashboard &gt; Settings &gt; Billing &amp; Plan</strong> inside your Zelsis account.</li>
              <li>Click <strong>&quot;Manage Billing on Polar / Stripe&quot;</strong> to view active subscriptions.</li>
              <li>Select <strong>&quot;Cancel Subscription&quot;</strong>. Your cancellation takes effect immediately at the end of the current billing cycle.</li>
              <li>You will retain full access to paid audit features until the current prepaid period expires.</li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Automatic Renewal Refunds</h2>
            <p>
              Subscriptions renew automatically at the end of each billing cycle unless cancelled prior to the renewal date. If your account was unintentionally renewed, contact our support team within <strong>48 hours</strong> of the renewal charge. As long as no subsequent premium scans have been initiated during that cycle, we will process a full courtesy refund and cancel future billings.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">5. Refund Processing Timelines &amp; Methods</h2>
            <p>
              Once approved, refunds are credited back to the original payment method (Credit/Debit card, Apple Pay, Google Pay) used during checkout.
            </p>
            <p>
              Refund processing typically takes <strong>3 to 5 business days</strong> to reflect on your bank statement, depending on your card issuer or banking institution.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">6. How to Request a Refund</h2>
            <p>
              To initiate a refund request under the 14-day guarantee or inquire about a billing charge, contact our developer support team directly:
            </p>
            <div className="p-4 rounded-lg bg-[#141414] border border-white/10 flex flex-col gap-1 font-mono text-xs text-zinc-300">
              <div><strong>Email:</strong> {CONTACT_EMAIL}</div>
              <div><strong>Subject:</strong> Refund Request - [Your Account Email]</div>
              <div><strong>Response Window:</strong> Dedicated response within 24 business hours</div>
            </div>
            <p className="text-zinc-400 text-xs">
              Please include your checkout email address, project repository name, or Polar/Stripe invoice number to expedite processing.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">7. Chargebacks and Dispute Policy</h2>
            <p>
              We encourage customers to contact us directly prior to filing a dispute or chargeback with their bank. We reply to billing requests within 2 business days and can issue refunds faster than the standard 60-day bank resolution process.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
