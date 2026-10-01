import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck, ArrowLeft } from 'lucide-react';
import { CONTACT_EMAIL, contactMailto } from '@/lib/contact';

export const metadata: Metadata = {
  title: 'Privacy Policy & Data Protection',
  description: 'Zelsis Global Privacy Policy, GDPR & CCPA compliance, telemetry data handling, and zero codebase retention policy.',
};

export default function PrivacyPolicyPage() {
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
              href="/cookies"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Cookie Policy
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
            <ShieldCheck size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Privacy Policy &amp; Data Protection
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 10, 2026 // Global Compliance (GDPR EU 2016/679 &amp; CCPA/CPRA)
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Data Controller &amp; Operating Entity</h2>
            <p>
              Zelsis (&quot;we&quot;, &quot;our&quot;, or &quot;us&quot;) operates the Zelsis Pre-Flight Release Gate SaaS platform. This Privacy Policy outlines our global data processing practices for international users, in full alignment with the European Union General Data Protection Regulation (GDPR), the Turkish Law on the Protection of Personal Data (KVKK No. 6698), the California Consumer Privacy Act (CCPA/CPRA), and standard international data privacy principles.
            </p>
            <div className="bg-[#141414] border border-[#262626] rounded-xl p-3 text-xs font-mono text-[#AAAAAA] mt-1 space-y-1">
              <div><strong className="text-white">Operating Entity:</strong> Zelsis Technologies (Bedirhan Elibol)</div>
              <div><strong className="text-white">Operations:</strong> Istanbul, Turkey // Global Edge SaaS Operations</div>
              <div><strong className="text-white">Data Protection Office:</strong> {CONTACT_EMAIL}</div>
              <div><strong className="text-white">Legal &amp; Business Inquiries:</strong> {CONTACT_EMAIL}</div>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. Zero Codebase Retention Architecture</h2>
            <p>
              Source code submitted for static security analysis, secret detection, and architectural hygiene checks is processed in ephemeral serverless execution environments. <strong>We never store, index, sell, or train public AI/LLM models on your proprietary source code.</strong> As soon as the static security evaluation completes, in-memory buffers are permanently purged.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Categories of Personal Data Collected</h2>
            <ul className="list-disc list-inside space-y-1.5 text-[#AAAAAA]">
              <li><strong>Account Credentials:</strong> Name, email address, GitHub username, avatar URL (when authenticated via GitHub OAuth).</li>
              <li><strong>Telemetry &amp; Audit Logs:</strong> Timestamps of security scans, pass/warning/failed clearance scores, rule violation counts.</li>
              <li><strong>Technical Metadata:</strong> IP address, browser user-agent, secure encrypted session tokens.</li>
              <li><strong>Billing Records:</strong> Subscription plan tier, license keys, and transaction identifiers tokenized by PCI-DSS Level 1 certified payment gateways (Polar / Stripe). We never process or store raw payment card credentials.</li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Legal Grounds for Processing (GDPR Art. 6)</h2>
            <ul className="list-disc list-inside space-y-1 text-[#AAAAAA]">
              <li><strong>Contractual Performance:</strong> Providing automated release gate services, processing repository audits, and managing developer subscriptions.</li>
              <li><strong>Legitimate Interests:</strong> Protecting platform security, preventing abuse or denial-of-service attacks, and optimizing scanner performance.</li>
              <li><strong>Legal Compliance:</strong> Satisfying statutory taxation, financial accounting, and international reporting obligations.</li>
            </ul>
          </section>

          <section className="flex flex-col gap-3">
            <h2 className="text-base font-bold text-[#FFFFFF]">5. Subprocessors &amp; Cloud Infrastructure</h2>
            <p>
              To deliver high-availability, zero-latency release gates, Zelsis engages vetted third-party subprocessors. Each subprocessor operates under a Data Processing Addendum (DPA) incorporating European Commission Standard Contractual Clauses (SCCs):
            </p>
            <div className="overflow-x-auto border border-[#262626] rounded-xl">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141414] border-b border-[#262626] text-[#EDEDED]">
                  <tr>
                    <th className="p-2.5 font-bold">Subprocessor</th>
                    <th className="p-2.5 font-bold">Role / Purpose</th>
                    <th className="p-2.5 font-bold">Location</th>
                    <th className="p-2.5 font-bold">Security Standard</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262626] text-[#A1A1AA]">
                  <tr>
                    <td className="p-2.5 text-white font-bold">Supabase Inc.</td>
                    <td className="p-2.5">Managed PostgreSQL database, Auth &amp; Telemetry persistence</td>
                    <td className="p-2.5">USA (AWS us-east-1)</td>
                    <td className="p-2.5 text-emerald-400">SOC 2 Type II, AES-256</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-white font-bold">Vercel Inc.</td>
                    <td className="p-2.5">Global edge hosting, Serverless API execution &amp; CDN</td>
                    <td className="p-2.5">USA / Global Anycast Edge</td>
                    <td className="p-2.5 text-emerald-400">SOC 2 Type II, ISO 27001</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-white font-bold">Polar Software Inc.</td>
                    <td className="p-2.5">Merchant of Record, Global tax remittance &amp; billing checkout</td>
                    <td className="p-2.5">USA / EU</td>
                    <td className="p-2.5 text-emerald-400">PCI-DSS Level 1, DPA</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-white font-bold">GitHub Inc. (Microsoft)</td>
                    <td className="p-2.5">OAuth login provider &amp; source code repository sync API</td>
                    <td className="p-2.5">USA</td>
                    <td className="p-2.5 text-emerald-400">SOC 2 Type II, TLS 1.3</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">6. Data Subject Rights &amp; Erasure (GDPR Art. 17 / CCPA)</h2>
            <p>
              You maintain full rights to access, rectify, port, or permanently delete your account and all associated telemetry. You can execute permanent account destruction in your Project Settings dashboard (&quot;GDPR / CCPA Data Erasure&quot;) or submit a formal deletion request to{' '}
              <a href={contactMailto()} className="text-[#FFFFFF] underline underline-offset-4 font-mono">
                {CONTACT_EMAIL}
              </a>.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">7. Turkish Personal Data Protection Law (KVKK No. 6698)</h2>
            <p>
              For users located in Turkey or subject to the Republic of Turkey Law on the Protection of Personal Data No. 6698 (KVKK), Zelsis processes data strictly under Article 5 (establishment and performance of the contract, fulfillment of legal obligations, and legitimate interests of the data controller). In accordance with KVKK Article 11, data subjects are entitled to inquire about their personal data, request correction, request erasure upon cessation of processing reasons, and learn of third-party transfers. Requests may be directed to <a href={contactMailto()} className="text-emerald-400 underline">{CONTACT_EMAIL}</a>.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">8. Contact &amp; Inquiries</h2>
            <p className="font-mono text-xs text-emerald-400">
              {CONTACT_EMAIL} // Attn: Data Protection Desk
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
