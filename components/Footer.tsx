'use client';

import React from 'react';
import { ShieldCheck, ArrowUpRight } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import { CONTACT_EMAIL } from '@/lib/contact';

export const Footer: React.FC = () => {
  return (
    <footer className="bg-[#0A0A0A] text-[#A1A1AA] border-t border-white/10 pt-20 pb-12 px-6">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-12 pb-16 border-b border-white/10">
        {/* Col 1: Brand Info (5 cols) */}
        <div className="md:col-span-5 flex flex-col gap-4">
          <ZelsisLogo size="md" />

          <p className="text-sm leading-relaxed max-w-sm text-[#A1A1AA]">
            Universal pre-flight release gate for modern web and cloud applications. Automated OWASP security clearance, WCAG 2.2 AA accessibility, and cloud infrastructure verification.
          </p>

          <div className="flex flex-col gap-1.5 mt-2 text-xs font-mono text-zinc-400">
            <span className="text-white font-semibold">Zelsis Software Technologies</span>
            <span className="inline-flex items-center gap-1 text-zinc-300">
              <span>{CONTACT_EMAIL}</span>
              <ArrowUpRight size={12} />
            </span>
            <span>Support: reply within 2 business days</span>
            <span className="text-[11px] text-zinc-400">Istanbul &amp; Global Edge Infrastructure</span>
          </div>
        </div>

        {/* Col 2: Navigation (3 cols) */}
        <div className="md:col-span-3 flex flex-col gap-3">
          <span className="text-xs font-bold text-white font-mono tracking-widest uppercase mb-2">
            NAVIGATION
          </span>
          <a href="#features" className="text-sm hover:text-white transition-colors">
            Platform Features
          </a>
          <a href="#workflow" className="text-sm hover:text-white transition-colors">
            How It Works
          </a>
          <a href="#pricing" className="text-sm hover:text-white transition-colors">
            Pricing Plans
          </a>
        </div>

        {/* Col 3: SaaS Platform (4 cols) */}
        <div className="md:col-span-4 flex flex-col gap-3">
          <span className="text-xs font-bold text-[#EDEDED] tracking-widest uppercase mb-2 font-mono">
            ZELSIS PLATFORM
          </span>
          <a href="/dashboard" className="text-sm text-white hover:underline transition-colors font-mono">
            Launch Audit Engine →
          </a>
          <span className="text-xs text-[#A1A1AA]">Deterministic Pre-Flight Vulnerability Clearance</span>
          <span className="text-xs text-[#A1A1AA]">Automated WCAG 2.2 AA &amp; UX Audit Gates</span>
          <span className="text-xs text-[#A1A1AA]">Cloud Infrastructure &amp; Container Hardening</span>
        </div>


      </div>

      {/* Bottom Bar */}
      <div className="max-w-7xl mx-auto pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#A1A1AA]">
        <div>
          © 2026 Zelsis Software Technologies. All rights reserved.
        </div>
        <div className="flex flex-wrap gap-4 sm:gap-6">
          <a href="/privacy" className="hover:text-white transition-colors">Privacy &amp; Cookies</a>
          <a href="/terms" className="hover:text-white transition-colors">Terms of Service</a>
          <a href="/refund" className="hover:text-white transition-colors">Refund Policy</a>
          <a href="/do-not-sell" className="hover:text-white transition-colors">Do Not Sell or Share My Personal Information</a>
          <button
            type="button"
            onClick={() => {
              if (typeof window !== 'undefined') {
                window.dispatchEvent(new CustomEvent('zelsis:reopenConsent'));
              }
            }}
            className="hover:text-white transition-colors cursor-pointer text-left"
          >
            Cookie Settings
          </button>
        </div>
      </div>
    </footer>
  );
};
