'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, HelpCircle, ShieldCheck } from 'lucide-react';

interface FaqItem {
  question: string;
  answer: string;
}

export const FaqSection: React.FC = () => {
  const [openIdx, setOpenIdx] = useState<number | null>(0);

  const faqs: FaqItem[] = [
    {
      question: 'Do you store or train AI models on our proprietary source code?',
      answer:
        'Never. Zelsis operates on a strict zero-retention architecture. Your repository payload is streamed directly into ephemeral worker memory, parsed via syntax and structural pattern tokens, and immediately released. We never write your code to disk, never save repositories into databases, and never use customer data for AI model training.'
    },
    {
      question: 'Does Zelsis work with private GitHub repositories?',
      answer:
        'Yes. You can connect private GitHub repositories using your authenticated GitHub token or by running our localized CLI. Because scans execute in-memory, your confidential intellectual property remains strictly within your authorized team perimeter.'
    },
    {
      question: 'How does Zelsis integrate into our existing CI/CD pipelines?',
      answer:
        'Zelsis can be invoked via automated webhooks, CLI pre-commit hooks, or GitHub Actions. It outputs deterministic exit codes and signed JSON/CSV release manifests. You can enforce a minimum release threshold (e.g. 90/100 readiness score) to block pull request merges containing critical vulnerabilities.'
    },
    {
      question: 'How are the release gate and security rules maintained and updated?',
      answer:
        'Our rule inventory is continuously synchronized with the latest industry benchmarks, including OWASP Top 10 (2025/2026), OWASP API Security, Django, FastAPI, Go, and React best practices, WCAG 2.2 AA accessibility guidelines, and Kubernetes/Docker CIS benchmarks.'
    },
    {
      question: 'Can we configure custom severity levels or disable irrelevant rules?',
      answer:
        'Yes. Pro and Enterprise subscribers have full access to our Rule Configurator. You can toggle specific rules on or off, adjust severity thresholds (CRITICAL, HIGH, MEDIUM, LOW), and configure tailored notification channels (Slack / Discord) per repository.'
    },
    {
      question: 'What is your refund policy and subscription cancellation model?',
      answer:
        'All plans are 100% self-serve and transparent. You can cancel or modify your subscription at any time with a single click in your billing portal. You will retain full access until the end of your paid billing cycle with zero surprise charges.'
    }
  ];

  if (faqs.length === 0) return null;

  return (
    <section id="faq" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-4xl mx-auto flex flex-col gap-12">
        {/* Section Header */}
        <div className="flex flex-col gap-4 text-center">
          <div className="inline-flex items-center justify-center text-xs font-mono uppercase tracking-widest text-zinc-400">
            <span>SECURITY &amp; ARCHITECTURE FAQ</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            Frequently Asked Questions
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed font-sans">
            Direct technical specifications and answers regarding zero-retention architecture, CI/CD gates, and deterministic verification.
          </p>
        </div>

        {/* FAQ Accordion List */}
        <div className="flex flex-col divide-y divide-white/10 border-y border-white/10">
          {faqs.map((faq, idx) => (
            <div key={idx} className="py-6">
              <button
                onClick={() => setOpenIdx(openIdx === idx ? null : idx)}
                className="w-full flex items-center justify-between gap-4 text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-white/20 focus-visible:ring-offset-2 focus-visible:ring-offset-black rounded-md cursor-pointer"
                aria-expanded={openIdx === idx}
                aria-label={`Toggle answer for: ${faq.question}`}
              >
                <span className="text-base sm:text-lg font-bold text-white group-hover:text-zinc-300 transition-colors">
                  {faq.question}
                </span>
                <span className={`p-1.5 rounded-md border border-white/10 bg-white/[0.02] text-zinc-400 group-hover:text-white transition-all transform ${openIdx === idx ? 'rotate-180 bg-white/10' : ''}`}>
                  <ChevronDown size={16} />
                </span>
              </button>

              <AnimatePresence>
                {openIdx === idx && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.15 }}
                    className="overflow-hidden"
                  >
                    <p className="mt-4 text-sm text-zinc-400 leading-relaxed font-sans pr-6">
                      {faq.answer}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
