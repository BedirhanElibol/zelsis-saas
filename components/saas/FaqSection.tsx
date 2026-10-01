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
        'No. Repository files are fetched into worker memory, scanned with pattern-based rules, and released when the scan ends. We do not save repositories; we save the findings, which include a short snippet of each flagged line so you can review it. Customer code is never used to train AI models.'
    },
    {
      question: 'Does Zelsis work with private GitHub repositories?',
      answer:
        'Yes. Provide a GitHub token with read access to the repository. The token is used only to fetch files for the scan, and the files are scanned in memory.'
    },
    {
      question: 'How does Zelsis integrate into our existing CI/CD pipelines?',
      answer:
        'Call the gate API from any CI runner (GitHub Actions, GitLab CI, Bitbucket, CircleCI). With failOnBlock=true it returns HTTP 422 when the gate fails, so the job fails. The dashboard generates ready-to-use workflows, and a .zelsisrc.json in your repository can require a minimum readiness score.'
    },
    {
      question: 'How are the release gate and security rules maintained and updated?',
      answer:
        'Every rule change is measured against a pinned benchmark of intentionally vulnerable apps and maintained production projects in several languages. Rules that misfire on clean code become experimental and stop affecting the gate, and a CRITICAL finding can fail a release only when its rule has test fixtures, caught a documented flaw, or was reviewed as a true positive. Results are published in the benchmark section.'
    },
    {
      question: 'Can we configure custom severity levels or disable irrelevant rules?',
      answer:
        'Yes, on every plan. Add a .zelsisrc.json (or .zelsisignore) to your repository to ignore rules or paths, turn off whole pillars, and choose smart, strict or advisory gating with a minimum score. The dashboard rule configurator can generate the file for you.'
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
