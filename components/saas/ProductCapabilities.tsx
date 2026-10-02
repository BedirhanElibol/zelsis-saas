'use client';

import React, { useCallback, useRef, useState } from 'react';
import { useDialogFocus } from '@/hooks/useDialogFocus';
import { motion, AnimatePresence } from 'framer-motion';
import Image from 'next/image';
import { 
  ShieldCheck, 
  CheckCircle2, 
  Layers, 
  Maximize2, 
  X,
  Code2,
  Terminal,
  Activity,
  FileCode,
  Zap
} from 'lucide-react';

interface ProductCapability {
  id: string;
  badge: string;
  title: string;
  subtitle: string;
  description: string;
  image: string;
  alt: string;
  tag: string;
  architecturePills: string[];
  bulletPoints: string[];
}

export const ProductCapabilities: React.FC = () => {
  const [zoomImage, setZoomImage] = useState<string | null>(null);
  const lightboxRef = useRef<HTMLDivElement>(null);
  const closeZoom = useCallback(() => setZoomImage(null), []);
  useDialogFocus(lightboxRef, Boolean(zoomImage), closeZoom);

  const capabilities: ProductCapability[] = [
    {
      id: 'rules',
      badge: 'RULE TAXONOMY',
      title: 'Release rules that know your stack',
      subtitle: 'Continuous verification across OWASP Top 10, database isolation, and cloud architecture.',
      description:
        'Audit your codebase against an extensive taxonomy of deterministic static & lexical rules. Enforce zero day-one OWASP Top 10 vulnerabilities, verify multi-database security policies, block wildcard CORS endpoints, and eliminate root container privilege escalation risks.',
      image: '/images/security_rules.png',
      alt: 'Zelsis Release Gate Rule Catalog and Policy Configurator',
      tag: 'POLICY ENGINE',
      architecturePills: [
        'OWASP Top 10 (2025/2026)',
        'PostgreSQL Row Level Security',
        'Next.js, Django, FastAPI & Go',
        'Docker & K8s Security Context'
      ],
      bulletPoints: [
        'Deterministic, non-LLM static detection engine for high-fidelity alerts',
        'Granular severity controls: Configure CRITICAL, HIGH, MEDIUM per repository',
        'Clear explanations mapped to CWE standards and security best practices'
      ]
    },
    {
      id: 'findings',
      badge: 'SURGICAL CODE TRIAGE',
      title: 'Line-by-Line Vulnerability Triage & Context',
      subtitle: 'Pinpoint vulnerabilities down to the exact line number with 1-click AI remediation prompts.',
      description:
        'Every detected flaw is isolated with its syntax context, risk severity, and remediation guidance. Review exact line-by-line diffs and copy automated AI prompts to remediate issues instantly in your AI coding assistant.',
      image: '/images/audit_findings.png',
      alt: 'Zelsis Vulnerability Triage and Line-by-Line Code Findings',
      tag: 'SURGICAL DIFFS',
      architecturePills: [
        'Precise Line Number Isolation',
        '1-Click AI Fix Prompts',
        'CWE Risk Explanations',
        'Exportable JSON & CSV'
      ],
      bulletPoints: [
        'Exact line numbers with syntax-highlighted code context',
        'Pre-engineered AI prompts ready for any AI coding assistant',
        'Every finding tagged verified or suggestion, so you fix what is proven first'
      ]
    },
    {
      id: 'sandbox',
      badge: 'ZERO-INSTALL REPL',
      title: 'Interactive In-Memory Security Sandbox',
      subtitle: 'Test production code snippets against clearance rules in live browser memory.',
      description:
        'Experiment with production snippets before pushing to version control. Test API routes, Dockerfiles, and React components against the full Zelsis engine without installing any local packages or daemons.',
      image: '/images/vulnerability_sandbox.png',
      alt: 'Zelsis In-Memory Vulnerability Sandbox and Lexical Pattern Playground',
      tag: 'ZERO-INSTALL REPL',
      architecturePills: [
        'Client-Side In-Memory Execution',
        'Zero Data Egress / Full Privacy',
        'Instant Pattern & Syntax Evaluation',
        '5 Built-in Production Presets'
      ],
      bulletPoints: [
        'Live lexical & pattern analyzer running directly inside your browser viewport',
        '1-click presets for secret exposure, permissive RLS, and container root',
        'Real-time feedback as you type or paste production code'
      ]
    },
    {
      id: 'profiler',
      badge: 'WEB VITALS & INFRASTRUCTURE',
      title: 'Performance, Accessibility & Infrastructure Checks',
      subtitle: 'Catch the code patterns behind layout shifts, heavy bundles and unbounded containers.',
      description:
        'Static checks for the causes of poor Core Web Vitals (images without dimensions, render-blocking scripts, oversized imports), WCAG 2.2 AA accessibility gaps, and Docker or Kubernetes resources left unbounded, before you deploy.',
      image: '/images/bundle_profiler.png',
      alt: 'Zelsis Performance Bundle Profiler and Cloud Resource Analyzer',
      tag: 'PERFORMANCE GAUGE',
      architecturePills: [
        'Layout-Shift Risks',
        'Render-Blocking Assets',
        'WCAG 2.2 AA Accessibility',
        'Container Resource Quotas'
      ],
      bulletPoints: [
        'Patterns that cause layout shift (CLS) and slow first paint (LCP)',
        'Detection of unkeyed React iterators and heavy third-party bundle leaks',
        'Docker healthcheck enforcement and memory quota allocation checks'
      ]
    }
  ];

  if (capabilities.length === 0) {
    return <div className="text-neutral-500 font-mono text-sm">No capabilities defined.</div>;
  }

  return (
    <section id="features" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-20">
        {/* Section Title */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center text-xs font-mono uppercase tracking-widest text-zinc-400">
            <span>What it checks</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            Security checks built for how SaaS apps break
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed font-sans">
            Secrets, database access rules, injection, auth and dependencies, each finding with the exact line and a fix you can paste into your AI assistant.
          </p>
        </div>

        {/* Sequential Alternating Showcase of All 4 Pillars */}
        <div className="flex flex-col gap-16">
          {capabilities.map((capability, idx) => {
            const isReversed = idx % 2 === 1;
            return (
              <div
                key={capability.id}
                className={`rounded-2xl border border-white/15 bg-[#121216] p-6 sm:p-10 shadow-2xl flex flex-col ${
                  isReversed ? 'lg:flex-row-reverse' : 'lg:flex-row'
                } gap-10 items-center`}
              >
                {/* Text & Architecture Pills Column (5 cols) */}
                <div className="w-full lg:w-5/12 flex flex-col gap-6">
                  <h3 className="text-2xl sm:text-3xl font-extrabold text-white leading-tight">
                    {capability.title}
                  </h3>

                  <p className="text-xs sm:text-sm font-semibold text-zinc-300 leading-normal">
                    {capability.subtitle}
                  </p>

                  <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans">
                    {capability.description}
                  </p>

                  {/* Architecture Capability Tags (No Fake Numbers) */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 py-4 border-y border-white/10">
                    {capability.architecturePills.map((pill, pIdx) => (
                      <div key={pIdx} className="p-2.5 rounded-lg bg-[#0E0E10] border border-white/5 flex items-center">
                        <span className="text-xs font-mono text-zinc-300">{pill}</span>
                      </div>
                    ))}
                  </div>

                  {/* Bullet List */}
                  <ul className="flex flex-col gap-2.5">
                    {capability.bulletPoints.map((bp, bpIdx) => (
                      <li key={bpIdx} className="flex items-start gap-2.5 text-xs text-zinc-300">
                        <span className="text-zinc-400 font-mono text-xs select-none shrink-0">—</span>
                        <span>{bp}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Screenshot Showcase Column (7 cols) */}
                <div className="w-full lg:w-7/12 flex flex-col gap-3">
                  <div className="relative aspect-[16/10] w-full rounded-xl border border-white/15 bg-[#0A0A0A] overflow-hidden shadow-2xl group">
                    <Image
                      src={capability.image}
                      alt={capability.alt}
                      fill
                      sizes="(max-width: 1200px) 100vw, 700px"
                      className="object-cover object-top transition-transform duration-500 group-hover:scale-[1.02]"
                    />

                    {/* Zoom Trigger Button */}
                    <button
                      onClick={() => setZoomImage(capability.image)}
                      className="absolute top-3 right-3 p-3 rounded-lg bg-[#0E0E10]/80 backdrop-blur-md border border-white/15 text-zinc-300 hover:text-white transition-all opacity-0 group-hover:opacity-100 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-white/70 shadow-lg cursor-pointer"
                      aria-label="Zoom Image Preview"
                    >
                      <Maximize2 size={16} />
                    </button>

                    <div className="absolute bottom-0 inset-x-0 p-3 bg-gradient-to-t from-black/90 via-black/40 to-transparent flex items-center justify-between text-xs font-mono text-zinc-400">
                      <span className="text-xs text-zinc-300 font-semibold">{capability.alt}</span>
                      <span className="text-xs text-zinc-300 font-bold">{capability.tag}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Modal Lightbox for High-Res Zoom */}
        <AnimatePresence>
          {zoomImage && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setZoomImage(null)}
              className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 sm:p-8 cursor-zoom-out"
            >
              <div
                ref={lightboxRef}
                role="dialog"
                aria-modal="true"
                aria-label="Screenshot preview"
                tabIndex={-1}
                className="relative max-w-6xl w-full aspect-[16/10] rounded-xl overflow-hidden border border-white/20 shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              >
                <Image
                  src={zoomImage}
                  alt="High Resolution Screenshot Preview"
                  fill
                  sizes="(max-width: 1280px) 100vw, 1152px"
                  className="object-contain"
                />
                <button
                  onClick={() => setZoomImage(null)}
                  className="absolute top-4 right-4 p-2 rounded-full bg-white/10 hover:bg-white/20 text-white border border-white/20 transition-all"
                  aria-label="Close Preview"
                >
                  <X size={20} />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
};
