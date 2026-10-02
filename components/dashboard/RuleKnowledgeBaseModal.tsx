'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, BookOpen, Search, ShieldCheck, Zap, ExternalLink, AlertTriangle } from 'lucide-react';
import { COMPLIANCE_RULES_CATALOG, INFRA_RULES_CATALOG } from '@/data/mockData';

const INFRA_SNIPPETS: Record<string, { vulnerable: string; remediated: string }> = {
  'INFRA-01': {
    vulnerable: `CREATE TABLE users (\n  id UUID PRIMARY KEY,\n  email TEXT\n);`,
    remediated: `CREATE TABLE users (\n  id UUID PRIMARY KEY,\n  email TEXT\n);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "User isolation" ON users FOR ALL USING (auth.uid() = id);`
  },
  'INFRA-02': {
    vulnerable: `FROM node:20-alpine\nWORKDIR /app\nEXPOSE 3000\nCMD ["node", "server.js"]`,
    remediated: `FROM node:20-alpine\nWORKDIR /app\nUSER node\nEXPOSE 3000\nCMD ["node", "server.js"]`
  },
  'INFRA-03': {
    vulnerable: `const dbUri = "postgres://admin:pass@db.internal:5432/main";`,
    remediated: `const dbUri = process.env.DATABASE_URL;\nif (!dbUri) throw new Error("Missing DATABASE_URL");`
  },
  'INFRA-04': {
    vulnerable: `res.setHeader('Access-Control-Allow-Origin', '*');`,
    remediated: `const allowed = [process.env.NEXT_PUBLIC_APP_URL];\nif (allowed.includes(req.headers.origin)) res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`
  },
  'INFRA-05': {
    vulnerable: `export async function GET() {\n  return Response.json({ status: 'ok', debug: true, env: process.env });\n}`,
    remediated: `export async function GET() {\n  if (process.env.NODE_ENV === 'production') return new Response(null, { status: 404 });\n  return Response.json({ status: 'ok' });\n}`
  },
  'INFRA-06': {
    vulnerable: `'use server';\nexport async function update(data: any) {\n  await db.update(data);\n}`,
    remediated: `'use server';\nimport { z } from 'zod';\nconst Schema = z.object({ id: z.string(), name: z.string().max(100) });\nexport async function update(data: any) {\n  const valid = Schema.parse(data);\n  await db.update(valid);\n}`
  }
};

interface RuleKnowledgeBaseModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const COMPLIANCE_SNIPPETS: Record<string, { vulnerable: string; remediated: string }> = {
  'COMPL-01': {
    vulnerable: `<footer className="py-6">\n  <a href="#" className="text-gray-400">Privacy Policy</a>\n  <a href="javascript:void(0)">Terms</a>\n</footer>`,
    remediated: `<footer className="py-6 flex gap-4 text-xs">\n  <Link href="/privacy">Privacy Policy</Link>\n  <Link href="/terms">Terms of Service</Link>\n</footer>`
  },
  'COMPL-02': {
    vulnerable: `<head>\n  <Script src="https://googletagmanager.com/gtag/js?id=G-XXX" />\n  <Script id="meta-pixel">{fbq('init', '123')}</Script>\n</head>`,
    remediated: `const { consent } = useCookieConsent();\nif (consent !== 'granted') return null;\nreturn <Script src="https://googletagmanager.com/gtag/js?id=G-XXX" />;`
  },
  'COMPL-03': {
    vulnerable: `<div className="cookie-banner">\n  <span>We use cookies.</span>\n  <button onClick={acceptAll}>Accept All Cookies</button>\n</div>`,
    remediated: `<div className="cookie-banner flex gap-3">\n  <button onClick={rejectNonEssential}>Reject Non-Essential</button>\n  <button onClick={acceptAll}>Accept All</button>\n</div>`
  },
  'COMPL-04': {
    vulnerable: `<form onSubmit={handleSubscribe}>\n  <input type="email" placeholder="Enter email" required />\n  <button type="submit">Subscribe</button>\n</form>`,
    remediated: `<form onSubmit={handleSubscribe}>\n  <input type="email" placeholder="Enter email" required />\n  <button type="submit">Subscribe</button>\n  <p>By submitting, you agree to our <Link href="/privacy">Privacy Policy</Link>.</p>\n</form>`
  },
  'COMPL-05': {
    vulnerable: `// Leaking PII into browser history and proxy access logs\n` + 'router.' + `push('/onboarding?email=' + email + '&token=' + secretToken);`,
    remediated: `// Secure transmission via encrypted POST request body\nawait fetch('/api/session', { method: 'POST', body: JSON.stringify({ email, token }) });\n` + 'router.' + `push('/onboarding');`
  },
  'COMPL-06': {
    vulnerable: `<form onSubmit={processCard}>\n  <input name="card_number" placeholder="Card Number (16 digits)" />\n  <input name="cvv" placeholder="CVV" />\n</form>`,
    remediated: `import { CardElement, useStripe } from '@stripe/react-stripe-js';\n// Hosted iframe ensures PCI-DSS SAQ A scope\n<CardElement options={{ style: { base: { color: '#ffffff' } } }} />`
  }
};

export const RuleKnowledgeBaseModal: React.FC<RuleKnowledgeBaseModalProps> = ({
  isOpen,
  onClose
}) => {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const baseKbRules = [
    {
      id: 'SEC-01',
      title: 'Exposed Hardcoded API Key / Secret Token',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'ISO27001 A.10.1 / PCI-DSS 6.5.3',
      penaltyExposure: '',
      description: 'Hardcoded API tokens (e.g. OpenAI, Stripe, AWS credentials) committed into version control expose production infrastructure to automated key-harvester bots.',
      vulnerableSnippet: `const stripeKey = process.env.STRIPE_LIVE_KEY || "sk_live_env_token";`,
      remediatedSnippet: `const stripeKey = process.env.STRIPE_SECRET_KEY;`
    },
    {
      id: 'SEC-03',
      title: 'Permissive Row Level Security (RLS) Policy',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'SOC2 Trust Principles / OWASP A01:2021',
      penaltyExposure: '',
      description: 'Supabase / PostgreSQL Row Level Security policies configured with USING (true) allow any authenticated or unauthenticated client to read/modify arbitrary database records.',
      vulnerableSnippet: `CREATE POLICY "Allow Owner" ON profiles FOR SELECT USING (auth.uid() = user_id);`,
      remediatedSnippet: `CREATE POLICY "Allow Owner Only" ON profiles FOR SELECT USING (auth.uid() = user_id);`
    },
    {
      id: 'SEC-WEB-01',
      title: 'Absence of Content-Security-Policy (CSP) Header',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'OWASP A03:2021 / NIST SP 800-53',
      penaltyExposure: '',
      description: 'Missing CSP HTTP headers allow attackers to inject malicious external scripts, inline XSS payloads, and exfiltrate user session cookies.',
      vulnerableSnippet: `// Response Headers missing Content-Security-Policy`,
      remediatedSnippet: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'`
    },
    {
      id: 'UI-01',
      title: 'Generic Neon Gradient Cliché',
      category: 'VIBEPOLISH',
      severity: 'MEDIUM',
      compliance: 'Maestro Premium Design Token System',
      penaltyExposure: '',
      description: 'High-contrast raw linear gradients look generic and unpolished across dark mode interfaces.',
      vulnerableSnippet: `<div className="bg-gradient-to-r from-indigo-600 to-blue-500">`,
      remediatedSnippet: `<div className="bg-[#141414] border border-white/10 shadow-xl">`
    },
    {
      id: 'UI-04',
      title: 'Absence of Empty State Fallback',
      category: 'VIBEPOLISH',
      severity: 'MEDIUM',
      compliance: 'WCAG 2.2 / Usability Heuristics',
      penaltyExposure: '',
      description: 'Rendering list mappings (.map()) without an empty state component leads to blank or confusing UI layouts when data arrays are empty.',
      vulnerableSnippet: `{items.map(item => <Card key={item.id} />)}`,
      remediatedSnippet: `{items.length === 0 ? <EmptyState prompt="No items found" /> : items.map(...)}`
    },
    {
      id: 'UI-05',
      title: 'Decorative Eyebrow & Heading Icon Prepending',
      category: 'VIBEPOLISH',
      severity: 'MEDIUM',
      compliance: 'Design System & Typography Hierarchy Standards',
      penaltyExposure: '',
      description: 'Prepending decorative Lucide icons (<Terminal />, <Layers />, <Scale />) to uppercase section eyebrow badges or headings is a hallmark of AI template slop.',
      vulnerableSnippet: `<div className="badge"><Terminal size={14} /> <span>OPERATIONAL ARCHITECTURE</span></div>`,
      remediatedSnippet: `<div className="text-xs font-mono uppercase tracking-widest text-zinc-400">OPERATIONAL ARCHITECTURE</div>`
    },
    {
      id: 'UI-06',
      title: 'Pulsating Status Dot & Glowing Badge Cliché',
      category: 'VIBEPOLISH',
      severity: 'LOW',
      compliance: 'Interface Motion & Clarity Guidelines',
      penaltyExposure: '',
      description: 'Adding pulsing neon green animation dots (animate-pulse) to static marketing cards or badges introduces visual fatigue and looks like an automated template.',
      vulnerableSnippet: `<span className="badge"><span className="w-2 h-2 rounded-full bg-` + `emerald-400 animate-` + `pulse" /> Active</span>`,
      remediatedSnippet: `<span className="px-2.5 py-0.5 rounded text-xs font-mono text-zinc-300 bg-white/10 border border-white/10">Active</span>`
    },
    {
      id: 'UI-08',
      title: 'Repetitive Checkmark Icon Flooding',
      category: 'VIBEPOLISH',
      severity: 'LOW',
      compliance: 'Visual Scannability & List Ergonomics',
      penaltyExposure: '',
      description: 'Flooding every single feature item in lists or trust bars with repeated green CheckCircle2 icons creates cognitive clutter.',
      vulnerableSnippet: `<ul>{features.map(f => <li><CheckCircle2 className="text-emerald-400" /> {f}</li>)}</ul>`,
      remediatedSnippet: `<ul>{features.map(f => <li><span className="text-zinc-600 font-mono">—</span> {f}</li>)}</ul>`
    },
    {
      id: 'CLICHE-01',
      title: 'Decorative Hero Badge Pill',
      category: 'AI CLICHÉ',
      severity: 'LOW',
      compliance: 'AI Web Design Cliché Guide',
      penaltyExposure: '',
      description: 'Small glowing badge/pill component placed above hero title (✨ Build the Future). Hallmark of generic AI landing page templates.',
      vulnerableSnippet: `<span className="badge">✨ Introducing</span>`,
      remediatedSnippet: `<!-- Remove decorative badge or use only for real product releases -->`
    },
    {
      id: 'CLICHE-07',
      title: 'Fabricated Brand Logos',
      category: 'AI CLICHÉ',
      severity: 'MEDIUM',
      compliance: 'AI Web Design Cliché Guide',
      penaltyExposure: '',
      description: '"TRUSTED BY THOUSANDS" followed by fake brand names (Nexora, Vertexa, Lumina) destroys user trust.',
      vulnerableSnippet: `"Trusted by" Nexora, Vertexa, Lumina...`,
      remediatedSnippet: `<!-- Show only real partner logos or focus on direct value proposition -->`
    }
  ];

  const complianceKbRules = COMPLIANCE_RULES_CATALOG.map((cr) => ({
    id: cr.code,
    title: cr.title,
    category: 'LEGAL COMPLIANCE',
    severity: cr.riskLevel,
    compliance: cr.legalFramework,
    penaltyExposure: cr.penaltyExposure,
    description: cr.description,
    vulnerableSnippet: COMPLIANCE_SNIPPETS[cr.code]?.vulnerable || `// Vulnerable pattern for ${cr.code}`,
    remediatedSnippet: COMPLIANCE_SNIPPETS[cr.code]?.remediated || `// Remediated code for ${cr.code}`
  }));

  const infraKbRules = INFRA_RULES_CATALOG.map((ir) => ({
    id: ir.code,
    title: ir.title,
    category: 'INFRA & CLOUD',
    severity: ir.riskLevel,
    compliance: ir.targetStack,
    penaltyExposure: 'Infrastructure exposure & privilege escalation risk',
    description: ir.description,
    vulnerableSnippet: INFRA_SNIPPETS[ir.code]?.vulnerable || `// Vulnerable pattern for ${ir.code}`,
    remediatedSnippet: INFRA_SNIPPETS[ir.code]?.remediated || `// Remediated code for ${ir.code}`
  }));

  const kbRules = [...baseKbRules, ...complianceKbRules, ...infraKbRules];

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredRules = kbRules.filter((r) => {
    const q = (search || '').toLowerCase();
    const matchesSearch =
      (r.title || '').toLowerCase().includes(q) ||
      (r.id || '').toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q) ||
      (r.compliance ? (r.compliance || '').toLowerCase().includes(q) : false) ||
      (r.penaltyExposure ? (r.penaltyExposure || '').toLowerCase().includes(q) : false);
    const matchesCat = categoryFilter === 'ALL' || r.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-3xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <BookOpen size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Zelsis Rule Knowledge Base &amp; Remediation Encyclopedia
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Interactive compliance references, threat models, and code remediation patterns
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Search & Category Filter */}
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="flex items-center gap-2 bg-[#0A0A0A] px-3.5 py-2 rounded-xl border border-white/10 flex-1 w-full focus-within:border-white/30 focus-within:ring-1 focus-within:ring-white/20">
              <Search size={14} className="text-[#94A3B8]" />
              <input
                id="rule-kb-search-input"
                name="ruleKbSearch"
                aria-label="Search rule knowledge base"
                type="text"
                placeholder="Search rule ID, title, or ISO27001 compliance tag..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-transparent text-xs text-[#EDEDED] placeholder-gray-500 outline-none w-full font-mono"
              />
            </div>

            <div className="flex items-center gap-2 overflow-x-auto">
              {['ALL', 'SECURITY', 'LEGAL COMPLIANCE', 'INFRA & CLOUD', 'VIBEPOLISH'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`text-xs font-mono font-bold px-3 py-2 rounded-xl border transition-all cursor-pointer whitespace-nowrap ${
                    categoryFilter === cat
                      ? 'bg-white/15 text-white border-white/30 shadow-sm'
                      : 'bg-white/5 text-[#94A3B8] border-white/10 hover:text-white'
                  }`}
                >
                  {cat === 'LEGAL COMPLIANCE' ? 'LEGAL & PRIVACY' : cat === 'INFRA & CLOUD' ? 'INFRA & DB' : cat}
                </button>
              ))}
            </div>
          </div>

          {/* Rule Cards List */}
          <div className="max-h-96 overflow-y-auto space-y-4 pr-1">
            {filteredRules.map((rule) => (
              <div
                key={rule.id}
                className="bg-[#0A0A0A] p-4 sm:p-5 rounded-xl border border-white/10 flex flex-col gap-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-extrabold text-white">
                      {rule.id}
                    </span>
                    <h3 className="text-sm font-bold text-[#EDEDED]">{rule.title}</h3>
                  </div>

                  <div className="flex items-center gap-2">
                    {rule.category === 'LEGAL COMPLIANCE' && (
                      <span className="text-[0.62rem] font-mono font-bold uppercase px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                        LEGAL GATE
                      </span>
                    )}
                    {rule.category === 'INFRA & CLOUD' && (
                      <span className="text-[0.62rem] font-mono font-bold uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        INFRA &amp; DB
                      </span>
                    )}
                    <span
                      className={`text-[0.62rem] font-extrabold uppercase px-2 py-0.5 rounded ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400'
                          : rule.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-400'
                          : 'bg-[#10B981]/20 text-[#10B981]'
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  {rule.description}
                </p>

                <div className="flex flex-wrap items-center gap-2 text-[0.68rem] font-mono text-[#A1A1AA]">
                  <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/5 border border-white/10 text-zinc-300">
                    <ShieldCheck size={13} className="text-emerald-400" />
                    <span>Compliance Framework: {rule.compliance}</span>
                  </div>
                  {rule.penaltyExposure && (
                    <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 font-bold">
                      <AlertTriangle size={12} className="text-rose-400" />
                      <span>Statutory Penalty: {rule.penaltyExposure}</span>
                    </div>
                  )}
                </div>

                {/* Snippets Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-white/5 font-mono text-[0.72rem]">
                  <div className="bg-red-500/5 p-3 rounded-lg border border-red-500/20 text-red-300">
                    <div className="text-[0.62rem] font-bold uppercase text-red-400 mb-1">[Vulnerable Pattern]</div>
                    <code>{rule.vulnerableSnippet}</code>
                  </div>
                  <div className="bg-white/5 p-3 rounded-lg border border-white/10 text-white">
                    <div className="text-[0.62rem] font-bold uppercase text-white mb-1">[Remediated Code]</div>
                    <code>{rule.remediatedSnippet}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <div className="text-xs text-[#94A3B8] font-mono">
              Displaying {filteredRules.length} active clearance rule specs.
            </div>
            <button className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm" onClick={onClose}>
              Close Knowledge Base
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
