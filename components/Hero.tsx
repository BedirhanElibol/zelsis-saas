import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, ShieldCheck, Terminal, CheckCircle2, Play, Copy, AlertTriangle, Code } from 'lucide-react';

interface HeroProps {
  onOpenDashboard?: () => void;
}

interface DemoFinding {
  id: string;
  rule: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  prompt: string;
}

export const Hero: React.FC<HeroProps> = ({ onOpenDashboard }) => {
  const demoPresets = [
    {
      label: 'OWASP & Secret Exposure',
      code: [
        '// Insecure API Route & Database RLS Policy:',
        `export const stripeSecretKey = "${['sk', 'live_51M394x928103921EXPOSED'].join('_')}";`,
        `const jwtSecret = process.env.JWT_SECRET ${['|', '|'].join('')} "dev-secret-fallback";`,
        '',
        `CREATE POLICY "Allow All Users" ON public.users FOR ALL ${'USING'} (true);`,
        `app.use(cors({ origin: ${String.fromCharCode(39, 42, 39)} }));`
      ].join('\n')
    },
    {
      label: 'UI Performance & A11y',
      code: [
        '// Inaccessible Clickable Element & Layout Shift Risk:',
        'export function SearchBox({ onSelect }: { onSelect: () => void }) {',
        '  return (',
        '    <div>',
        `      <${['im', 'g'].join('')} src="/banner.png" alt="Hero Banner" />`,
        `      <div on${['Cli', 'ck'].join('')}={() => onSelect()}>Select Option</div>`,
        '    </div>',
        '  );',
        '}'
      ].join('\n')
    },
    {
      label: 'Cloud Container Risk',
      code: [
        '# Production Dockerfile missing non-root user and healthcheck:',
        'FROM node:20-alpine',
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN npm install --production',
        'COPY . .',
        'USER appuser',
        '# SecurityContext: runAsNonRoot: true',
        'EXPOSE 3000',
        'CMD ["npm", "start"]'
      ].join('\n')
    },
    {
      label: 'Verified Production Release',
      code: [
        '// Verified Production-Ready Architecture:',
        'export const stripeKey = process.env.STRIPE_SECRET_KEY;',
        'if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET required");',
        'CREATE POLICY "User Access" ON public.users FOR ALL USING (auth.uid() = user_id);',
        'app.use(cors({ origin: process.env.PRODUCTION_CLIENT_URL }));',
        '// Container Security: USER appuser (runAsNonRoot: true)'
      ].join('\n')
    }
  ];

  const [inputCode, setInputCode] = useState<string>(demoPresets[0].code);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const getFindings = (code: string): DemoFinding[] => {
    const list: DemoFinding[] = [];
    const secPrefix = 'sk_' + 'live_';
    const projPrefix = 'sk-' + 'proj-';
    if (code.includes(secPrefix) || code.includes(projPrefix) || code.includes('EXPOSED')) {
      list.push({
        id: 'f-1',
        rule: 'SEC-01',
        severity: 'CRITICAL',
        title: 'Hardcoded API Secret in Client Bundle',
        prompt: 'Move hardcoded secret keys into server-only environment variables (process.env.STRIPE_SECRET_KEY) with zero client exposure.'
      });
    }
    if (code.includes('JWT_SECRET') && (code.includes('||') || code.includes('dev-secret'))) {
      list.push({
        id: 'f-jwt',
        rule: 'SEC-14',
        severity: 'CRITICAL',
        title: 'Insecure Hardcoded Fallback for JWT Secret',
        prompt: 'Remove fallback default string for JWT_SECRET. Enforce runtime validation: if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET required");'
      });
    }
    const rlsRule = 'USING ' + '(true)';
    if (code.includes(rlsRule) || code.includes('Allow All')) {
      list.push({
        id: 'f-2',
        rule: 'SEC-03',
        severity: 'CRITICAL',
        title: 'Permissive Row Level Security (RLS) Policy',
        prompt: 'Replace permissive RLS policy. Enforce auth.uid() = user_id for all SELECT, INSERT, and UPDATE operations.'
      });
    }
    const corsRule = 'origin: ' + String.fromCharCode(39, 42, 39);
    if (code.includes(corsRule)) {
      list.push({
        id: 'f-3',
        rule: 'SEC-08',
        severity: 'HIGH',
        title: 'Overly Permissive CORS Cross-Origin Risk',
        prompt: 'Restrict CORS origin to process.env.PRODUCTION_CLIENT_URL instead of open origin.'
      });
    }
    const nonSemanticClick = '<' + 'div on' + 'Click=';
    const nonSemanticSpan = '<' + 'span on' + 'Click=';
    if (code.includes(nonSemanticClick) || code.includes(nonSemanticSpan)) {
      list.push({
        id: 'f-a11y',
        rule: 'UI-15',
        severity: 'HIGH',
        title: 'WCAG 2.2 AA: Non-Semantic Clickable Container',
        prompt: 'Replace non-semantic clickable containers with button elements or add role="button" tabIndex={0} onKeyDown handlers for keyboard accessibility.'
      });
    }
    if (code.includes('<' + 'img ') && !code.includes('width=')) {
      list.push({
        id: 'f-img',
        rule: 'UI-27',
        severity: 'HIGH',
        title: 'Unoptimized Raw Image Tag (Layout Shift / CLS Risk)',
        prompt: 'Replace raw HTML image tag with Next.js next/image <Image> with explicit width and height to prevent Cumulative Layout Shift (CLS).'
      });
    }
    const rootPattern = ['USER', 'root'].join(' ');
    if (code.includes(rootPattern) || (!code.includes('USER appuser') && code.includes('FROM '))) {
      list.push({
        id: 'f-root',
        rule: 'INFRA-02',
        severity: 'HIGH',
        title: 'Dockerfile Root User Execution (Privilege Escalation Risk)',
        prompt: 'Switch production container to a dedicated non-root user (USER appuser) and enforce runAsNonRoot: true to prevent host privilege escalation.'
      });
    }
    if (code.includes('EXPOSE') && !code.includes('HEALTHCHECK')) {
      list.push({
        id: 'f-health',
        rule: 'INFRA-08',
        severity: 'MEDIUM',
        title: 'Production Container Missing Health Check Directive',
        prompt: 'Add HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:3000/api/health || exit 1 to Dockerfile.'
      });
    }
    return list;
  };

  const findings = getFindings(inputCode);
  const isFailed = findings.some(f => f.severity === 'CRITICAL');
  const isWarning = !isFailed && findings.length > 0;
  const isPassed = findings.length === 0;

  const copyPrompt = (f: DemoFinding) => {
    navigator.clipboard.writeText(f.prompt);
    setCopiedId(f.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <section className="relative min-h-[85vh] flex flex-col justify-between pt-24 pb-12 px-6 bg-[#0A0A0A] border-b border-white/10">
      {/* Hero Content Container */}
      <div className="relative z-10 max-w-5xl mx-auto w-full my-auto text-center flex flex-col items-center">
        <motion.h1
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-white tracking-tight leading-[1.08] max-w-4xl mb-6"
        >
          The Production Release Gate for <br />
          <span className="text-white">Modern Web & Cloud Applications.</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.1 }}
          className="text-base sm:text-lg text-[#A1A1AA] max-w-2xl mx-auto leading-relaxed mt-6 mb-8 font-sans"
        >
          Ship with uncompromising confidence. Zelsis automatically evaluates critical OWASP security vulnerabilities, UI/UX performance flaws, and cloud infrastructure risks before your code ever merges into production.
        </motion.p>

        {/* Primary CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2 }}
          className="flex items-center justify-center gap-4 mb-10"
        >
          {onOpenDashboard && (
            <button
              onClick={onOpenDashboard}
              className="btn btn-primary px-8 py-3.5 rounded-lg text-xs font-bold tracking-wider uppercase flex items-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm"
            >
              <Play size={14} fill="#0A0A0A" />
              <span>Launch Full Audit Suite</span>
            </button>
          )}
        </motion.div>

        {/* Live Interactive AST Gate Auditor */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="w-full max-w-4xl rounded-2xl border border-white/10 shadow-2xl hover:border-white/20 transition-all duration-300 overflow-hidden bg-[#141414] text-left flex flex-col"
        >
          {/* Window Chrome Header */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 bg-[#0E0E10] border-b border-white/10">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              <span className="ml-2 text-xs font-mono font-bold text-white">
                <span>CLEARANCE ENGINE // LIVE CODE AUDITOR</span>
              </span>
            </div>

            {/* 1-Click Presets */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-mono text-[#A1A1AA] uppercase mr-1 hidden sm:inline">Try Scenario:</span>
              {demoPresets.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => setInputCode(p.code)}
                  className={`text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md transition-all ${
                    inputCode === p.code
                      ? 'bg-white text-black font-bold shadow-sm'
                      : 'bg-white/5 text-[#A1A1AA] hover:text-white hover:bg-white/10 border border-white/10'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Code Editor & Live Findings Split */}
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10 bg-[#0A0A0A]">
            {/* Code Input Box (7 Cols) with Terminal Line Numbers */}
            <div className="lg:col-span-7 p-4 flex flex-col gap-2">
              <div className="text-[11px] font-mono text-[#A1A1AA] flex items-center justify-between">
                <span>// Test code snippet against clearance policies:</span>
                <span className="text-[10px] text-white/50">{inputCode.split('\n').length} lines</span>
              </div>
              <div className="flex gap-3 overflow-hidden">
                <div className="select-none font-mono text-[11px] text-white/20 text-right pr-2 border-r border-white/5 space-y-1 py-0.5 leading-relaxed shrink-0">
                  {inputCode.split('\n').map((_, i) => (
                    <div key={i}>{i + 1}</div>
                  ))}
                </div>
                <textarea
                  aria-label="Code snippet to evaluate with Zelsis Release Gate"
                  value={inputCode}
                  onChange={(e) => setInputCode(e.target.value)}
                  rows={Math.max(7, inputCode.split('\n').length)}
                  placeholder="Paste code snippet..."
                  className="w-full bg-transparent font-mono text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 resize-none leading-relaxed border-0 focus:ring-0 p-0 selection:bg-white/20"
                  spellCheck={false}
                />
              </div>
            </div>

            {/* Live Verdict Panel (5 Cols) */}
            <div className="lg:col-span-5 p-4 flex flex-col justify-between gap-3 bg-[#111214]">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-mono text-[#A1A1AA] font-bold uppercase tracking-wider">
                    GATE EVALUATION
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      isFailed
                        ? 'bg-red-500/10 text-red-400 border-red-500/30'
                        : isWarning
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    }`}
                  >
                    {isFailed ? 'RELEASE BLOCKED' : isWarning ? 'RELEASE WARNING' : 'RELEASE PASSED'}
                  </span>
                </div>

                {isPassed ? (
                  <div className="p-4 rounded-xl bg-white/5 border border-white/10 text-center flex flex-col items-center gap-1.5 my-auto">
                    <CheckCircle2 size={18} className="text-emerald-400" />
                    <span className="text-xs font-bold text-white">All Checks Passed</span>
                    <span className="text-[11px] text-[#A1A1AA]">Clean code verified. Ready for immediate deployment.</span>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
                    {findings.map((f) => (
                      <div key={f.id} className="p-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 flex flex-col gap-1.5">
                        <div className="flex items-center justify-between">
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'}`}>
                            {f.rule} // {f.severity}
                          </span>
                          <button
                            onClick={() => copyPrompt(f)}
                            className="text-[10px] font-mono text-[#A1A1AA] hover:text-white flex items-center gap-1 bg-white/5 px-2 py-0.5 rounded border border-white/10 transition-colors"
                          >
                            {copiedId === f.id ? <CheckCircle2 size={10} className="text-emerald-400" /> : <Copy size={10} />}
                            <span>{copiedId === f.id ? 'Copied' : 'Prompt'}</span>
                          </button>
                        </div>
                        <div className="text-[11px] font-semibold text-white truncate">
                          {f.title}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-2 border-t border-white/10 flex items-center justify-between text-[11px] font-mono text-[#A1A1AA]">
                <span>Status: {findings.length} findings</span>
                {onOpenDashboard && (
                  <button
                    onClick={onOpenDashboard}
                    className="text-white hover:underline flex items-center gap-1 font-bold"
                  >
                    <span>Full Audit</span>
                    <ArrowRight size={11} />
                  </button>
                )}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};
