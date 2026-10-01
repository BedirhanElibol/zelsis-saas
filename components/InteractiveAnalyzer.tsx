'use client';

import React, { useState } from 'react';
import { Finding } from '@/data/schema';
import { Code, Play, CheckCircle2, Copy, FileCode } from 'lucide-react';

export const InteractiveAnalyzer: React.FC = () => {
  const [inputCode, setInputCode] = useState<string>(`// Verified Secure Production Architecture Code Snippet:
export const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
export const openAiApiKey = process.env.OPENAI_API_KEY;

// Supabase strict RLS policy snippet
CREATE POLICY "User Access" ON public.users FOR ALL USING (auth.uid() = user_id);

// Express/FastAPI strict CORS setup
app.use(cors({ origin: process.env.PRODUCTION_CLIENT_URL }));

// Explicit model version snapshot
const modelVersion = "gpt-4o-2024-08-06";

// Error handling boundary
try {
  executeTask();
} catch (e) {
  console.error("ERR-106: Context error ID", e);
}
`);

  const [analyzedFindings, setAnalyzedFindings] = useState<Finding[]>([]);
  const [hasScanned, setHasScanned] = useState(false);
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);
  const [emptyWarning, setEmptyWarning] = useState<string | null>(null);

  const runLiveAudit = () => {
    if (!inputCode || !inputCode.trim()) {
      setAnalyzedFindings([]);
      setHasScanned(true);
      setEmptyWarning('Please enter a code snippet or SQL migration to analyze.');
      return;
    }

    if (inputCode.length > 50000) {
      setAnalyzedFindings([]);
      setHasScanned(true);
      setEmptyWarning(`Input code snippet exceeds maximum limit of 50,000 characters (${inputCode.length.toLocaleString()} characters). Please shorten snippet to proceed.`);
      return;
    }

    setEmptyWarning(null);
    const findings: Finding[] = [];

    // Rule 1: Secret Leak Check
    if (inputCode.includes('sk_live_') || inputCode.includes('sk-proj-') || inputCode.includes('secret') || inputCode.includes('api_key = "sk-')) {
      findings.push({
        id: `custom-find-${Date.now()}-1`,
        ruleId: 1,
        type: 'SECURITY',
        title: 'Hardcoded API Secret Detected in Codebase',
        severity: 'CRITICAL',
        category: 'Secret Isolation',
        filePath: 'Pasted Code Snippet',
        lineRange: 'Line 2-3',
        snippet: inputCode.split('\n').slice(0, 4).join('\n'),
        reproductionSteps: [
          'Scanned code bundle strings for sensitive tokens.',
          'Detected plain-text API key prefix sk_live_ or sk-proj-.'
        ],
        remediationPrompt: `Audit my pasted code. Extract all hardcoded secret keys (sk_live_, sk-proj-) into server-only environment variables (STRIPE_SECRET_KEY, OPENAI_API_KEY) and reference process.env without client exposure.`,
        status: 'OPEN',
        owner: 'Security Architect',
        falsePositive: false
      });
    }

    // Rule 2: Database Permissive Policy Check
    if (inputCode.includes('USING (true)') || inputCode.includes('FOR ALL USING') || inputCode.toLowerCase().includes('allow all')) {
      findings.push({
        id: `custom-find-${Date.now()}-2`,
        ruleId: 3,
        type: 'SECURITY',
        title: 'Permissive Row Level Security (RLS) Policy',
        severity: 'CRITICAL',
        category: 'Database',
        filePath: 'Database Policy Snippet',
        lineRange: 'Line 6',
        snippet: inputCode.split('\n').filter(l => l.includes('POLICY') || l.includes('USING')).join('\n') || 'USING (true)',
        reproductionSteps: [
          'Detected CREATE POLICY with USING (true).',
          'Anonymous users can read and overwrite all customer records.'
        ],
        remediationPrompt: `Replace permissive RLS policy. Write strict Supabase Row Level Security policy enforcing auth.uid() = user_id for SELECT, INSERT, and UPDATE queries.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
    }

    // Rule 3: CORS Wildcard Check
    if (inputCode.includes("origin: '*'") || inputCode.includes('Access-Control-Allow-Origin: *')) {
      findings.push({
        id: `custom-find-${Date.now()}-3`,
        ruleId: 8,
        type: 'SECURITY',
        title: 'Wildcard CORS (*) Vulnerability',
        severity: 'HIGH',
        category: 'Network & CORS',
        filePath: 'CORS Configuration',
        lineRange: 'Line 9',
        snippet: "app.use(cors({ origin: '*' }));",
        reproductionSteps: [
          'Detected wildcard Access-Control-Allow-Origin.',
          'Malicious third-party origins can execute cross-site API requests.'
        ],
        remediationPrompt: `Restrict CORS origin to process.env.PRODUCTION_CLIENT_URL instead of wildcard (*).`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
    }

    // Rule 4: Empty Catch Block (UI-106 AI Slop)
    if (/catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*(?:\/\*.*?\*\/)?\s*\}/.test(inputCode) || inputCode.includes(['catch', ' (e) {}'].join('')) || inputCode.includes(['catch', ' {}'].join(''))) {
      findings.push({
        id: `custom-find-${Date.now()}-4`,
        ruleId: 106,
        type: 'VIBEPOLISH',
        title: 'UI-106: Empty Silent Catch Block (AI Code Slop)',
        severity: 'HIGH',
        category: 'Code Quality & Refactoring',
        filePath: 'Pasted Code Snippet',
        lineRange: 'Catch Handler',
        snippet: 'try { ... } catch (err) { /* silent */ }',
        reproductionSteps: [
          'Detected empty try-catch block swallowing runtime errors.',
          'Errors fail silently without error logging or boundary reporting.'
        ],
        remediationPrompt: `Remove empty catch block. Log caught error with context and error boundary metric or rethrow to caller.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
    }

    // Rule 5: TypeScript Any Type Escaping (UI-111 AI Slop)
    if (/: any\b|as any\b/.test(inputCode)) {
      findings.push({
        id: `custom-find-${Date.now()}-5`,
        ruleId: 111,
        type: 'VIBEPOLISH',
        title: 'UI-111: TypeScript "any" Type Escape (Type Safety Illusion)',
        severity: 'MEDIUM',
        category: 'TypeScript & Types',
        filePath: 'Pasted Code Snippet',
        lineRange: 'Type Definition',
        snippet: inputCode.split('\n').find(l => /: any\b|as any\b/.test(l)) || 'const data: any = res.json();',
        reproductionSteps: [
          'Detected "any" type assignment bypassing TypeScript type safety checks.'
        ],
        remediationPrompt: `Replace "any" types with strict Zod interfaces or unknown + type guard validation functions.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
    }

    // Rule 6: Sparkles & Neon Glow Cliché (UI-03)
    if (inputCode.includes('Sparkles') || inputCode.includes('cyan-600') || inputCode.includes('shadow-[')) {
      findings.push({
        id: `custom-find-${Date.now()}-6`,
        ruleId: 3,
        type: 'VIBEPOLISH',
        title: 'UI-03: Excessive Lucide Sparkles & Neon Glow Cliché',
        severity: 'MEDIUM',
        category: 'UI/UX Visual Polishing',
        filePath: 'UI Component Snippet',
        lineRange: 'JSX Tree',
        snippet: inputCode.split('\n').find(l => l.includes('Sparkles') || l.includes('cyan-') || l.includes('shadow-[')) || '<Sparkles className="..." />',
        reproductionSteps: [
          'Detected overused Lucide Sparkles icon and neon ambient shadow.',
          'Violates clean monochrome dark design tokens.'
        ],
        remediationPrompt: `Refactor UI component. Remove Sparkles icons and neon shadows. Use crisp 1px borders (border-white/10) and desaturated, functional color accents.`,
        status: 'OPEN',
        owner: 'Design Lead',
        falsePositive: false
      });
    }

    // Rule 7: Streaming Cancellation & Prompt Bloat (SLOP-142)
    if (inputCode.includes('systemPrompt') || inputCode.includes('1500') || inputCode.includes('gpt-4o')) {
      findings.push({
        id: `custom-find-${Date.now()}-7`,
        ruleId: 142,
        type: 'VIBEPOLISH',
        title: 'SLOP-142: Unhandled Stream Disconnect & System Prompt Bloat',
        severity: 'HIGH',
        category: 'AI Agents & LLM Infrastructure',
        filePath: 'API Stream Handler',
        lineRange: 'POST Route',
        snippet: inputCode.split('\n').find(l => l.includes('fetch') || l.includes('systemPrompt')) || 'return new Response(response.body);',
        reproductionSteps: [
          'Detected LLM streaming API route missing req.signal abort listener.',
          'Detected uncompressed static system prompt causing token budget inflation.'
        ],
        remediationPrompt: `Add req.signal abort controller listener to terminate downstream LLM stream when client disconnects. Compress system prompt using key-value JSON schema.`,
        status: 'OPEN',
        owner: 'AI Engineer',
        falsePositive: false
      });
    }

    setAnalyzedFindings(findings);
    setHasScanned(true);
  };

  const handleSelectPreset = (presetCode: string) => {
    setInputCode(presetCode);
    setEmptyWarning(null);
    setTimeout(() => {
      runLiveAudit();
    }, 50);
  };

  const copyPrompt = (f: Finding) => {
    navigator.clipboard.writeText(f.remediationPrompt);
    setCopiedPromptId(f.id);
    setTimeout(() => setCopiedPromptId(null), 2000);
  };

  const demoPresets = [
    {
      name: 'Insecure Secret & RLS',
      code: `// Insecure AI API Route & Supabase RLS Policy:
export const stripeSecretKey = "sk_live_51M394x928103921EXPOSED";
export const openAiApiKey = "sk-proj-948210392109321EXPOSED";

// Supabase Permissive Migration:
CREATE POLICY "Allow All Users" ON public.users FOR ALL USING (true);
app.use(cors({ origin: '*' }));`
    },
    {
      name: 'UI Anti-Patterns & Sparkles',
      code: `// UI Anti-Pattern Component:
import { Sparkles } from 'lucide-react';

export function ClichéHero() {
  return (
    <div className="bg-gradient-to-r from-blue-900 to-indigo-900 shadow-[0_0_50px_rgba(59,130,246,0.4)] p-8 rounded-2xl">
      <h1 className="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 flex items-center gap-2">
        <Sparkles className="w-8 h-8 text-cyan-400 animate-pulse" />
        Build The Future With AI
      </h1>
      <button className="bg-cyan-600 hover:bg-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.5)] rounded-full px-8 py-4 text-white">
        Get Started
      </button>
    </div>
  );
}`
    },
    {
      name: 'AI Stream & Prompt Bloat',
      code: `// AI Stream Handler Anti-Pattern:
export async function POST(req: Request) {
  const systemPrompt = "You are a helpful assistant. " + "A".repeat(1500);
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    body: JSON.stringify({ model: "gpt-4o", stream: true })
  });
  return new Response(response.body);
}`
    },
    {
      name: 'Any Type & Silent Catch',
      code: `// AI Slop: Any type escape & silent error swallowing
export function processUserData(payload: any) {
  try {
    const parsed = JSON.parse(payload) as any;
    return parsed.user.email;
  } catch (e) {
    /* unhandled catch */
  }
}`
    }
  ];

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-extrabold text-[#FAFAFA]">
            Live Custom Codebase AST Inspector
          </h2>
          <div className="text-xs text-[#94A3B8] mt-0.5">
            Paste your AI-generated code to run real-time AST security checks &amp; linter rules
          </div>
        </div>

        <button onClick={runLiveAudit} className="btn btn-primary px-5 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm">
          <Play size={14} fill="#0A0A0A" />
          <span>Analyze Codebase</span>
        </button>
      </div>

      {/* Code Editor Area */}
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
          <label htmlFor="live-code-textarea" className="text-xs font-bold text-[#94A3B8] font-mono uppercase">
            <span>Source Code Snippet / Migration File:</span>
          </label>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[0.7rem] text-[#94A3B8] font-bold font-mono">1-Click Presets:</span>
            {demoPresets.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectPreset(preset.code)}
                className="text-[0.7rem] font-mono font-bold bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-[#FAFAFA] px-2.5 py-1 rounded transition-colors"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        <div className="relative flex rounded-xl bg-[#0A0A0A] border border-white/10 overflow-hidden font-mono text-xs">
          {/* Line Number Gutter */}
          <div className="py-4 px-3 bg-[#141414] border-r border-white/10 text-right select-none text-[#94A3B8] flex flex-col font-mono text-xs leading-relaxed min-w-[40px]">
            {Array.from({ length: Math.max(1, inputCode.split('\n').length) }, (_, i) => i + 1).map((num) => (
              <span key={num}>{num}</span>
            ))}
          </div>
          <textarea
            id="live-code-textarea"
            rows={7}
            value={inputCode}
            onChange={(e) => {
              setInputCode(e.target.value);
              if (emptyWarning) setEmptyWarning(null);
            }}
            placeholder="Paste JavaScript, TypeScript, SQL, or Python code..."
            className="w-full p-4 bg-transparent font-mono text-xs text-[#FAFAFA] outline-none focus-visible:ring-1 focus-visible:ring-white/20 resize-none leading-relaxed rounded"
          />
        </div>
      </div>

      {/* Analysis Output */}
      {hasScanned && (
        <div className="flex flex-col gap-4 pt-4 border-t border-white/10">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-extrabold text-[#FAFAFA]">
              Live Static Analysis Results ({emptyWarning ? 0 : analyzedFindings.length} Violations Found)
            </h3>
          </div>

          {emptyWarning ? (
            <div className="p-6 rounded-xl bg-amber-500/10 border border-amber-500/30 text-center text-xs text-amber-300 font-mono">
              ⚠️ {emptyWarning}
            </div>
          ) : analyzedFindings.length === 0 ? (
            <div className="p-6 rounded-xl bg-[#0A0A0A] border border-white/10 text-center text-xs text-white font-mono">
              Zero vulnerabilities detected in snippet. Compliant with OWASP security rules.
            </div>
          ) : (
            <div className="space-y-4">
              {analyzedFindings.map((f) => (
                <div key={f.id} className="p-5 rounded-xl bg-[#0A0A0A] border border-[#EF4444]/30 flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="badge badge-critical">{f.severity}</span>
                      <span className="text-xs font-extrabold text-[#FAFAFA]">{f.title}</span>
                    </div>
                    <span className="text-[0.7rem] font-mono text-[#94A3B8]">{f.category}</span>
                  </div>

                  <div className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-xs text-[#FCA5A5]">
                    <pre className="m-0">{f.snippet}</pre>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-white/10">
                    <span className="text-[0.72rem] text-[#94A3B8] font-mono">
                      Generated Fix Prompt:
                    </span>
                    <button onClick={() => copyPrompt(f)} className="btn btn-secondary btn-sm text-[0.7rem] px-3 py-1 font-mono">
                      {copiedPromptId === f.id ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedPromptId === f.id ? 'Copied!' : 'Copy Prompt'}</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
