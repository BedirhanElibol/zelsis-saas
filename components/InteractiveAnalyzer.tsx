'use client';

import React, { useState } from 'react';
import { Finding } from '@/data/schema';
import { Play, CheckCircle2, Copy, Loader2 } from 'lucide-react';

// Loaded on first use: the rule engine is ~3 MB of JS. It runs in this tab and makes no network
// calls (the OSV dependency lookup is off unless a caller opts in), so the snippet is never uploaded.
const runStaticCodeScan: typeof import('@/lib/scanner-engine').runStaticCodeScan = async (...args) =>
  (await import('@/lib/scanner-engine')).runStaticCodeScan(...args);

const MAX_CODE_LENGTH = 50000;

// Many rules key off the file path (route handlers, migrations, Dockerfiles, language extensions),
// so the snippet is scanned under a realistic path for the chosen file type.
const FILE_TYPES = [
  { label: 'Next.js route (route.ts)', path: 'app/api/billing/route.ts' },
  { label: 'React component (.tsx)', path: 'components/Example.tsx' },
  { label: 'SQL migration (.sql)', path: 'supabase/migrations/20260101000000_example.sql' },
  { label: 'Dockerfile', path: 'Dockerfile' },
  { label: 'Python (.py)', path: 'app/main.py' },
  { label: 'Go (.go)', path: 'handlers/example.go' },
  { label: 'Ruby (.rb)', path: 'app/controllers/example_controller.rb' },
  { label: 'PHP (.php)', path: 'public/index.php' },
  { label: 'Java (.java)', path: 'src/main/java/com/example/ExampleController.java' },
  { label: 'Kotlin (.kt)', path: 'app/src/main/java/com/example/Example.kt' },
  { label: 'Swift (.swift)', path: 'Sources/App/Example.swift' },
  { label: 'Dart (.dart)', path: 'lib/main.dart' },
  { label: 'C# (.cs)', path: 'Controllers/ExampleController.cs' },
] as const;

const PRESETS = [
  {
    name: 'Leaked secret',
    path: 'app/api/billing/route.ts',
    code: `import Stripe from 'stripe';

const stripe = new Stripe("sk_live_51M394x928103921aBcDeFgHiJkLmNoPq");

export async function POST(req: Request) {
  const { amount } = await req.json();
  const intent = await stripe.paymentIntents.create({ amount, currency: 'usd' });
  return Response.json(intent);
}
`,
  },
  {
    name: 'Permissive RLS',
    path: 'supabase/migrations/20260101000000_example.sql',
    code: `create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  stripe_customer_id text
);

alter table public.profiles enable row level security;

create policy "Anyone can update profiles"
  on public.profiles for update
  using (true);
`,
  },
  {
    name: 'Root container',
    path: 'Dockerfile',
    code: `FROM node:20
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
`,
  },
  {
    name: 'Python SQL injection',
    path: 'app/main.py',
    code: `import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    name = request.args.get("name")
    rows = conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()
    return {"rows": rows}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
`,
  },
  {
    name: 'Go SQL injection',
    path: 'handlers/example.go',
    code: `package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

func GetUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		row := db.QueryRow(fmt.Sprintf("SELECT email FROM users WHERE id = %s", id))
		var email string
		row.Scan(&email)
		fmt.Fprint(w, email)
	}
}
`,
  },
];

const SEVERITY_STYLES: Record<Finding['severity'], string> = {
  CRITICAL: 'bg-red-500/15 text-red-300 border-red-500/40',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  LOW: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  PASSED: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
};

type ScanState =
  | { kind: 'idle' }
  | { kind: 'scanning' }
  | { kind: 'warning'; message: string }
  | { kind: 'done'; findings: Finding[]; path: string; durationMs?: number };

export const InteractiveAnalyzer: React.FC = () => {
  const [inputCode, setInputCode] = useState<string>(PRESETS[0].code);
  const [filePath, setFilePath] = useState<string>(PRESETS[0].path);
  const [scan, setScan] = useState<ScanState>({ kind: 'idle' });
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);

  const selectedType = FILE_TYPES.find((t) => t.path === filePath)?.path ?? '';

  const runScan = async (code: string, path: string) => {
    if (!code.trim()) {
      setScan({ kind: 'warning', message: 'Paste a code snippet to scan.' });
      return;
    }
    if (code.length > MAX_CODE_LENGTH) {
      setScan({
        kind: 'warning',
        message: `The snippet is ${code.length.toLocaleString()} characters; the sandbox limit is ${MAX_CODE_LENGTH.toLocaleString()}.`,
      });
      return;
    }
    const scanPath = path.trim() || FILE_TYPES[0].path;

    setScan({ kind: 'scanning' });
    try {
      const result = await runStaticCodeScan([{ path: scanPath, content: code }], 'Sandbox');
      setScan({ kind: 'done', findings: result.findings, path: scanPath, durationMs: result.durationMs });
    } catch (err) {
      console.error('Sandbox scan failed', err);
      setScan({ kind: 'warning', message: 'The rule engine failed to load or run. Reload the page and try again.' });
    }
  };

  const handleSelectPreset = (preset: (typeof PRESETS)[number]) => {
    setInputCode(preset.code);
    setFilePath(preset.path);
    void runScan(preset.code, preset.path);
  };

  const copyPrompt = async (f: Finding) => {
    try {
      await navigator.clipboard.writeText(f.remediationPrompt);
      setCopiedPromptId(f.id);
      setTimeout(() => setCopiedPromptId(null), 2000);
    } catch (err) {
      console.error('Clipboard write failed', err);
    }
  };

  const isScanning = scan.kind === 'scanning';

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-extrabold text-[#FAFAFA]">Rule sandbox</h2>
          <div className="text-xs text-[#94A3B8] mt-0.5">
            Runs the same rule engine as repository scans, in this browser tab. The snippet is not uploaded.
          </div>
        </div>

        <button
          type="button"
          onClick={() => void runScan(inputCode, filePath)}
          disabled={isScanning}
          className="btn btn-primary px-5 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isScanning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} fill="#0A0A0A" />}
          <span>{isScanning ? 'Scanning…' : 'Scan snippet'}</span>
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[0.7rem] text-[#94A3B8] font-bold font-mono">Examples:</span>
        {PRESETS.map((preset) => (
          <button
            key={preset.name}
            type="button"
            onClick={() => handleSelectPreset(preset)}
            disabled={isScanning}
            className="text-[0.7rem] font-mono font-bold bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-[#FAFAFA] px-2.5 py-1 rounded transition-colors disabled:opacity-50"
          >
            {preset.name}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="sandbox-file-type" className="text-xs font-bold text-[#94A3B8] font-mono uppercase">
            File type
          </label>
          <select
            id="sandbox-file-type"
            value={selectedType}
            onChange={(e) => {
              if (e.target.value) setFilePath(e.target.value);
            }}
            className="bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-base sm:text-xs font-mono text-[#FAFAFA] outline-none focus-visible:ring-1 focus-visible:ring-white/20"
          >
            {!selectedType && <option value="">Custom path</option>}
            {FILE_TYPES.map((t) => (
              <option key={t.path} value={t.path}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="sandbox-file-path" className="text-xs font-bold text-[#94A3B8] font-mono uppercase">
            Scanned as path
          </label>
          <input
            id="sandbox-file-path"
            type="text"
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
            spellCheck={false}
            className="bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-base sm:text-xs font-mono text-[#FAFAFA] outline-none focus-visible:ring-1 focus-visible:ring-white/20"
          />
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <label htmlFor="live-code-textarea" className="text-xs font-bold text-[#94A3B8] font-mono uppercase">
            Snippet
          </label>
          <span className={`text-[0.68rem] font-mono ${inputCode.length > MAX_CODE_LENGTH ? 'text-amber-400' : 'text-[#71717A]'}`}>
            {inputCode.length.toLocaleString()} / {MAX_CODE_LENGTH.toLocaleString()} chars
          </span>
        </div>

        <div className="relative flex rounded-xl bg-[#0A0A0A] border border-white/10 overflow-hidden font-mono text-xs">
          <div className="py-4 px-3 bg-[#141414] border-r border-white/10 text-right select-none text-[#94A3B8] flex flex-col font-mono text-xs leading-relaxed min-w-[40px]">
            {Array.from({ length: Math.max(1, inputCode.split('\n').length) }, (_, i) => i + 1).map((num) => (
              <span key={num}>{num}</span>
            ))}
          </div>
          <textarea
            id="live-code-textarea"
            rows={12}
            value={inputCode}
            onChange={(e) => {
              setInputCode(e.target.value);
              if (scan.kind === 'warning') setScan({ kind: 'idle' });
            }}
            spellCheck={false}
            placeholder="Paste a route handler, migration, Dockerfile or component…"
            className="w-full p-4 bg-transparent font-mono text-base sm:text-xs text-[#FAFAFA] outline-none focus-visible:ring-1 focus-visible:ring-white/20 resize-none leading-relaxed rounded"
          />
        </div>
      </div>

      {scan.kind !== 'idle' && (
        <div className="flex flex-col gap-4 pt-4 border-t border-white/10" aria-live="polite">
          {scan.kind === 'scanning' && (
            <div className="text-xs text-[#94A3B8] font-mono flex items-center gap-2">
              <Loader2 size={14} className="animate-spin" />
              Running the rule engine…
            </div>
          )}

          {scan.kind === 'warning' && (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 font-mono">
              {scan.message}
            </div>
          )}

          {scan.kind === 'done' && (
            <>
              <h3 className="text-sm font-extrabold text-[#FAFAFA]">
                {scan.findings.length} {scan.findings.length === 1 ? 'finding' : 'findings'} in{' '}
                <span className="font-mono text-[#94A3B8]">{scan.path}</span>
                {typeof scan.durationMs === 'number' && (
                  <span className="text-xs font-normal text-[#71717A]"> · {scan.durationMs} ms</span>
                )}
              </h3>

              {scan.findings.length === 0 ? (
                <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#FAFAFA] font-mono">
                  No rule matched this snippet. A repository scan also runs cross-file rules that a single snippet
                  cannot trigger.
                </div>
              ) : (
                <div className="space-y-4">
                  {scan.findings.map((f) => (
                    <div key={f.id} className="p-5 rounded-xl bg-[#0A0A0A] border border-white/10 flex flex-col gap-3">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="flex items-start gap-2 min-w-0">
                          <span className={`shrink-0 px-2 py-0.5 rounded border text-[0.65rem] font-bold font-mono ${SEVERITY_STYLES[f.severity]}`}>
                            {f.severity}
                          </span>
                          <span className="text-xs font-extrabold text-[#FAFAFA] break-words">{f.title}</span>
                        </div>
                        <span className="text-[0.7rem] font-mono text-[#94A3B8]">
                          {f.lineRange}
                          {f.maturity ? ` · ${f.maturity}` : ''}
                        </span>
                      </div>

                      {f.snippet && (
                        <div className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-xs text-[#FCA5A5] overflow-x-auto">
                          <pre className="m-0">{f.snippet}</pre>
                        </div>
                      )}

                      <div className="flex items-center justify-between pt-2 border-t border-white/10">
                        <span className="text-[0.72rem] text-[#94A3B8] font-mono">{f.category}</span>
                        <button
                          type="button"
                          onClick={() => void copyPrompt(f)}
                          className="btn btn-secondary btn-sm text-[0.7rem] px-3 py-1 font-mono"
                        >
                          {copiedPromptId === f.id ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Copy size={12} />}
                          <span>{copiedPromptId === f.id ? 'Copied' : 'Copy fix prompt'}</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
