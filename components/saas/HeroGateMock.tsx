import { Sparkles } from 'lucide-react';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

interface ExampleFinding {
  severity: Severity;
  title: string;
  location: string;
}

// Illustrative result for a typical Next.js + Supabase + Stripe starter; every finding is a class Zelsis detects.
const EXAMPLE_FINDINGS: ExampleFinding[] = [
  { severity: 'CRITICAL', title: 'Row Level Security disabled on table "invoices"', location: 'supabase/migrations/0003_invoices.sql:12' },
  { severity: 'CRITICAL', title: 'Stripe secret key committed to the repository', location: 'lib/stripe.ts:4' },
  { severity: 'HIGH', title: 'Webhook handler accepts events without verifying the signature', location: 'app/api/webhooks/stripe/route.ts:18' },
  { severity: 'HIGH', title: 'Open redirect through the ?next= parameter', location: 'app/auth/callback/route.ts:27' },
  { severity: 'MEDIUM', title: 'Dependency with a published security advisory', location: 'package-lock.json' },
];

const severityStyle: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/15 text-red-300 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
};

/** Readable example of a failing release gate, drawn in HTML so it stays sharp and light on every screen. */
export function HeroGateMock() {
  const criticals = EXAMPLE_FINDINGS.filter((f) => f.severity === 'CRITICAL').length;
  const highs = EXAMPLE_FINDINGS.filter((f) => f.severity === 'HIGH').length;

  return (
    <div className="bg-[#0A0A0A] p-4 sm:p-6 flex flex-col gap-4">
      {/* Verdict */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-lg border border-red-500/30 bg-red-500/[0.07]">
        <div className="flex items-center gap-3 min-w-0">
          <span className="shrink-0 px-2.5 py-1 rounded-md bg-red-500 text-black text-xs font-mono font-bold uppercase tracking-wider">
            Gate failed
          </span>
          <span className="text-sm text-zinc-200 truncate">
            acme/saas-starter · <span className="font-mono">main</span>
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono text-zinc-300">
          <span>
            Score <strong className="text-white text-base">62</strong>/100
          </span>
          <span className="text-red-300">{criticals} critical</span>
          <span className="text-orange-300">{highs} high</span>
        </div>
      </div>

      {/* Findings */}
      <ul className="flex flex-col divide-y divide-white/5 rounded-lg border border-white/10 bg-[#111113]">
        {EXAMPLE_FINDINGS.map((f, i) => (
          <li key={f.title} className={`flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 px-4 py-3 ${i > 2 ? 'hidden sm:flex' : ''}`}>
            <span className={`self-start sm:self-auto shrink-0 w-20 text-center px-2 py-0.5 rounded border text-xs font-mono font-bold ${severityStyle[f.severity]}`}>
              {f.severity}
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-sm text-zinc-100">{f.title}</div>
              <div className="text-xs font-mono text-zinc-400 truncate">{f.location}</div>
            </div>
            <span className="hidden md:inline-flex shrink-0 items-center gap-1.5 text-xs text-emerald-400 border border-emerald-500/30 bg-emerald-500/10 rounded px-2 py-1">
              <Sparkles size={12} aria-hidden="true" />
              Fix prompt
            </span>
          </li>
        ))}
      </ul>

      <p className="text-xs text-zinc-400">
        Release blocked until the critical findings are fixed. Every finding links to the exact line and a fix you can paste into your AI assistant.
      </p>
    </div>
  );
}
