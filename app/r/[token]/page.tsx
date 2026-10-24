import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, CircleAlert, CircleCheck, CircleX, ShieldCheck } from 'lucide-react';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { isShareToken, toPublicReport, type PublicReport } from '@/lib/report-share';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Shared security report',
  robots: { index: false, follow: false },
};

type Lookup = { report: PublicReport } | { error: 'not-found' | 'revoked' | 'unavailable' };

async function loadReport(token: string): Promise<Lookup> {
  if (!isShareToken(token)) return { error: 'not-found' };
  const admin = getSupabaseAdmin();
  if (!admin) return { error: 'unavailable' };
  const { data: share } = await admin.from('report_shares').select('job_id, revoked_at').eq('token', token).maybeSingle();
  if (!share) return { error: 'not-found' };
  if (share.revoked_at) return { error: 'revoked' };
  const { data: job } = await admin
    .from('scan_jobs')
    .select('repo_url, result_data, updated_at, created_at')
    .eq('id', share.job_id)
    .eq('status', 'COMPLETED')
    .maybeSingle();
  const report = job ? toPublicReport(job.result_data, job.repo_url, job.updated_at || job.created_at) : null;
  return report ? { report } : { error: 'not-found' };
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-300 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  LOW: 'bg-white/5 text-zinc-300 border-white/15',
};

const GATE = {
  PASSED: { label: 'Gate passed', icon: CircleCheck, cls: 'text-emerald-400' },
  WARNING: { label: 'Passed with warnings', icon: CircleAlert, cls: 'text-amber-300' },
  FAILED: { label: 'Gate failed', icon: CircleX, cls: 'text-red-400' },
} as const;

function ScanYourOwn() {
  return (
    <div className="mt-10 p-5 rounded-xl border border-white/10 bg-[#141414] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <p className="font-semibold text-white">Check your own app</p>
        <p className="text-sm text-zinc-400">Zelsis finds leaked keys, broken auth and logic bugs before they ship. Free plan, no credit card.</p>
      </div>
      <Link href="/?ref=shared-report" className="inline-flex items-center justify-center gap-2 px-4 min-h-11 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400 focus-visible:ring-2 focus-visible:ring-white focus-visible:outline-none">
        Scan a repository <ArrowRight size={14} aria-hidden="true" />
      </Link>
    </div>
  );
}

export default async function SharedReportPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const result = await loadReport(token);

  if ('error' in result) {
    const message = result.error === 'revoked'
      ? 'The owner turned this link off.'
      : result.error === 'unavailable'
        ? 'Reports cannot be loaded right now. Try again in a few minutes.'
        : 'This link does not exist or the report was deleted.';
    return (
      <main className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-24">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-2xl font-bold text-white mb-2">Report not available</h1>
          <p className="text-zinc-400">{message}</p>
          <ScanYourOwn />
        </div>
      </main>
    );
  }

  const { report } = result;
  const gate = GATE[report.gateStatus];
  const GateIcon = gate.icon;
  return (
    <main className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-16 sm:py-24">
      <div className="max-w-3xl mx-auto">
        <p className="text-xs font-mono uppercase tracking-widest text-zinc-400 mb-3 flex items-center gap-2">
          <ShieldCheck size={14} aria-hidden="true" /> Shared Zelsis report
        </p>
        <h1 className="text-2xl sm:text-3xl font-bold text-white break-words">{report.target}</h1>
        <p className="text-sm text-zinc-400 mt-1">Scanned {new Date(report.scannedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</p>

        <div className="mt-8 grid grid-cols-2 sm:grid-cols-6 gap-3">
          <div className="col-span-2 p-4 rounded-xl border border-white/10 bg-[#141414]">
            <p className="text-xs text-zinc-400">Score</p>
            <p className="text-3xl font-extrabold text-white tabular-nums">{report.score}<span className="text-base text-zinc-400">/100</span></p>
            <p className={`text-sm font-semibold flex items-center gap-1.5 mt-1 ${gate.cls}`}><GateIcon size={14} aria-hidden="true" />{gate.label}</p>
          </div>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
            <div key={s} className="p-4 rounded-xl border border-white/10 bg-[#141414]">
              <p className="text-xs text-zinc-400">{s.charAt(0) + s.slice(1).toLowerCase()}</p>
              <p className="text-2xl font-bold text-white tabular-nums">{report.counts[s]}</p>
            </div>
          ))}
        </div>

        <h2 className="text-lg font-semibold text-white mt-10 mb-3">Findings ({report.findings.length})</h2>
        {report.findings.length === 0 ? (
          <p className="text-zinc-400">No open findings.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {report.findings.map((f, i) => (
              <li key={i} className="p-3 rounded-lg border border-white/10 bg-[#121212] flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-3 min-w-0">
                <span className={`shrink-0 self-start px-2 py-0.5 rounded border text-[0.68rem] font-mono font-bold ${SEVERITY_STYLE[f.severity]}`}>{f.severity}</span>
                <div className="min-w-0">
                  <p className="text-sm text-white break-words">{f.title}</p>
                  <p className="text-xs font-mono text-zinc-400 break-all">{f.filePath}{f.lineRange ? `:${f.lineRange.replace(/^L/, '')}` : ''}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-zinc-400 mt-6">
          Shared by the project owner. Code snippets and fix instructions are not included in shared reports.
        </p>

        <ScanYourOwn />
      </div>
    </main>
  );
}
