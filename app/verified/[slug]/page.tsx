import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, CircleCheck, CircleAlert, Clock, ShieldCheck } from 'lucide-react';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { isTrustSlug, toTrustSummary, TRUST_MAX_AGE_DAYS, type TrustSummary } from '@/lib/trust-page';

export const dynamic = 'force-dynamic';

type Lookup = { name: string; summary: TrustSummary } | { error: 'not-found' | 'no-scan' | 'unavailable' };

async function loadTrustPage(slug: string): Promise<Lookup> {
  if (!isTrustSlug(slug)) return { error: 'not-found' };
  const admin = getSupabaseAdmin();
  if (!admin) return { error: 'unavailable' };
  const { data: page } = await admin
    .from('trust_pages')
    .select('user_id, project_id, display_name, revoked_at')
    .eq('slug', slug)
    .maybeSingle();
  if (!page || page.revoked_at) return { error: 'not-found' };
  const { data: job } = await admin
    .from('scan_jobs')
    .select('result_data, updated_at, created_at')
    .eq('user_id', page.user_id)
    .eq('project_id', page.project_id)
    .eq('status', 'COMPLETED')
    .not('result_data', 'is', null)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  const summary = job ? toTrustSummary(job.result_data, job.updated_at || job.created_at) : null;
  return summary ? { name: page.display_name, summary } : { error: 'no-scan' };
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const result = await loadTrustPage(slug);
  if ('error' in result) return { title: 'Trust page', robots: { index: false, follow: false } };
  return {
    title: `${result.name}: security checks by Zelsis`,
    description: `Automated security and logic checks for ${result.name}, run by Zelsis on every change.`,
  };
}

const STATUS = {
  verified: { label: 'No open critical or high issues', icon: CircleCheck, cls: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' },
  'issues-open': { label: 'Issues are being fixed', icon: CircleAlert, cls: 'text-amber-300 border-amber-500/30 bg-amber-500/10' },
  stale: { label: `No check in the last ${TRUST_MAX_AGE_DAYS} days`, icon: Clock, cls: 'text-zinc-300 border-white/15 bg-white/5' },
} as const;

function CheckYourOwn() {
  return (
    <div className="mt-10 p-5 rounded-xl border border-white/10 bg-[#141414] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <p className="font-semibold text-white">Want a page like this for your app?</p>
        <p className="text-sm text-zinc-400">Zelsis checks every pull request for leaked keys, broken access control and logic bugs.</p>
      </div>
      <Link href="/?ref=trust-page" className="inline-flex items-center justify-center gap-2 px-4 min-h-11 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400 focus-visible:ring-2 focus-visible:ring-white focus-visible:outline-none">
        Check your app <ArrowRight size={14} aria-hidden="true" />
      </Link>
    </div>
  );
}

export default async function TrustPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const result = await loadTrustPage(slug);

  if ('error' in result) {
    const message = result.error === 'unavailable'
      ? 'This page cannot be loaded right now. Try again in a few minutes.'
      : result.error === 'no-scan'
        ? 'This project has no completed check yet.'
        : 'This page does not exist or the owner turned it off.';
    return (
      <main className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-24">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-2xl font-bold text-white mb-2">Trust page not available</h1>
          <p className="text-zinc-400">{message}</p>
          <CheckYourOwn />
        </div>
      </main>
    );
  }

  const { name, summary } = result;
  const status = STATUS[summary.status];
  const StatusIcon = status.icon;
  const checked = new Date(summary.scannedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

  return (
    <main className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] px-4 py-16 sm:py-24">
      <div className="max-w-3xl mx-auto">
        <p className="text-xs font-mono uppercase tracking-widest text-zinc-400 mb-3 flex items-center gap-2">
          <ShieldCheck size={14} aria-hidden="true" /> Checked by Zelsis
        </p>
        <h1 className="text-2xl sm:text-3xl font-bold text-white break-words">{name}</h1>
        <p className="text-sm text-zinc-400 mt-1">Last checked {checked}</p>

        <div className={`mt-8 p-5 rounded-xl border flex items-center gap-3 ${status.cls}`}>
          <StatusIcon size={22} aria-hidden="true" className="shrink-0" />
          <div>
            <p className="font-semibold">{status.label}</p>
            <p className="text-sm opacity-80">Readiness score {summary.score}/100 on the latest check.</p>
          </div>
        </div>

        <h2 className="text-lg font-semibold text-white mt-10 mb-3">What is checked</h2>
        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {summary.areas.map((a) => (
            <li key={a.kind} className="p-3 rounded-lg border border-white/10 bg-[#121212] flex items-center justify-between gap-3">
              <span className="text-sm text-white">{a.label}</span>
              {a.open === 0 ? (
                <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1"><CircleCheck size={14} aria-hidden="true" /> Clear</span>
              ) : (
                <span className="text-xs font-semibold text-amber-300">{a.open} open</span>
              )}
            </li>
          ))}
        </ul>

        <h2 className="text-lg font-semibold text-white mt-10 mb-3">Not covered by this check</h2>
        <ul className="text-sm text-zinc-300 space-y-2 list-disc pl-5">
          <li>The running application: no attack traffic, fuzzing or penetration testing against live servers.</li>
          <li>Business rules that need human judgment, such as whether a discount or approval flow is fair.</li>
          <li>Live database and cloud settings that are changed outside the code (for example in a hosting dashboard).</li>
        </ul>

        <div className="mt-8 text-xs text-zinc-400 space-y-2">
          <p>
            Zelsis reads the source code and configuration of this project and checks them with deterministic rules: access
            control, leaked keys, payment and webhook logic, database policies, injection and deployment settings. Details of
            open issues are visible only to the project owner.
          </p>
          <p>
            This page reports automated checks. It is not a penetration test, an audit or a certification, and a clear result
            does not mean the software has no security issues. See{' '}
            <Link href="/docs/boundaries" className="underline hover:text-white">what Zelsis does not check</Link>.
          </p>
        </div>

        <CheckYourOwn />
      </div>
    </main>
  );
}
