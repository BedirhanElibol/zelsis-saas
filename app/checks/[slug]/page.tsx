import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AlertCircle, ArrowLeft, Check, ShieldCheck } from 'lucide-react';
import { CATEGORY_PAGES, categoryBySlug } from '@/data/category-pages';
import { LANDING_CHECKS } from '@/data/landing-checks';

export const dynamicParams = false;

export function generateStaticParams() {
  return CATEGORY_PAGES.map((c) => ({ slug: c.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const c = categoryBySlug((await params).slug);
  if (!c) return {};
  return { title: c.title, description: c.description, alternates: { canonical: `/checks/${c.slug}` } };
}

export default async function CategoryPage({ params }: { params: Promise<{ slug: string }> }) {
  const c = categoryBySlug((await params).slug);
  if (!c) notFound();
  const examples = c.landing ? LANDING_CHECKS.filter((x) => x.category === c.landing).slice(0, 2) : [];

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans px-4 sm:px-6 py-10 sm:py-14">
      <div className="max-w-4xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <p className="mt-8 text-xs font-mono uppercase tracking-widest text-emerald-400">What Zelsis checks · {c.name}</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-extrabold tracking-tight text-white">{c.title}</h1>
        <p className="mt-4 text-zinc-400 leading-relaxed">{c.lead}</p>

        <h2 className="mt-10 text-xl font-semibold text-white">Checked on every pull request</h2>
        <ul className="mt-4 flex flex-col gap-2.5">
          {c.checks.map((line) => (
            <li key={line} className="flex items-start gap-2.5 text-zinc-300">
              <Check size={16} className="text-emerald-400 shrink-0 mt-1" aria-hidden="true" />
              <span>{line}</span>
            </li>
          ))}
        </ul>

        {examples.length > 0 && (
          <>
            <h2 className="mt-12 text-xl font-semibold text-white">Caught in real code</h2>
            <p className="mt-2 text-sm text-zinc-400">Our test suite scans these examples on every release.</p>
            <div className="mt-5 flex flex-col gap-5">
              {examples.map((x) => (
                <article key={x.ruleId} className="rounded-xl border border-white/10 bg-[#121214] overflow-hidden">
                  <div className="p-5 border-b border-white/5">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="font-semibold text-white">{x.title}</h3>
                      <span className="shrink-0 px-2 py-0.5 rounded bg-white/5 text-[0.68rem] font-mono text-zinc-300">{x.code}</span>
                    </div>
                    <p className="mt-2 text-sm text-zinc-400">{x.description}</p>
                  </div>
                  <div className="bg-[#0A0A0A] p-4 text-xs font-mono leading-relaxed">
                    <div className="text-zinc-500 mb-2 truncate">{x.path}</div>
                    <div className="text-red-400 mb-1.5 flex items-center gap-2"><AlertCircle className="w-3 h-3" aria-hidden="true" /> Flagged</div>
                    <pre className="text-zinc-400 mb-4 overflow-x-auto"><code>{x.bad}</code></pre>
                    <div className="text-emerald-400 mb-1.5 flex items-center gap-2"><ShieldCheck className="w-3 h-3" aria-hidden="true" /> Passes</div>
                    <pre className="text-zinc-200 overflow-x-auto"><code>{x.good}</code></pre>
                  </div>
                </article>
              ))}
            </div>
          </>
        )}

        <div className="mt-12 flex flex-wrap gap-3">
          <Link href="/#pricing" className="inline-flex items-center min-h-11 px-5 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400">Scan a repository</Link>
          {c.slug === 'looks-unfinished' && (
            <Link href="/site-check" className="inline-flex items-center min-h-11 px-5 rounded-lg border border-white/15 text-sm text-zinc-200 hover:border-white/30">Check a live page for free</Link>
          )}
        </div>

        <nav aria-label="Other categories" className="mt-12 pt-6 border-t border-white/10 flex flex-wrap gap-x-5 gap-y-2 text-sm">
          {CATEGORY_PAGES.filter((o) => o.slug !== c.slug).map((o) => (
            <Link key={o.slug} href={`/checks/${o.slug}`} className="text-zinc-400 hover:text-white">{o.name}</Link>
          ))}
        </nav>
      </div>
    </div>
  );
}
