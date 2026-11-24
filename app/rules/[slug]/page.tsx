import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { RULE_PAGES, ruleBySlug } from '@/data/rule-pages';

export const dynamicParams = false;

export function generateStaticParams() {
  return RULE_PAGES.map((r) => ({ slug: r.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const r = ruleBySlug((await params).slug);
  if (!r) return {};
  return { title: r.title, description: r.description, alternates: { canonical: `/rules/${r.slug}` } };
}

export default async function RulePageView({ params }: { params: Promise<{ slug: string }> }) {
  const r = ruleBySlug((await params).slug);
  if (!r) notFound();

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans px-4 sm:px-6 py-10 sm:py-14">
      <div className="max-w-3xl mx-auto">
        <Link href="/docs/rules" className="inline-flex items-center text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          All rules
        </Link>
        <p className="mt-8 text-xs uppercase tracking-widest text-emerald-400">{r.severity} · {r.code}</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-extrabold tracking-tight text-white">{r.title}</h1>
        <p className="mt-4 text-zinc-400 leading-relaxed">{r.description}</p>

        <h2 className="mt-10 text-xl font-semibold text-white">What it costs you</h2>
        <p className="mt-2 text-zinc-300 leading-relaxed">{r.consequence}</p>

        <h2 className="mt-10 text-xl font-semibold text-white">The code Zelsis flags</h2>
        <div className="mt-4 rounded-xl border border-white/10 bg-[#0A0A0A] p-4 text-xs font-mono leading-relaxed">
          <div className="text-zinc-500 mb-2 truncate">{r.path}</div>
          <div className="text-red-400 mb-1.5">Flagged</div>
          <pre className="text-zinc-400 mb-4 overflow-x-auto"><code>{r.bad}</code></pre>
          <div className="text-emerald-400 mb-1.5">Passes</div>
          <pre className="text-zinc-200 overflow-x-auto"><code>{r.good}</code></pre>
        </div>

        <h2 className="mt-10 text-xl font-semibold text-white">How to fix it</h2>
        <p className="mt-2 text-zinc-300 leading-relaxed">{r.fix}</p>

        <div className="mt-12 flex flex-wrap gap-3">
          <Link href="/" className="inline-flex items-center min-h-11 px-5 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400">Scan my repo free</Link>
          <Link href={`/checks/${r.category}`} className="inline-flex items-center min-h-11 px-5 rounded-lg border border-white/15 text-sm text-zinc-200 hover:border-white/30">See the whole category</Link>
        </div>

        <nav aria-label="Other rules" className="mt-12 pt-6 border-t border-white/10 flex flex-wrap gap-x-5 gap-y-2 text-sm">
          {RULE_PAGES.filter((o) => o.slug !== r.slug).map((o) => (
            <Link key={o.slug} href={`/rules/${o.slug}`} className="text-zinc-400 hover:text-white">{o.title}</Link>
          ))}
        </nav>
      </div>
    </div>
  );
}
