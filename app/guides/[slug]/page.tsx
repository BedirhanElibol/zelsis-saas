import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ScanCta } from '@/components/guides/GuideParts';
import { COMPARED_ON, COMPETITOR_ROWS } from '@/components/saas/CompetitorComparison';

// "<Tool> alternative" pages. Every claim about the other tool comes from the homepage comparison table, which is
// taken from their public pricing pages; nothing here is new or guessed.

type Key = 'snyk' | 'semgrep' | 'aikido' | 'github';

const TOOLS: Record<string, { key: Key; name: string; pricing: string; stayIf: string; pitch?: string }> = {
  'snyk-alternative': {
    key: 'snyk',
    name: 'Snyk',
    pricing: 'https://snyk.io/plans/',
    stayIf: 'you want one developer security platform from a large vendor and the per-developer price fits your budget',
    pitch: 'Snyk protects your code. Zelsis protects it too, and checks that your app is ready for the people who use it: payments that charge once, pages that load fast, screens that work on a phone, store reviews that pass, and nothing that looks unfinished.',
  },
  'semgrep-alternative': {
    key: 'semgrep',
    name: 'Semgrep',
    pricing: 'https://semgrep.dev/pricing',
    stayIf: 'you want to write and maintain your own custom rules, and someone on the team has time to tune them',
    pitch: 'Semgrep finds the patterns you write rules for. Zelsis comes with the rules, and also checks that your app is ready for the people who use it: payments that charge once, pages that load fast, screens that work on a phone, store reviews that pass, and nothing that looks unfinished.',
  },
  'aikido-alternative': {
    key: 'aikido',
    name: 'Aikido',
    pricing: 'https://www.aikido.dev/pricing',
    stayIf: 'you want one platform that also covers your cloud accounts and runtime, and the starting price fits',
    pitch: 'Aikido brings code, cloud and runtime security into one place. Zelsis checks your code for security too, and also for what your users will hit: payments that charge twice, slow pages, screens that break on a phone, store review rejections, and pages that look unfinished.',
  },
  'github-advanced-security-alternative': {
    key: 'github',
    name: 'GitHub Advanced Security',
    pricing: 'https://github.com/security/plans',
    stayIf: 'your code already lives on GitHub, you are fine paying per active committer, and vulnerability scanning with CodeQL is the coverage you need',
    pitch: 'GitHub security looks for vulnerabilities, vulnerable dependencies and leaked secrets. Zelsis checks for those too, and also for what your users will hit: payments that charge twice, slow pages, screens that break on a phone, store review rejections, and pages that look unfinished. One flat price instead of a charge per committer.',
  },
};

export const dynamicParams = false;

export function generateStaticParams() {
  return Object.keys(TOOLS).map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const t = TOOLS[slug];
  if (!t) return {};
  return {
    title: `${t.name} Alternative: A Release Check on Every Pull Request - Zelsis Guides`,
    description: `Looking for a ${t.name} alternative? Zelsis checks every pull request for logic bugs, performance, deploy safety, privacy, dependencies and security, at one flat price per account. When to choose which.`,
    alternates: { canonical: `/guides/${slug}` },
  };
}

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default async function AlternativePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const t = TOOLS[slug];
  if (!t) notFound();
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">{t.name} alternative for teams that ship every week</h1>
      <p className="text-zinc-400">
        {t.name} is a good tool, and many teams should keep it. This page is for the ones who are looking for something
        else: a check that runs on every pull request, catches the logic mistakes behind real incidents, and costs the same
        whether you have three developers or ten.
      </p>
      {t.pitch && <p className="mt-3 text-zinc-200 font-medium">{t.pitch}</p>}

      <section className="space-y-3">
        <h2 className={H2}>Price and focus side by side</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs sm:text-sm border-collapse">
            <thead>
              <tr className="text-zinc-400 border-b border-white/10">
                <th className="py-2 pr-3"> </th>
                <th className="py-2 pr-3">Zelsis</th>
                <th className="py-2">{t.name}</th>
              </tr>
            </thead>
            <tbody>
              {COMPETITOR_ROWS.map((row) => (
                <tr key={row.label} className="border-b border-white/5 align-top">
                  <td className="py-2 pr-3 text-zinc-400">{row.label}</td>
                  <td className="py-2 pr-3 text-zinc-300">{row.zelsis}</td>
                  <td className="py-2 text-zinc-300">{row[t.key]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-zinc-500">
          {t.name} figures from{' '}
          <a href={t.pricing} className={LINK} target="_blank" rel="noopener noreferrer">
            their pricing page
          </a>
          , {COMPARED_ON}. Prices change; check theirs before you decide.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>What Zelsis checks that most security tools do not</h2>
        <p className="text-zinc-300">
          Security scanners look for known vulnerability patterns. Zelsis looks for those too, and also for the mistakes
          that cost money or customers without being a CVE: a checkout that trusts the price sent by the browser, a pay
          button that charges twice, a page that runs one database query per product, a migration that locks the orders
          table during a deploy, a cookie banner with no way to refuse. Each finding has the file, the line and a fix you
          can paste into your AI assistant.
        </p>
        <p className="text-zinc-300">
          Only rules that have caught a documented flaw, or were reviewed as true positives, can fail the check. Everything
          else shows up as a warning, so the gate stays quiet enough that nobody turns it off. The{' '}
          <Link href="/#benchmark" className={LINK}>
            benchmark
          </Link>{' '}
          is published with what we miss.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>When to stay with {t.name}</h2>
        <p className="text-zinc-300">Stay with {t.name} if {t.stayIf}. Zelsis does not try to replace a full security platform.</p>
        <p className="text-zinc-300">
          Choose Zelsis if you mainly want each pull request checked before it merges, across logic, performance, deploy
          safety, privacy and security, at one flat price per account. Plenty of teams run both: the other tool for its
          platform, Zelsis as the release check.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>How it compares with an AI reviewer</h2>
        <p className="text-zinc-300">
          We ran Zelsis and CodeRabbit on the same five pull requests with planted flaws and published every comment.{' '}
          <Link href="/guides/zelsis-vs-coderabbit" className={LINK}>
            Read the comparison
          </Link>
          .
        </p>
      </section>

      <ScanCta />
    </article>
  );
}
