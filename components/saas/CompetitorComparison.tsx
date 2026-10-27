import React from 'react';
import { ENTERPRISE_SEAT_LIMIT, priceLabel } from '@/data/pricing-plans';

/** Competitor prices: verify on each vendor's pricing page and update COMPARED_ON whenever they change. */
export const COMPARED_ON = 'October 2026';

export const COMPETITOR_ROWS: { label: string; zelsis: string; aikido: string; snyk: string; semgrep: string; github: string }[] = [
  {
    label: 'Paid plan',
    zelsis: `${priceLabel('Pro')} flat per account; team of ${ENTERPRISE_SEAT_LIMIT} for ${priceLabel('Enterprise')}`,
    aikido: '$300/mo flat for 10 users and 100 repos (Basic)',
    snyk: 'Team from $25/mo, up to 10 developers',
    semgrep: '$30/mo per contributor (Code or Supply Chain)',
    github: 'Code Security 30 USD/mo plus Secret Protection 19 USD/mo, each per active committer',
  },
  {
    label: 'Free plan',
    zelsis: 'Unlimited scans, 3 saved projects, 5 fix prompts / month',
    aikido: '2 users, 10 repos',
    snyk: '5 projects, 100 Code tests/mo',
    semgrep: 'Up to 10 contributors and 10 private repos',
    github: 'CodeQL, Dependabot and secret scanning on public repositories',
  },
  {
    label: 'Focus',
    zelsis: 'Logic bugs behind real incidents (auth, payments, caching, database rules), plus secrets, dependencies and CI/CD config, gated on every pull request',
    aikido: 'All-in-one platform (code, cloud, runtime)',
    snyk: 'Developer security platform',
    semgrep: 'Customizable SAST and supply chain',
    github: 'Code scanning (CodeQL), dependencies and leaked secrets, built into GitHub',
  },
];

/** Honest price comparison against the tools buyers already know. */
export function CompetitorComparison() {
  return (
    <section className="py-12 sm:py-14 bg-[#0A0A0A] border-t border-white/5" id="compare">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Priced per account, not per developer.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            Snyk protects your code. Zelsis protects it too, and checks that your app is ready for the people who use it: payments that charge once, pages that load fast, screens that work on a phone, store reviews that pass, and nothing that looks unfinished.
            One flat price that does not grow with every hire.
          </p>
        </div>

        <div className="overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
          <table className="w-full min-w-[720px] text-left border-collapse text-sm">
            <caption className="sr-only">Zelsis compared with Aikido, Snyk and Semgrep</caption>
            <thead>
              <tr className="border-b border-white/10">
                <th scope="col" className="py-4 px-5 font-medium text-white bg-[#141414] rounded-tl-xl">&nbsp;</th>
                <th scope="col" className="py-4 px-5 font-medium text-emerald-400 bg-emerald-500/5 border-x border-emerald-500/20">Zelsis</th>
                <th scope="col" className="py-4 px-5 font-medium text-white bg-[#141414]">Aikido</th>
                <th scope="col" className="py-4 px-5 font-medium text-white bg-[#141414]">Snyk</th>
                <th scope="col" className="py-4 px-5 font-medium text-white bg-[#141414] rounded-tr-xl">Semgrep</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {COMPETITOR_ROWS.map((row) => (
                <tr key={row.label}>
                  <th scope="row" className="py-4 px-5 text-zinc-300 font-medium">{row.label}</th>
                  <td className="py-4 px-5 text-white bg-emerald-500/[0.03] border-x border-emerald-500/10">{row.zelsis}</td>
                  <td className="py-4 px-5 text-zinc-400">{row.aikido}</td>
                  <td className="py-4 px-5 text-zinc-400">{row.snyk}</td>
                  <td className="py-4 px-5 text-zinc-400">{row.semgrep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="mt-6 text-xs text-zinc-500">
          Competitor prices from their public pricing pages, {COMPARED_ON}; they may have changed since.{' '}
          <a href="https://www.aikido.dev/pricing" target="_blank" rel="noopener noreferrer" className="underline hover:text-zinc-300">Aikido</a>{' · '}
          <a href="https://snyk.io/plans/" target="_blank" rel="noopener noreferrer" className="underline hover:text-zinc-300">Snyk</a>{' · '}
          <a href="https://semgrep.dev/pricing" target="_blank" rel="noopener noreferrer" className="underline hover:text-zinc-300">Semgrep</a>
        </p>
      </div>
    </section>
  );
}
