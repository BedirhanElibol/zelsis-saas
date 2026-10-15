import React from 'react';
import { ENTERPRISE_SEAT_LIMIT, priceLabel } from '@/data/pricing-plans';

/** Competitor prices: verify on each vendor's pricing page and update COMPARED_ON whenever they change. */
const COMPARED_ON = 'October 2026';

const ROWS: { label: string; zelsis: string; aikido: string; snyk: string; semgrep: string }[] = [
  {
    label: 'Paid plan',
    zelsis: `${priceLabel('Pro')} flat per account; team of ${ENTERPRISE_SEAT_LIMIT} for ${priceLabel('Enterprise')}`,
    aikido: '$300/mo flat for 10 users and 100 repos (Basic)',
    snyk: 'Team from $25/mo, up to 10 developers',
    semgrep: '$30/mo per contributor (Code or Supply Chain)',
  },
  {
    label: 'Free plan',
    zelsis: 'Unlimited scans, 3 saved projects, 5 fix prompts / month',
    aikido: '2 users, 10 repos',
    snyk: '5 projects, 100 Code tests/mo',
    semgrep: 'Up to 10 contributors and 10 private repos',
  },
  {
    label: 'Focus',
    zelsis: 'Logic bugs behind real incidents (auth, payments, caching, database rules), plus secrets, dependencies and CI/CD config, gated on every pull request',
    aikido: 'All-in-one platform (code, cloud, runtime)',
    snyk: 'Developer security platform',
    semgrep: 'Customizable SAST and supply chain',
  },
];

/** Honest price comparison against the tools buyers already know. */
export function CompetitorComparison() {
  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5" id="compare">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Priced per account, not per developer.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            The established tools are excellent general-purpose platforms. Zelsis is built for small teams shipping web, mobile and SaaS apps and
            APIs: deep on the logic bugs that cause real incidents, at a flat price that does not grow with every hire.
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
              {ROWS.map((row) => (
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
