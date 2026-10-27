import React from 'react';
import { Repeat, KeyRound, FileWarning, Lock } from 'lucide-react';

// Each item is a bug class Zelsis has a rule for (see CatchTabs); no counts or invented incidents.
const PROBLEMS = [
  { icon: Repeat, title: 'A customer is charged twice', body: 'The first support email asks for a refund, and the review mentions it.' },
  { icon: KeyRound, title: 'A secret key ships to the browser', body: 'Anyone who opens the developer tools can copy it.' },
  { icon: Lock, title: 'A deploy locks the orders table', body: 'Checkout hangs for every visitor until the migration finishes.' },
  { icon: FileWarning, title: 'The page still says lorem ipsum', body: 'Visitors decide the app is unfinished, and some post a screenshot.' },
];

/** Sits under the hero: what users notice when a rushed release goes out. */
export function ProblemBand() {
  return (
    <section aria-labelledby="problem-band-title" className="py-12 sm:py-14 px-4 sm:px-6 lg:px-10 bg-[#0C0C0D] border-b border-white/10">
      <div className="max-w-7xl mx-auto">
        <h2 id="problem-band-title" className="text-xl sm:text-2xl font-bold text-white tracking-tight max-w-3xl">
          Apps ship in weeks now. Users find the rough edges in minutes.
        </h2>
        <ul className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {PROBLEMS.map(({ icon: Icon, title, body }) => (
            <li key={title} className="rounded-xl border border-white/10 bg-[#121214] p-5">
              <Icon className="w-5 h-5 text-red-400" aria-hidden="true" />
              <h3 className="mt-3 font-semibold text-white">{title}</h3>
              <p className="mt-1.5 text-sm text-zinc-400">{body}</p>
            </li>
          ))}
        </ul>
        <p className="mt-6 text-sm text-zinc-300">
          Zelsis checks every pull request for these before it merges.{' '}
          <a href="#specifics" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-4">See what it catches</a>
        </p>
      </div>
    </section>
  );
}
