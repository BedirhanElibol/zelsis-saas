import React from 'react';
import Link from 'next/link';
import {
  BellOff,
  GitPullRequest,
  ShieldCheck,
  FileCode,
  Rocket,
  KeyRound,
  Users,
  CreditCard,
  Repeat,
  Gauge,
  Database,
  Cookie,
  Accessibility,
  Package,
} from 'lucide-react';
import { CODE_RETENTION_STATEMENT } from '@/lib/data-retention';

// Claims here must stay true to the product: no counts, no timings, no guarantees.
const POINTS = [
  {
    icon: BellOff,
    title: 'A gate that stays quiet',
    body: 'Only proven critical findings fail the build. The rest show up as notes you can read when you have time.',
  },
  {
    icon: GitPullRequest,
    title: 'Runs next to your AI reviewer',
    body: 'Keep CodeRabbit or Copilot for review comments. Zelsis adds a pass or fail check that gives the same result every time it runs.',
    link: { href: '/guides/zelsis-vs-coderabbit', label: 'See both on the same five pull requests' },
  },
  {
    icon: ShieldCheck,
    title: 'Your code is not kept',
    body: CODE_RETENTION_STATEMENT,
  },
  {
    icon: FileCode,
    title: 'No setup file to start',
    body: 'Paste a repository URL and get a report. Add a .zelsisrc.json later if you want to tune thresholds or ignore paths.',
  },
  {
    icon: Rocket,
    title: 'Fix it and ship the same day',
    body: 'Each finding gives the file, the line and a fix prompt, so you can fix it and merge without waiting for a separate security review.',
  },
];

// One category per area Zelsis checks, so the list matches what the product does (not only security)
const CATEGORIES = [
  { icon: CreditCard, title: 'Prices set by the browser', body: 'Checkout amounts the client can change before payment.' },
  { icon: Repeat, title: 'Customers charged twice', body: 'Pay buttons that stay clickable and webhooks applied twice.' },
  { icon: Gauge, title: 'Pages that crawl', body: 'One database query per item in a list, unbounded sorts and deep pagination.' },
  { icon: Database, title: 'Deploys that freeze checkout', body: 'Migrations that lock a busy table while they run.' },
  { icon: Cookie, title: 'No way to say no', body: 'Cookie banners without a reject option and personal data written to logs.' },
  { icon: Accessibility, title: 'Screens some people cannot use', body: 'Dialogs that trap the keyboard, missing labels, pages wider than the phone.' },
  { icon: Package, title: 'Packages with known holes', body: 'Dependency versions with a published advisory, and the version that fixes it.' },
  { icon: Users, title: 'One user reading another’s data', body: 'Routes and tables that skip the owner check.' },
  { icon: KeyRound, title: 'Leaked keys', body: 'Secret keys in client code, logs or committed config.' },
];

export const WhyZelsis: React.FC = () => (
  <section className="py-20 sm:py-28 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
    <div className="max-w-6xl mx-auto">
      <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight [text-wrap:balance]">
        Made for whoever ships the code
      </h2>
      <p className="text-base sm:text-lg text-[#A1A1AA] mt-4 max-w-3xl leading-relaxed">
        You might build with an AI assistant or write every line yourself. Either way the pull request gets the same check before it merges.
      </p>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 mt-10">
        {POINTS.map(({ icon: Icon, title, body, link }) => (
          <div key={title} className="rounded-xl border border-white/10 bg-[#111113] p-5">
            <Icon size={18} className="text-emerald-400" aria-hidden="true" />
            <h3 className="text-base font-bold text-white mt-3">{title}</h3>
            <p className="text-sm text-[#A1A1AA] mt-1.5 leading-relaxed">{body}</p>
            {link ? (
              <Link href={link.href} className="inline-block text-sm text-emerald-400 hover:text-emerald-300 underline mt-2">
                {link.label}
              </Link>
            ) : null}
          </div>
        ))}
      </div>

      <h3 className="text-xl sm:text-2xl font-extrabold text-white mt-16">What it catches before release</h3>
      <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2 lg:grid-cols-3 mt-6">
        {CATEGORIES.map(({ icon: Icon, title, body }) => (
          <div key={title} className="flex gap-3">
            <Icon size={18} className="text-red-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <p className="text-sm font-bold text-white">{title}</p>
              <p className="text-sm text-[#A1A1AA] mt-0.5 leading-relaxed">{body}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  </section>
);
