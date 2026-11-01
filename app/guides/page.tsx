import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { connection } from 'next/server';
import { GuideFilter } from './GuideFilter';

export const metadata: Metadata = {
  alternates: { canonical: '/guides' },
  title: 'Guides: Bugs to Fix Before You Ship - Zelsis',
  description:
    'Practical guides for teams shipping web, mobile and SaaS apps: testing Supabase RLS, fixing the user-delete foreign key error, and sending Stripe amounts in cents.',
};

export default async function GuidesIndexPage() {
  // Render per request so ?type= is in the first HTML; filtered links show the right list without a Suspense swap.
  await connection();
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Guides</h1>
      <p className="text-zinc-400">
        Short, practical fixes for bugs that software teams ship again and again. Each guide
        shows the broken pattern, the fix, and how to check it yourself.
      </p>
      <GuideFilter />
      <p className="text-zinc-400">
        More real examples: <Link href="/docs/real-world-bugs" className="text-emerald-400 hover:text-emerald-300 underline">bugs we found in popular open-source repos</Link>.
      </p>
    </div>
  );
}
