import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { SiteCheckForm } from '@/components/site-check/SiteCheckForm';

export const metadata: Metadata = {
  title: 'Free site check: does your app look finished?',
  description:
    'Enter a URL and see what visitors notice first: a template page title, lorem ipsum, no link preview image, no icon, a page that is not built for phones. Free, no account.',
  alternates: { canonical: '/site-check' },
};

export default function SiteCheckPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans px-4 sm:px-6 py-10 sm:py-14">
      <div className="max-w-3xl mx-auto">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
        <p className="mt-8 text-xs font-mono uppercase tracking-widest text-emerald-400">Free site check · no account</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-extrabold tracking-tight text-white">Does your app look finished?</h1>
        <p className="mt-4 text-zinc-400 leading-relaxed">
          Visitors judge a new app in seconds. A starter page title, filler text or a blank link preview tells them it was rushed.
          Enter your address and Zelsis checks the page the way a first visitor sees it.
        </p>
        <div className="mt-8">
          <SiteCheckForm />
        </div>
      </div>
    </div>
  );
}
