import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { SecurityAdvisor } from '@/components/saas/SecurityAdvisor';

export const metadata: Metadata = {
  title: 'Zelsis with Supabase Security Advisor',
  description: 'What Supabase Security Advisor checks in your database, and what Zelsis adds by reading the app code that talks to it.',
  alternates: { canonical: '/supabase' },
};

export default function SupabasePage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-10 pt-10">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
      </div>
      <SecurityAdvisor />
    </div>
  );
}
