import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { BenchmarkSection } from '@/components/saas/BenchmarkSection';

export const metadata: Metadata = {
  title: 'Zelsis benchmark: what it catches and what it misses',
  description: 'Every pinned open-source project Zelsis scans, the documented flaws it finds, the ones it misses, and how noisy it is on maintained apps.',
  alternates: { canonical: '/benchmark' },
};

export default function BenchmarkPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-10 pt-10">
        <Link href="/" className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition-colors min-h-[24px]">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Home
        </Link>
      </div>
      <BenchmarkSection />
    </div>
  );
}
