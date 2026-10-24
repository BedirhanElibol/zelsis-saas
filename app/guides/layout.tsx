import React from 'react';
import Link from 'next/link';
import { ArrowLeft, BookOpen, Compass } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

export default function GuidesLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-zinc-300">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <header className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-white/10">
          <Link href="/" className="flex items-center" aria-label="Zelsis home">
            <ZelsisLogo size="sm" />
          </Link>
          <nav className="flex flex-wrap items-center gap-2 text-xs font-mono" aria-label="Guides navigation">
            <Link href="/guides" className="flex items-center gap-1.5 text-zinc-400 hover:text-white px-2 py-1 rounded bg-white/5 hover:bg-white/10">
              <Compass size={12} aria-hidden="true" />
              <span>Guides</span>
            </Link>
            <Link href="/docs" className="flex items-center gap-1.5 text-zinc-400 hover:text-white px-2 py-1 rounded bg-white/5 hover:bg-white/10">
              <BookOpen size={12} aria-hidden="true" />
              <span>Docs</span>
            </Link>
            <Link href="/dashboard" className="flex items-center gap-1.5 text-zinc-400 hover:text-white px-2 py-1 rounded bg-white/5 hover:bg-white/10">
              <ArrowLeft size={12} aria-hidden="true" />
              <span>Dashboard</span>
            </Link>
          </nav>
        </header>

        <main className="min-w-0 bg-[#141414] border border-white/10 rounded-xl p-5 sm:p-10 text-sm leading-relaxed break-words shadow-xl shadow-black/40">
          {children}
        </main>
      </div>
    </div>
  );
}
