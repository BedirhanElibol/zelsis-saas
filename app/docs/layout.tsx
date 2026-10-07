import React from 'react';
import { DocsSidebar } from '@/components/docs/DocsSidebar';

export const metadata = {
  title: 'Documentation | Zelsis Pre-Flight SAST',
  description: 'Technical documentation for Zelsis static analysis security testing, CI release gate, configuration, and data protection.',
};

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-zinc-300">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row px-4 sm:px-6 lg:px-8 py-8 gap-8">
        <DocsSidebar />

        {/* Content Area */}
        <main className="flex-1 min-w-0 bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-10 text-sm leading-relaxed prose prose-invert prose-emerald max-w-none shadow-xl shadow-black/40">
          {children}
        </main>
      </div>
    </div>
  );
}
