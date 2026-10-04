import React from 'react';
import Link from 'next/link';
import { BookOpen, Rocket, GitBranch, Settings, List, ShieldAlert, XCircle } from 'lucide-react';

export const metadata = {
  title: 'Zelsis Documentation',
  description: 'Official documentation for Zelsis SAST and UI auditing platform',
};

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  const navItems = [
    { href: '/docs/getting-started', label: 'Getting Started', icon: <Rocket size={16} /> },
    { href: '/docs/ci-gate', label: 'CI Release Gate', icon: <GitBranch size={16} /> },
    { href: '/docs/configuration', label: 'Configuration', icon: <Settings size={16} /> },
    { href: '/docs/rules', label: 'Rule Catalog', icon: <List size={16} /> },
    { href: '/docs/data-handling', label: 'Data Handling', icon: <ShieldAlert size={16} /> },
    { href: '/docs/boundaries', label: 'What We Don\'t Check', icon: <XCircle size={16} /> },
  ];

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-zinc-300">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row px-4 sm:px-6 lg:px-8 py-8 gap-8">
        {/* Sidebar */}
        <aside className="w-full md:w-64 shrink-0 flex flex-col gap-1">
          <div className="flex items-center gap-2 px-3 py-4 text-white font-bold mb-2">
            <BookOpen size={20} className="text-emerald-400" />
            <span>Documentation</span>
          </div>
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm hover:bg-white/5 hover:text-white transition-colors"
            >
              {item.icon}
              {item.label}
            </Link>
          ))}
        </aside>

        {/* Content */}
        <main className="flex-1 min-w-0 bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-10 text-sm leading-relaxed prose prose-invert prose-emerald max-w-none">
          {children}
        </main>
      </div>
    </div>
  );
}
