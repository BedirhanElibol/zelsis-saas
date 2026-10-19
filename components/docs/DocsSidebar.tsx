'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { BookOpen, Rocket, GitBranch, Settings, List, ShieldAlert, XCircle, Bug, Lock, ArrowLeft, Terminal, type LucideIcon } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

const NAV_ITEMS: NavItem[] = [
  { href: '/docs/getting-started', label: 'Getting Started', icon: Rocket },
  { href: '/docs/private-repos', label: 'Scan a Private Repo', icon: Lock },
  { href: '/docs/ci-gate', label: 'CI Release Gate', icon: GitBranch },
  { href: '/docs/cli', label: 'CLI and AI Agents (MCP)', icon: Terminal },
  { href: '/docs/configuration', label: 'Configuration', icon: Settings },
  { href: '/docs/rules', label: 'Rule Catalog', icon: List },
  { href: '/docs/data-handling', label: 'Data Handling', icon: ShieldAlert },
  { href: '/docs/real-world-bugs', label: 'Real Bugs We Found', icon: Bug },
  { href: '/docs/boundaries', label: "What We Don't Check", icon: XCircle },
];

export function DocsSidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-full md:w-64 shrink-0 flex flex-col gap-4">
      {/* Brand header */}
      <div className="flex items-center justify-between pb-4 border-b border-white/10">
        <Link href="/" className="flex items-center group">
          <ZelsisLogo size="sm" />
        </Link>
        <Link
          href="/dashboard"
          className="flex items-center gap-1.5 text-xs font-mono text-zinc-400 hover:text-white transition-colors px-2 py-1 rounded bg-white/5 hover:bg-white/10"
        >
          <ArrowLeft size={12} />
          <span>Dashboard</span>
        </Link>
      </div>

      <div className="flex items-center gap-2 px-3 py-1 text-white font-semibold text-xs tracking-wider uppercase font-mono text-zinc-400">
        <BookOpen size={14} className="text-emerald-400" />
        <span>Documentation</span>
      </div>

      <nav className="flex flex-col gap-1" aria-label="Documentation Navigation">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150 ${
                isActive
                  ? 'bg-emerald-500/10 text-emerald-400 font-medium border-l-2 border-emerald-400 rounded-l-none pl-[10px]'
                  : 'text-zinc-400 hover:text-zinc-100 hover:bg-white/5'
              }`}
            >
              <Icon size={16} className={isActive ? 'text-emerald-400' : 'text-zinc-500'} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
