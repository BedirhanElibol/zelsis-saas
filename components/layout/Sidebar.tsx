'use client';

import React, { useEffect } from 'react';
import Image from 'next/image';
import { UserAvatar } from '@/components/ui/UserAvatar';
import {
  LayoutDashboard,
  ShieldCheck,
  Palette,
  Layers,
  Activity,
  FolderGit2,
  CheckSquare,
  CreditCard
} from 'lucide-react';
import {
  Settings,
  FileText,
  LogIn,
  X,
  ShieldAlert,
  Scale,
  Database,
  Terminal
} from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import { getSubscriptionValidity } from '@/lib/subscription-utils';
import { UsageGauge } from './UsageGauge';
import { PlanUsageQuota } from '@/data/schema';

interface SidebarProps {
  activeNav: string;
  onNavigate: (nav: string) => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode: 'signin') => void;
  onNavigateSettings?: () => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
  quota?: PlanUsageQuota;
  projectsCount?: number;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeNav,
  onNavigate,
  user,
  onOpenAuth,
  onNavigateSettings,
  isMobileOpen = false,
  onCloseMobile,
  quota,
  projectsCount = 0,
  onOpenCheckout
}) => {
  useEffect(() => {
    if (!isMobileOpen || !onCloseMobile) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseMobile();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobileOpen, onCloseMobile]);

  const mainNav = [
    { id: 'dashboard', label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'projects', label: 'Connected Projects', icon: FolderGit2 },
    { id: 'scans', label: 'Scan History', icon: FileText },
  ];

  const pillarNav = [
    { id: 'security', label: 'Security Pre-Flight', icon: ShieldCheck },
    { id: 'compliance', label: 'Legal & Privacy Gate', icon: Scale },
    { id: 'infra', label: 'Infra & Database Gate', icon: Database },
    { id: 'vibepolish', label: 'Design & UX Polish', icon: Palette },
    { id: 'aicliche', label: 'AI Anti-Pattern Audit', icon: Palette },
    { id: 'aimaster', label: 'Master Quality Matrix', icon: Layers },
    { id: 'vibecare', label: 'VibeCare Health', icon: Activity },
  ];

  const managementNav = [
    { id: 'cicd', label: 'CI/CD & CLI Automation', icon: Terminal },
    { id: 'remediation', label: 'Remediation Queue', icon: CheckSquare },
    { id: 'checkout', label: 'Billing & Tiers', icon: CreditCard },
    { id: 'portal', label: 'Customer Portal', icon: FileText },
    { id: 'settings', label: 'Security Policies', icon: Settings },
  ];

  const handleNavClick = (id: string) => {
    if (id === 'portal') {
      if (user?.email) {
        window.open(`/api/v1/customer-portal?email=${encodeURIComponent(user.email)}`, '_blank');
      } else if (onOpenAuth) {
        onOpenAuth('signin');
      }
      return;
    }
    onNavigate(id);
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  const renderNavList = () => (
    <div className="flex flex-col gap-6">
      {/* Navigation Group 1: Core */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          CORE MODULES
        </span>
        {mainNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
          return (
            <button
              key={item.id}
              onClick={() => handleNavClick(item.id)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full text-left ${
                isActive
                  ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                  : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
              }`}
            >
              <Icon size={16} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      <div className="h-[1px] bg-white/[0.08] my-1" />

      {/* Navigation Group 2: Audit Gates */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          PRODUCT PILLARS
        </span>
        {pillarNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
          return (
            <button
              key={item.id}
              onClick={() => handleNavClick(item.id)}
              className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full ${
                isActive
                  ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                  : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon size={16} />
                <span>{item.label}</span>
              </div>
            </button>
          );
        })}
      </div>

      <div className="h-[1px] bg-white/[0.08] my-1" />

      {/* Navigation Group 3: Management */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          MANAGEMENT
        </span>
        {managementNav.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
          return (
            <button
              key={item.id}
              onClick={() => handleNavClick(item.id)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full text-left ${
                isActive
                  ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                  : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
              }`}
            >
              <Icon size={16} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );

  const renderFooter = () => {
    const validity = getSubscriptionValidity(user);
    const openSettings = () => {
      if (onCloseMobile) onCloseMobile();
      if (onNavigateSettings) onNavigateSettings();
      else onNavigate('settings');
    };

    return (
      <div className="pt-4 border-t border-white/10 mt-6">
        {user && user.isLoggedIn ? (
          <div className="p-2.5 rounded-xl bg-[#141414] border border-white/10 hover:border-white/20 transition-all flex items-center justify-between gap-2 shadow-sm">
            <div
              role="button"
              tabIndex={0}
              aria-label="Account settings"
              onClick={openSettings}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  openSettings();
                }
              }}
              className="flex items-center gap-2.5 min-w-0 flex-1 cursor-pointer select-none group rounded-lg focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
            >
              <UserAvatar
                src={user.avatarUrl}
                name={user.name}
                size={32}
                className="w-8 h-8"
              />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-bold text-white truncate leading-tight group-hover:text-zinc-200 transition-colors">
                  {user.name || 'User'}
                </div>
                <div className="mt-0.5 flex items-center gap-1.5 flex-wrap">
                  <span className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                    user.tier === 'Free'
                      ? 'bg-white/10 border border-white/20 text-zinc-300'
                      : user.tier === 'Pro'
                      ? 'bg-white/10 border border-white/20 text-white'
                      : 'bg-white/15 border border-white/25 text-white'
                  }`}>
                    {user.tier === 'Free' ? 'Free Plan' : `${user.tier} Plan`}
                  </span>
                  {user.tier !== 'Free' && (
                    <span
                      className={`px-1.5 py-0.5 rounded text-[11px] font-mono font-bold ${validity.badgeColors.bg} ${validity.badgeColors.text} ${validity.badgeColors.border} border`}
                      title={validity.countdownLabel}
                    >
                      {validity.compactLabel}
                    </span>
                  )}
                </div>
              </div>
            </div>

          <button
            onClick={() => {
              if (onCloseMobile) onCloseMobile();
              if (onNavigateSettings) onNavigateSettings();
              else onNavigate('settings');
            }}
            className="p-1.5 rounded-lg text-[#A1A1AA] hover:text-white hover:bg-white/10 transition-colors shrink-0"
            title="Profile & Settings"
            aria-label="Profile & Settings"
          >
            <Settings size={15} />
          </button>
        </div>
      ) : (
        <button
          onClick={() => {
            if (onCloseMobile) onCloseMobile();
            if (onOpenAuth) onOpenAuth('signin');
          }}
          className="w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-xs font-mono font-bold text-white transition-all shadow-sm group"
        >
          <LogIn size={14} className="text-[#A1A1AA] group-hover:text-white transition-colors" />
          <span>Sign In / Register</span>
        </button>
      )}
    </div>
    );
  };

  return (
    <>
      {/* Desktop Persistent Sidebar */}
      <aside className="hidden md:flex w-64 bg-[#0A0A0A] border-r border-white/10 p-4 flex-col justify-between shrink-0 sticky top-16 h-[calc(100vh-4rem)] overflow-y-auto">
        <div className="flex flex-col gap-4">
          {quota && (
            <div className="shrink-0 mb-1">
              <UsageGauge
                tier={user?.tier || 'Free'}
                quota={quota}
                projectsCount={projectsCount}
                onOpenCheckout={onOpenCheckout}
              />
            </div>
          )}
          {renderNavList()}
        </div>
        <div className="pt-4 border-t border-white/10 mt-6 shrink-0">
          {renderFooter()}
        </div>
      </aside>

      {/* Mobile Drawer Overlay */}
      {isMobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Dark Backdrop */}
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={onCloseMobile}
            aria-hidden="true"
          />

          {/* Drawer Menu */}
          <aside className="relative w-72 max-w-[85vw] bg-[#0E0E12] border-r border-white/10 p-5 flex flex-col justify-between shadow-2xl z-10 overflow-y-auto h-full animate-in slide-in-from-left duration-200">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <ZelsisLogo size="sm" />
                <button
                  onClick={onCloseMobile}
                  className="p-1.5 rounded-lg text-[#A1A1AA] hover:text-white hover:bg-white/10 transition-colors"
                  aria-label="Close navigation menu"
                >
                  <X size={18} />
                </button>
              </div>
              {quota && (
                <div className="shrink-0 mb-1">
                  <UsageGauge
                    tier={user?.tier || 'Free'}
                    quota={quota}
                    projectsCount={projectsCount}
                    onOpenCheckout={onOpenCheckout}
                  />
                </div>
              )}
              {renderNavList()}
            </div>
            <div className="pt-4 border-t border-white/10 mt-6 shrink-0">
              {renderFooter()}
            </div>
          </aside>
        </div>
      )}
    </>
  );
};
