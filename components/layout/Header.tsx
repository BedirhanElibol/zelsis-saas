'use client';

import React, { useState, useEffect, useRef } from 'react';
import Image from 'next/image';
import { Project, PlanUsageQuota, UserTier } from '@/data/schema';
import { Play, ArrowLeft, ArrowRight, FolderGit2, LogOut, User, ChevronDown, Settings, Menu, Calendar, ExternalLink, Terminal, Shield, Building2 } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { normalizeRepoUrl, extractRepoDisplayName } from '@/lib/github-api';
import { ConnectTargetModal } from './ConnectTargetModal';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import { UserAvatar } from '@/components/ui/UserAvatar';
import { getSubscriptionValidity } from '@/lib/subscription-utils';
import { openCustomerPortal } from '@/lib/billing-portal';
import { TierDetailsModal } from '../pricing/TierDetailsModal';
import { UNDETECTED_FRAMEWORK } from '@/lib/scanner/stack-detect';

interface HeaderProps {
  projects: Project[];
  selectedProject: Project;
  onSelectProject: (p: Project) => void;
  onTriggerScan: (projectOverride?: Project) => void;
  onNavigateLanding?: () => void;
  onAddNewProject?: (p: Project) => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onSignOut?: () => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  onNavigateSettings?: () => void;
  onToggleMobileMenu?: () => void;
  quota?: PlanUsageQuota;
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  selectedProject,
  onSelectProject,
  onTriggerScan,
  onNavigateLanding,
  onAddNewProject,
  user,
  onOpenAuth,
  onSignOut,
  onOpenCheckout,
  onNavigateSettings,
  onToggleMobileMenu,
  quota
}) => {
  const [isGithubModalOpen, setIsGithubModalOpen] = useState<boolean>(false);
  const [isTierDetailsOpen, setIsTierDetailsOpen] = useState<boolean>(false);
  const [activeTargetUrl, setActiveTargetUrl] = useState<string>(selectedProject.repoUrl);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const validity = getSubscriptionValidity(user);

  useEffect(() => {
    setActiveTargetUrl(selectedProject.repoUrl);
  }, [selectedProject]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsUserMenuOpen(false);
      }
    };
    if (isUserMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isUserMenuOpen]);

  const handleAuditAction = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (isSubmitting) return;
    setIsSubmitting(true);
    setTimeout(() => setIsSubmitting(false), 1000);
    const rawTarget = activeTargetUrl || '';
    const cleanRepoUrl = normalizeRepoUrl(rawTarget) || rawTarget;
    const normTarget = (cleanRepoUrl || '').toLowerCase().replace(/\/+$/, '').trim();
    if (!normTarget) return;

    const selectedUrl = selectedProject?.repoUrl || '';
    const normSelected = (selectedUrl === 'local' ? 'local' : (normalizeRepoUrl(selectedUrl) || selectedUrl)).toLowerCase().replace(/\/+$/, '').trim();
    if (normTarget === normSelected && selectedProject?.repoUrl && selectedProject.repoUrl !== 'undefined') {
      onTriggerScan(selectedProject);
      return;
    }

    const existing = projects.find((p) => {
      const pUrl = p?.repoUrl || '';
      const pNorm = (pUrl === 'local' ? 'local' : (normalizeRepoUrl(pUrl) || pUrl)).toLowerCase().replace(/\/+$/, '').trim();
      return pNorm === normTarget && p?.repoUrl && p.repoUrl !== 'undefined';
    });
    let savedToken: string | undefined;
    if (typeof window !== 'undefined') {
      try {
        savedToken =
          sessionStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('github_token') ||
          undefined;
      } catch {
        // Sandboxed storage fallback
      }
    }

    if (existing) {
      if (!existing.githubToken && savedToken) {
        existing.githubToken = savedToken;
      }
      onSelectProject(existing);
      onTriggerScan(existing);
      return;
    }

    const displayName = extractRepoDisplayName(cleanRepoUrl);
    const newProject: Project = {
      id: `proj-${Date.now()}`,
      name: displayName,
      repoUrl: cleanRepoUrl,
      githubToken: savedToken,
      framework: UNDETECTED_FRAMEWORK,
      providers: [],
      lastScanAt: 'Ready to Run Audit',
      readinessScore: 100,
      gateStatus: 'PASSED',
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      uiClicheCount: 0,
      findings: []
    };
    if (onAddNewProject) {
      onAddNewProject(newProject);
    } else {
      onSelectProject(newProject);
    }
    onTriggerScan(newProject);
  };

  return (
    <>
      <header className="h-16 px-3 sm:px-6 bg-[#0E0E12] border-b border-white/10 flex items-center justify-between gap-2 sm:gap-4 sticky top-0 z-30">
        {/* Left: Mobile Menu Trigger + Brand / Home Link */}
        <div className="flex items-center gap-2 sm:gap-4 min-w-0">
          {onToggleMobileMenu && (
            <button
              onClick={onToggleMobileMenu}
              className="p-1.5 -ml-1 text-[#A1A1AA] hover:text-white md:hidden rounded-lg hover:bg-white/5 transition-colors shrink-0"
              aria-label="Open Navigation Menu"
              title="Open Menu"
            >
              <Menu size={20} />
            </button>
          )}

          <a href="/" className="flex items-center group shrink-0" aria-label="Zelsis Home">
            <ZelsisLogo size="sm" showWordmark={false} />
          </a>

          {onNavigateLanding && (
            <button
              onClick={onNavigateLanding}
              className="hidden sm:flex items-center gap-1.5 text-xs text-[#A1A1AA] hover:text-white transition-colors shrink-0 min-h-11"
              title="Return to Landing Page"
            >
              <ArrowLeft size={15} />
              <span className="hidden sm:inline font-mono">Home</span>
            </button>
          )}

          {/* Project & Organization Selectors */}
          <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
            {/* Active Workspace Badge (Clean & Transparent) */}
            <div
              className="hidden xl:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#141414] border border-white/10 text-[11px] font-mono text-zinc-300 shrink-0"
              title={user?.tier === 'Enterprise' ? 'Enterprise Organization Workspace' : 'Personal Workspace'}
            >
              <Building2 size={13} className="text-zinc-400 shrink-0" />
              <span className="font-bold text-white">
                {user?.tier === 'Enterprise' ? `${user.name?.split(' ')[0] || 'Enterprise'} Workspace` : 'Personal Workspace'}
              </span>
              {user?.tier === 'Enterprise' && (
                <span className="text-[11px] font-mono font-extrabold uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 ml-0.5">
                  ADMIN
                </span>
              )}
            </div>

            <select
              aria-label="Select Active Project"
              value={selectedProject.id}
              onChange={(e) => {
                const found = projects.find((p) => p.id === e.target.value);
                if (found) onSelectProject(found);
              }}
              className="bg-[#141414] border border-white/10 rounded-lg px-2 sm:px-2.5 py-1.5 text-[11px] sm:text-xs font-mono font-bold text-white outline-none focus-visible:ring-2 focus-visible:ring-white/20 cursor-pointer max-w-[150px] sm:max-w-[240px] min-h-11 sm:min-h-0 truncate"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.framework})
                </option>
              ))}
            </select>

            {selectedProject.id === 'proj-saas-starter' && (!user || !user.isLoggedIn) && (
              <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-white/10 border border-white/15 text-zinc-300 shrink-0">
                Demo Showcase
              </span>
            )}

            <button
              onClick={() => setIsGithubModalOpen(true)}
              aria-label="Connect Repository / Website"
              className="min-w-11 min-h-11 sm:min-w-[36px] sm:min-h-[36px] p-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white transition-colors shrink-0 flex items-center justify-center outline-none focus-visible:ring-2 focus-visible:ring-white/20"
              title="Connect Repository / Website"
            >
              <FolderGit2 size={14} />
            </button>
          </div>
        </div>

        {/* Center: Interactive Target Command Bar */}
        {/* On phones the folder button opens the same connect-and-scan modal, so the bar is hidden */}
        <form onSubmit={handleAuditAction} className="hidden md:flex items-center flex-1 max-w-sm sm:max-w-md lg:max-w-lg mx-2 sm:mx-4 min-w-0">
          <div className="relative w-full flex items-center">
            <Terminal size={14} className="absolute left-2.5 sm:left-3 text-[#A1A1AA] pointer-events-none shrink-0" />
            <input
              id="header-target-repo-input"
              name="targetRepo"
              type="text"
              aria-label="Target repository or deployment URL"
              value={activeTargetUrl}
              onChange={(e) => setActiveTargetUrl(e.target.value)}
              placeholder="github.com/owner/repo or web URL..."
              className="w-full bg-[#141414] border border-white/15 rounded-lg pl-7 sm:pl-8 pr-16 sm:pr-20 py-1.5 text-xs font-mono text-[#EDEDED] placeholder-zinc-500 outline-none focus-visible:ring-2 focus-visible:ring-white/20 focus:border-white/30 transition-all shadow-inner"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="absolute right-1 min-h-[32px] px-2.5 sm:px-3 py-1 bg-white text-black hover:bg-neutral-200 disabled:opacity-50 disabled:cursor-not-allowed rounded-md text-[10px] sm:text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1 transition-all cursor-pointer shadow-sm active:scale-95 shrink-0 outline-none focus-visible:ring-2 focus-visible:ring-white/20"
              title="Audit Target Repository"
            >
              <Play size={10} fill="#0A0A0A" />
              <span>Scan</span>
            </button>
          </div>
        </form>

        {/* Right: User Auth Info / Profile Dropdown */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">

          {/* Quick Plan Quota Badge */}
          {quota && (
            <button
              type="button"
              onClick={() => setIsTierDetailsOpen(true)}
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-mono font-bold transition-all cursor-pointer bg-white/5 hover:bg-white/10 text-white border-white/10 shadow-sm"
              title="View Plan Details & Quotas"
            >
              <Shield size={11} className="text-zinc-400" />
              {user?.tier === 'Pro' ? (
                <span className="text-zinc-200">PRO · UNLIMITED</span>
              ) : user?.tier === 'Enterprise' ? (
                <span className="text-white">ENTERPRISE</span>
              ) : (
                <span className={quota.scansUsed >= quota.scansLimit ? 'text-rose-400 font-extrabold' : 'text-zinc-300'}>
                  FREE · {Math.max(0, quota.scansLimit - quota.scansUsed)}/3 SCANS LEFT
                </span>
              )}
            </button>
          )}

          {/* User Auth Info / Profile Dropdown */}
          {user && user.isLoggedIn ? (
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen((prev) => !prev)}
                className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/5 text-xs font-mono transition-colors"
                aria-label="User Profile and Plan Options"
              >
                <UserAvatar
                  src={user.avatarUrl}
                  name={user.name}
                  size={28}
                  className="w-7 h-7"
                />
                <span className="hidden sm:inline font-bold text-white max-w-[110px] truncate">
                  {user.name || 'User'}
                </span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                  user.tier === 'Free'
                    ? 'bg-white/10 border border-white/15 text-zinc-300'
                    : user.tier === 'Pro'
                    ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
                    : 'bg-white/10 border border-white/20 text-zinc-100'
                }`}>
                  {user.tier === 'Free' ? 'Free Plan' : `${user.tier} Plan`}
                </span>
                <ChevronDown size={12} className="text-[#A1A1AA]" />
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-72 bg-[#141414] border border-white/10 rounded-xl p-2 shadow-2xl z-50 flex flex-col gap-1 text-xs font-mono">
                    <div className="px-3 py-2.5 border-b border-white/10 flex items-center gap-2.5">
                      <UserAvatar
                        src={user.avatarUrl}
                        name={user.name}
                        size={32}
                        className="w-8 h-8"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="font-bold text-white truncate">{user.name || 'User'}</div>
                        <div className="text-[10px] text-[#A1A1AA] truncate">{user.email}</div>
                      </div>
                    </div>

                    {/* Subscription Validity Card */}
                    {validity.tier === 'Free' ? (
                      <div className="px-3 py-2 bg-white/[0.03] rounded-lg my-1 border border-white/5 flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[11px] font-bold text-white">Free Plan</span>
                          </div>
                          <span className="text-[10px] font-mono font-medium text-zinc-300 bg-white/10 border border-white/15 px-1.5 py-0.5 rounded">
                            Active
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-[#A1A1AA] pt-1 border-t border-white/5">
                          <span>Standard audit tier</span>
                          {onOpenCheckout && (
                            <button
                              onClick={() => {
                                setIsUserMenuOpen(false);
                                onOpenCheckout();
                              }}
                              className="text-amber-400 hover:text-amber-300 font-bold flex items-center gap-1 transition-colors cursor-pointer"
                            >
                              <ArrowRight size={11} className="text-amber-400" />
                              <span>Upgrade</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 bg-white/[0.03] rounded-lg my-1 border border-white/5 flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[11px] font-bold text-white">{validity.tier} Plan</span>
                          </div>
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${validity.badgeColors.bg} ${validity.badgeColors.text} ${validity.badgeColors.border}`}>
                            {validity.countdownLabel}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-[10px] text-[#A1A1AA]">
                          <div className="flex items-center gap-1 min-w-0">
                            <Calendar size={11} className="text-[#A1A1AA] shrink-0" />
                            <span className="truncate">
                              {validity.isExpired
                                ? `Expired ${validity.formattedRenewalDate}`
                                : `Renews ${validity.formattedRenewalDate} / Monthly Cycle`}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => { void openCustomerPortal(); }}
                            className="text-[10px] text-zinc-300 hover:text-white font-medium underline underline-offset-2 flex items-center gap-0.5 shrink-0 ml-1.5"
                          >
                            <span>Manage</span>
                            <ExternalLink size={9} />
                          </button>
                        </div>

                        {/* Subtle 2px cycle progress bar */}
                        <div className="w-full bg-white/10 rounded-full h-0.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-300 ${validity.badgeColors.bar}`}
                            style={{ width: `${validity.cycleProgressPercent}%` }}
                            role="progressbar"
                            aria-valuenow={validity.cycleProgressPercent}
                            aria-valuemin={0}
                            aria-valuemax={100}
                          />
                        </div>
                      </div>
                    )}

                  {onOpenCheckout && (
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onOpenCheckout();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2 transition-colors font-medium"
                    >
                      <ArrowRight size={13} className="text-amber-400" />
                      <span>Upgrade Plan</span>
                    </button>
                  )}

                  {onNavigateSettings && (
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onNavigateSettings();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2 transition-colors font-medium"
                    >
                      <Settings size={13} className="text-[#A1A1AA]" />
                      <span>Profile & Settings</span>
                    </button>
                  )}

                  {onSignOut && (
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onSignOut();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg text-red-400 hover:bg-red-500/10 flex items-center gap-2 border-t border-white/10 pt-2 transition-colors font-medium"
                    >
                      <LogOut size={13} />
                      <span>Sign Out</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
              <button
                onClick={() => onOpenAuth && onOpenAuth('signin')}
                className="hidden sm:inline-flex items-center min-h-11 text-xs font-mono text-[#A1A1AA] hover:text-white px-2 rounded transition-colors whitespace-nowrap"
              >
                Sign In
              </button>
              <button
                onClick={() => onOpenAuth && onOpenAuth('signup')}
                className="btn btn-primary text-xs font-mono px-3 min-h-11 sm:min-h-9 rounded bg-emerald-500 text-black hover:bg-emerald-400 whitespace-nowrap font-bold"
              >
                Sign Up
              </button>
            </div>
          )}
        </div>
      </header>

      <ConnectTargetModal
        isOpen={isGithubModalOpen}
        onClose={() => setIsGithubModalOpen(false)}
        onAddNewProject={onAddNewProject}
        onSelectProject={onSelectProject}
        onTriggerScan={onTriggerScan}
      />

      <TierDetailsModal
        isOpen={isTierDetailsOpen}
        onClose={() => setIsTierDetailsOpen(false)}
        currentTier={(user?.tier as UserTier) || 'Free'}
        onSelectPlan={(plan) => {
          if (onOpenCheckout) onOpenCheckout(plan);
        }}
      />
    </>
  );
};
