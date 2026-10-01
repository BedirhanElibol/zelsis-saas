'use client';

import React, { useState } from 'react';
import { Project } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/demo-data';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { PageTransition } from '../PageTransition';
import { UserProfile } from '@/components/auth/AuthModal';
import { PlanUsageQuota } from '@/data/schema';

interface AppShellProps {
  children?: React.ReactNode;
  activeNav: string;
  onNavigate: (nav: string) => void;
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
  quota?: PlanUsageQuota;
}

export const AppShell: React.FC<AppShellProps> = ({
  children,
  activeNav,
  onNavigate,
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
  quota
}) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  React.useEffect(() => {
    if (typeof document === 'undefined') return;
    if (isMobileMenuOpen) {
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.overflow = 'hidden';
      if (scrollbarWidth > 0) {
        document.body.style.paddingRight = `${scrollbarWidth}px`;
      }
    } else {
      document.body.style.overflow = '';
      document.body.style.paddingRight = '';
    }
    return () => {
      document.body.style.overflow = '';
      document.body.style.paddingRight = '';
    };
  }, [isMobileMenuOpen]);

  const customProjectsCount = projects.filter(
    (p) => !p.id.startsWith('proj-preset') && p.id !== 'proj-shipguard-self' && p.id !== 'proj-saas-starter' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-react-core'
  ).length;

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] flex flex-col font-sans">
      {/* Top Header with Layout Fixes & Auth Controls */}
      <Header
        projects={projects}
        selectedProject={selectedProject}
        onSelectProject={onSelectProject}
        onTriggerScan={onTriggerScan}
        onNavigateLanding={onNavigateLanding}
        onAddNewProject={onAddNewProject}
        user={user}
        onOpenAuth={onOpenAuth}
        onSignOut={onSignOut}
        onOpenCheckout={onOpenCheckout}
        onNavigateSettings={() => onNavigate('settings')}
        onToggleMobileMenu={() => setIsMobileMenuOpen((prev) => !prev)}
        quota={quota}
      />

      <div className="flex flex-1 relative">
        {/* Left Persistent Sidebar (Desktop) + Slide-over Drawer (Mobile) */}
        <Sidebar
          activeNav={activeNav}
          onNavigate={onNavigate}
          user={user}
          onOpenAuth={(mode) => onOpenAuth && onOpenAuth(mode)}
          onNavigateSettings={() => onNavigate('settings')}
          isMobileOpen={isMobileMenuOpen}
          onCloseMobile={() => setIsMobileMenuOpen(false)}
          quota={quota}
          projectsCount={customProjectsCount}
          onOpenCheckout={onOpenCheckout}
        />

        {/* Content Area with Fluid Page Transition */}
        <main className="flex-1 min-w-0 bg-[#0A0A0A] p-3 sm:p-6 md:p-8 overflow-y-auto w-full">
          <PageTransition routeKey={activeNav}>
            {children}
          </PageTransition>
        </main>
      </div>
    </div>
  );
};
