'use client';

import React, { Suspense, useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import { Project, Finding, ScanHistoryItem, UserTier } from '@/data/schema';
import { MOCK_PROJECTS, VIBEPOLISH_30_CATALOG, UI_RULES_CATALOG, AI_CLICHE_25_CATALOG } from '@/data/mockData';
import { AppShell } from '@/components/layout/AppShell';
import { DashboardView } from '@/components/dashboard/DashboardView';
import { ScanRunnerView } from '@/components/ScanRunnerView';
import { RemediationDrawer } from '@/components/findings/RemediationDrawer';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';
import { useDashboardState } from '@/hooks/useDashboardState';
import { useRouter, useSearchParams } from 'next/navigation';
import { verifyLicenseKey } from '@/lib/stripe-checkout';
import { checkScanQuota } from '@/lib/quota-manager';
import { QuotaLimitModal } from '@/components/dashboard/QuotaLimitModal';
import { isPlatformAdminEmail } from '@/lib/subscription-utils';

// Next.js Dynamic Code Splitting for heavy dashboard views
const SecurityAuditView = dynamic(() => import('@/components/SecurityAuditView').then(m => m.SecurityAuditView), { ssr: false });
const ComplianceAuditView = dynamic(() => import('@/components/ComplianceAuditView').then(m => m.ComplianceAuditView), { ssr: false });
const InfraAuditView = dynamic(() => import('@/components/InfraAuditView').then(m => m.InfraAuditView), { ssr: false });
const CicdAutomationView = dynamic(() => import('@/components/CicdAutomationView').then(m => m.CicdAutomationView), { ssr: false });
const VibePolishView = dynamic(() => import('@/components/VibePolishView').then(m => m.VibePolishView), { ssr: false });
const VibeCareView = dynamic(() => import('@/components/VibeCareView').then(m => m.VibeCareView), { ssr: false });
const RemediationQueueView = dynamic(() => import('@/components/RemediationQueueView').then(m => m.RemediationQueueView), { ssr: false });
const ProjectsView = dynamic(() => import('@/components/ProjectsView').then(m => m.ProjectsView), { ssr: false });
const ScanHistoryView = dynamic(() => import('@/components/ScanHistoryView').then(m => m.ScanHistoryView), { ssr: false });
const ProjectSettingsView = dynamic(() => import('@/components/ProjectSettingsView').then(m => m.ProjectSettingsView), { ssr: false });
const CheckoutView = dynamic(() => import('@/components/checkout/CheckoutView').then(m => m.CheckoutView), { ssr: false });
import { safeSetStorageItem } from '@/lib/storage';
import { ShieldCheck, Plus, Loader2, LogIn } from 'lucide-react';
import { LifecycleBanner } from '@/components/dashboard/LifecycleBanner';
import { normalizeRepoUrl, extractRepoDisplayName } from '@/lib/github-api';
import { ComponentErrorBoundary } from '@/components/common/ComponentErrorBoundary';
import { UNDETECTED_FRAMEWORK } from '@/lib/scanner/stack-detect';

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0A0A0A]" />}>
      <DashboardContent />
    </Suspense>
  );
}

function DashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const {
    activeNav,
    setActiveNav,
    projects,
    setProjects,
    selectedProject,
    setSelectedProject,
    isScanning,
    setIsScanning,
    inspectingFinding,
    setInspectingFinding,
    user,
    setUser,
    authStatus,
    isAuthModalOpen,
    setIsAuthModalOpen,
    authInitialMode,
    setAuthInitialMode,
    isCheckoutOpen,
    setIsCheckoutOpen,
    quota,
    setQuota,
    recordScanUsage,
    recordAiPromptUsage,
    requestScanAuthorization,
    completeScanTelemetry,
    persistProjectsList,
    handleSelectProject,
    handleDeleteProject,
    handleToggleResolveFinding,
    handleMarkFalsePositive,
    handleIgnoreRule,
    handleSignOut,
    handleUpdateUserProfile,
  } = useDashboardState();

  const [checkoutInitialPlan, setCheckoutInitialPlan] = useState<'Pro' | 'Enterprise'>('Pro');
  const [scanProjectOverride, setScanProjectOverride] = useState<Project | null>(null);
  const [isQuotaModalOpen, setIsQuotaModalOpen] = useState<boolean>(false);
  const hasProcessedRepoRef = React.useRef(false);

  const handleTriggerScan = (projectOverride?: Project | unknown) => {
    const isPlatformAdmin = isPlatformAdminEmail(user?.email);
    const userTier = isPlatformAdmin ? 'Enterprise' : ((user?.tier as UserTier) || 'Free');
    if (quota && !isPlatformAdmin) {
      const scanCheck = checkScanQuota(quota, userTier);
      if (!scanCheck.allowed) {
        setIsQuotaModalOpen(true);
        return;
      }
    }

    // Defensive check: Guard against SyntheticEvents, MouseEvents, or objects lacking repoUrl
    const candidateRecord = projectOverride as Record<string, unknown> | null;
    const isGenuineProject = Boolean(
      candidateRecord &&
      typeof candidateRecord === 'object' &&
      !('nativeEvent' in candidateRecord) &&
      !('preventDefault' in candidateRecord) &&
      !('_reactName' in candidateRecord) &&
      typeof candidateRecord.repoUrl === 'string' &&
      candidateRecord.repoUrl.trim().length > 0 &&
      candidateRecord.repoUrl !== 'undefined'
    );

    const validProject = isGenuineProject ? (projectOverride as Project) : null;

    if (validProject) {
      handleSelectProject(validProject);
      setScanProjectOverride(validProject);
    } else {
      setScanProjectOverride(null);
    }
    setActiveNav('dashboard');
    setIsScanning(true);
  };

  const handleAddNewProject = (newP: Project) => {
    const newUrl = newP?.repoUrl || '';
    const normTarget = (newUrl === 'local' ? 'local' : (normalizeRepoUrl(newUrl) || newUrl)).toLowerCase().replace(/\/+$/, '').trim();
    setProjects((prev) => {
      const existingIdx = prev.findIndex((p) => {
        if (p.id === newP.id) return true;
        const pUrl = p?.repoUrl || '';
        const pNorm = (pUrl === 'local' ? 'local' : (normalizeRepoUrl(pUrl) || pUrl)).toLowerCase().replace(/\/+$/, '').trim();
        return pNorm === normTarget;
      });

      let updated: Project[];
      if (existingIdx >= 0) {
        const copy = [...prev];
        copy[existingIdx] = { ...copy[existingIdx], ...newP, id: copy[existingIdx].id };
        updated = copy;
      } else {
        updated = [newP, ...prev];
      }
      persistProjectsList(updated);
      return updated;
    });
    handleSelectProject(newP);
  };

  // Direct repo URL scan trigger (e.g. from Landing Hero or URL query params)
  useEffect(() => {
    // Wait for a verified session; the OAuth round-trip drops query params, so fall back to the stored repo
    if (authStatus !== 'authenticated') return;
    let pendingRepo: string | null = null;
    try {
      pendingRepo = sessionStorage.getItem('zelsis_pending_repo');
      sessionStorage.removeItem('zelsis_pending_repo');
    } catch {
      pendingRepo = null;
    }
    const repoParam = searchParams.get('repo') || pendingRepo;
    const scanParam = searchParams.get('scan') || (pendingRepo ? 'true' : null);
    if (!repoParam || hasProcessedRepoRef.current) return;
    hasProcessedRepoRef.current = true;

    const normalized = normalizeRepoUrl(repoParam);
    if (!normalized) return;

    const existing = projects.find(
      (p) => (p?.repoUrl || '').toLowerCase() === (normalized || '').toLowerCase()
    );

    if (existing) {
      handleSelectProject(existing);
      if (scanParam === 'true') {
        handleTriggerScan(existing);
      }
    } else {
      const displayName = extractRepoDisplayName(normalized);
      const newProj: Project = {
        id: `proj-import-${Date.now()}`,
        name: displayName,
        repoUrl: normalized,
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
      handleAddNewProject(newProj);
      if (scanParam === 'true') {
        handleTriggerScan(newProj);
      }
    }

    if (typeof window !== 'undefined') {
      const cleanUrl = new URL(window.location.href);
      cleanUrl.searchParams.delete('repo');
      cleanUrl.searchParams.delete('scan');
      window.history.replaceState({}, '', cleanUrl.toString());
    }
  }, [searchParams, projects, authStatus]);

  const handleOpenCheckoutModal = (requestedPlan?: 'Pro' | 'Enterprise') => {
    if (requestedPlan) {
      setCheckoutInitialPlan(requestedPlan);
    } else {
      setCheckoutInitialPlan(user?.tier === 'Pro' ? 'Enterprise' : 'Pro');
    }
    if (!user || !user.isLoggedIn) {
      setAuthInitialMode('signup');
      setIsAuthModalOpen(true);
    } else {
      const plan = (requestedPlan || (user?.tier === 'Pro' ? 'Enterprise' : 'Pro')).toLowerCase();
      router.push(`/checkout?plan=${plan}`);
    }
  };

  const handleLoadDemoFindings = (demoFindings: Finding[]) => {
    const criticals = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
    const highs = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
    const mediums = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
    const lows = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
    const uiCliches = demoFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;
    const updated: Project = {
      ...selectedProject,
      findings: demoFindings,
      criticalCount: criticals,
      highCount: highs,
      mediumCount: mediums,
      lowCount: lows,
      uiClicheCount: uiCliches,
      readinessScore: 68,
      gateStatus: 'FAILED',
      lastScanAt: 'Just now (Demo Template)'
    };
    setSelectedProject(updated);
    setProjects((prev) => {
      const updatedList = prev.map((p) => (p.id === selectedProject.id ? updated : p));
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  const safeSelectedProject: Project = React.useMemo(() => {
    const candidate = (selectedProject && typeof selectedProject === 'object' && !('nativeEvent' in selectedProject) && selectedProject.id)
      ? selectedProject
      : (projects.find((p) => p && typeof p === 'object' && !('nativeEvent' in p) && p.id) || MOCK_PROJECTS[0]);
    return {
      ...candidate,
      name: candidate.name || 'Target Repository',
      framework: candidate.framework || UNDETECTED_FRAMEWORK,
      lastScanAt: candidate.lastScanAt || 'Never audited',
      readinessScore: typeof candidate.readinessScore === 'number' ? candidate.readinessScore : 100,
      gateStatus: candidate.gateStatus || 'PASSED',
      findings: Array.isArray(candidate.findings) ? candidate.findings : [],
      criticalCount: typeof candidate.criticalCount === 'number' ? candidate.criticalCount : 0,
      highCount: typeof candidate.highCount === 'number' ? candidate.highCount : 0,
      mediumCount: typeof candidate.mediumCount === 'number' ? candidate.mediumCount : 0,
      lowCount: typeof candidate.lowCount === 'number' ? candidate.lowCount : 0,
      uiClicheCount: typeof candidate.uiClicheCount === 'number' ? candidate.uiClicheCount : 0,
    };
  }, [selectedProject, projects]);

  // Auth gate: the dashboard is only usable with a verified Supabase session
  if (authStatus !== 'authenticated') {
    return (
      <div className="min-h-screen bg-[#0A0A0A] text-white flex items-center justify-center p-4 sm:p-6">
        {authStatus === 'loading' ? (
          <Loader2 size={28} className="animate-spin text-[#A1A1AA]" aria-label="Verifying session" />
        ) : (
          <div className="max-w-md w-full bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col items-center text-center shadow-2xl">
            <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-5">
              <LogIn size={28} />
            </div>
            <h2 className="text-xl font-extrabold tracking-tight mb-2">Sign in to continue</h2>
            <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed mb-6">
              Your saved repositories, live sites and scan history are tied to your account. Sign in or create a free account to use Zelsis.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 w-full">
              <button
                onClick={() => {
                  setAuthInitialMode('signin');
                  setIsAuthModalOpen(true);
                }}
                className="flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono bg-white text-black hover:bg-neutral-200 transition-all"
              >
                Sign In
              </button>
              <button
                onClick={() => {
                  setAuthInitialMode('signup');
                  setIsAuthModalOpen(true);
                }}
                className="flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono border border-white/10 text-white hover:bg-white/5 transition-all"
              >
                Create Free Account
              </button>
            </div>
            <button
              onClick={() => router.push('/')}
              className="mt-4 text-xs text-[#A1A1AA] hover:text-white transition-colors"
            >
              Back to homepage
            </button>
          </div>
        )}
        <AuthModal
          isOpen={isAuthModalOpen}
          onClose={() => setIsAuthModalOpen(false)}
          onLoginSuccess={() => setIsAuthModalOpen(false)}
          initialMode={authInitialMode}
        />
      </div>
    );
  }

  if (projects.length === 0) {
    const handleRestoreDemoShowcase = () => {
      const demoProject = MOCK_PROJECTS[0];
      setProjects([demoProject]);
      persistProjectsList([demoProject]);
      handleSelectProject(demoProject);
    };

    return (
      <div className="min-h-screen bg-[#0A0A0A] text-white flex items-center justify-center p-4 sm:p-6">
        <div className="max-w-md w-full bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col items-center text-center shadow-2xl">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-5 shadow-inner">
            <ShieldCheck size={28} />
          </div>

          <h2 className="text-xl font-extrabold text-white tracking-tight mb-2">
            No Projects Connected
          </h2>

          <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed mb-6">
            Connect your GitHub repository to audit deployment readiness against OWASP security, performance, and UI quality standards, or explore with our interactive showcase.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 w-full">
            <button
              onClick={handleRestoreDemoShowcase}
              className="btn btn-primary flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono bg-white text-black hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 shadow-lg"
            >
              <ShieldCheck size={14} />
              <span>Load Demo Showcase</span>
            </button>

            <button
              onClick={() => {
                const newProj: Project = {
                  id: `proj-${Date.now()}`,
                  name: 'My New Application',
                  repoUrl: 'https://github.com/example/repo',
                  framework: UNDETECTED_FRAMEWORK,
                  providers: [],
                  lastScanAt: 'Never audited',
                  readinessScore: 100,
                  gateStatus: 'PASSED',
                  criticalCount: 0,
                  highCount: 0,
                  mediumCount: 0,
                  lowCount: 0,
                  uiClicheCount: 0,
                  findings: []
                };
                handleAddNewProject(newProj);
              }}
              className="btn btn-secondary flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono border-white/10 text-white hover:bg-white/5 transition-all flex items-center justify-center gap-2"
            >
              <Plus size={14} />
              <span>Connect Your First Project</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <AppShell
      projects={projects}
      activeNav={activeNav}
      onNavigate={(nav) => {
        setIsScanning(false);
        setActiveNav(nav);
        if (typeof window !== 'undefined') {
          try {
            const url = new URL(window.location.href);
            if (nav === 'dashboard') {
              url.searchParams.delete('nav');
            } else {
              url.searchParams.set('nav', nav);
            }
            window.history.replaceState({}, '', url.pathname + url.search + url.hash);
          } catch (navSyncErr: unknown) {
            console.warn('[UI-106] Handled error in DashboardPage URL sync:', navSyncErr instanceof Error ? navSyncErr.message : String(navSyncErr));
          }
        }
      }}
      selectedProject={safeSelectedProject}
      onSelectProject={handleSelectProject}
      onTriggerScan={handleTriggerScan}
      onNavigateLanding={() => router.push('/')}
      onAddNewProject={handleAddNewProject}
      user={user}
      onOpenAuth={(mode) => {
        setAuthInitialMode(mode);
        setIsAuthModalOpen(true);
      }}
      onSignOut={handleSignOut}
      onOpenCheckout={() => handleOpenCheckoutModal()}
      quota={quota}
    >
      <div className="flex flex-col gap-6 w-full">
        <LifecycleBanner user={user} />
        {isScanning ? (
          <ComponentErrorBoundary componentName="ScanRunnerView" resetKeys={[scanProjectOverride?.id, selectedProject?.id]}>
            <ScanRunnerView
              project={
                (scanProjectOverride && scanProjectOverride.repoUrl && scanProjectOverride.repoUrl !== 'undefined')
                  ? scanProjectOverride
                  : (selectedProject && selectedProject.repoUrl && selectedProject.repoUrl !== 'undefined')
                  ? selectedProject
                  : (projects.find((p) => p?.repoUrl && p.repoUrl !== 'undefined') || MOCK_PROJECTS[0])
              }
              user={user}
              quota={quota}
              onOpenCheckout={(plan) => handleOpenCheckoutModal(plan)}
              onConsumeScanQuota={recordScanUsage}
              onRequestScanAuthorization={requestScanAuthorization}
              onCompleteScanTelemetry={completeScanTelemetry}
              onCompleteScan={(result) => {
                const currentTarget = scanProjectOverride || selectedProject;
                if (result) {
                  const newScanHistoryItem: ScanHistoryItem = {
                    id: `SCAN-${Date.now().toString(36).toUpperCase()}`,
                    date: new Date().toLocaleString(),
                    target: currentTarget.repoUrl,
                    score: result.score,
                    gateStatus: result.gateStatus,
                    criticalCount: result.criticalCount,
                    highCount: result.highCount,
                    mediumCount: result.mediumCount,
                    duration: '3.4s',
                    triggeredBy: 'Manual Dashboard Audit'
                  };
                  const updatedProject: Project = {
                    ...currentTarget,
                    readinessScore: result.score,
                    gateStatus: result.gateStatus,
                    criticalCount: result.criticalCount,
                    highCount: result.highCount,
                    mediumCount: result.mediumCount,
                    lowCount: result.lowCount,
                    uiClicheCount: result.uiClicheCount,
                    findings: result.findings,
                    framework: result.detectedFramework || currentTarget.framework,
                    providers: result.detectedProviders?.length ? result.detectedProviders : currentTarget.providers,
                    lastScanAt: new Date().toLocaleString(),
                    scanHistory: [newScanHistoryItem, ...(currentTarget.scanHistory || [])].slice(0, 20)
                  };
                  setSelectedProject(updatedProject);
                  setProjects((prev) => {
                    const exists = prev.some((p) => p.id === currentTarget.id);
                    const updatedList = exists
                      ? prev.map((p) => (p.id === currentTarget.id ? updatedProject : p))
                      : [updatedProject, ...prev];
                    persistProjectsList(updatedList);
                    return updatedList;
                  });
                }
                setScanProjectOverride(null);
                setIsScanning(false);
                setActiveNav('dashboard');
              }}
            />
          </ComponentErrorBoundary>
        ) : (
          <>
            {activeNav === 'dashboard' && (
              <ComponentErrorBoundary componentName="DashboardView" resetKeys={[safeSelectedProject?.id, safeSelectedProject?.lastScanAt]}>
                <DashboardView
                  project={safeSelectedProject}
                  onTriggerScan={handleTriggerScan}
                  onInspectFinding={(f) => setInspectingFinding(f)}
                  onNavigatePillar={(p) => setActiveNav(p)}
                  onLoadDemoFindings={handleLoadDemoFindings}
                  user={user}
                  onOpenAuth={(mode) => {
                    setAuthInitialMode(mode);
                    setIsAuthModalOpen(true);
                  }}
                  onAddNewProject={handleAddNewProject}
                  onSelectProject={handleSelectProject}
                  onOpenCheckout={handleOpenCheckoutModal}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'security' && (
              <ComponentErrorBoundary componentName="SecurityAuditView" resetKeys={[safeSelectedProject?.id]}>
                <SecurityAuditView
                  findings={safeSelectedProject.findings ?? []}
                  onInspectFinding={(f) => setInspectingFinding(f)}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'compliance' && (
              <ComponentErrorBoundary componentName="ComplianceAuditView" resetKeys={[safeSelectedProject?.id]}>
                <ComplianceAuditView
                  findings={safeSelectedProject.findings ?? []}
                  onInspectFinding={(f) => setInspectingFinding(f)}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'infra' && (
              <ComponentErrorBoundary componentName="InfraAuditView" resetKeys={[safeSelectedProject?.id]}>
                <InfraAuditView
                  findings={safeSelectedProject.findings ?? []}
                  onInspectFinding={(f) => setInspectingFinding(f)}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'vibepolish' && (
              <ComponentErrorBoundary componentName="VibePolishView">
                <VibePolishView
                  rules={VIBEPOLISH_30_CATALOG}
                  title="Design & UX Polish Matrix"
                  description="Automated design system audit evaluating visual hierarchy, responsive layout shifts, micro-interactions, color contrasts, and accessibility standards."
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'aicliche' && (
              <ComponentErrorBoundary componentName="AiClicheView">
                <VibePolishView
                  rules={AI_CLICHE_25_CATALOG}
                  title="AI Anti-Pattern & Cliché Detector"
                  description="Deep pattern analysis scanning for AI-generated design anti-patterns, generic layout locks, non-standard component trees, and trust-eroding visual tropes."
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'aimaster' && (
              <ComponentErrorBoundary componentName="AiMasterView">
                <VibePolishView
                  rules={UI_RULES_CATALOG}
                  title="Master Quality & Resilience Matrix"
                  description="Full-stack architecture audit covering OWASP top vulnerabilities, RAG retrieval leakage, agent execution boundaries, token cost governance, and production SLA metrics."
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'vibecare' && (
              <ComponentErrorBoundary componentName="VibeCareView" resetKeys={[safeSelectedProject?.id]}>
                <VibeCareView
                  project={safeSelectedProject}
                  user={user}
                  onOpenCheckout={() => handleOpenCheckoutModal('Enterprise')}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'cicd' && (
              <ComponentErrorBoundary componentName="CicdAutomationView" resetKeys={[safeSelectedProject?.id]}>
                <CicdAutomationView
                  projectName={safeSelectedProject.name}
                  project={safeSelectedProject}
                  userTier={user?.tier}
                  onOpenCheckout={handleOpenCheckoutModal}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'remediation' && (
              <ComponentErrorBoundary componentName="RemediationQueueView">
                <RemediationQueueView
                  projects={projects}
                  onInspectFinding={(f) => setInspectingFinding(f)}
                  onToggleResolveFinding={handleToggleResolveFinding}
                  userTier={user?.tier}
                  onOpenCheckout={handleOpenCheckoutModal}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'projects' && (
              <ComponentErrorBoundary componentName="ProjectsView">
                <ProjectsView
                  projects={projects}
                  onSelectProject={(p) => {
                    handleSelectProject(p);
                    setActiveNav('dashboard');
                  }}
                  onAddNewProject={handleAddNewProject}
                  onDeleteProject={handleDeleteProject}
                  onTriggerScan={handleTriggerScan}
                  user={user}
                  onOpenCheckout={() => handleOpenCheckoutModal()}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'scans' && (
              <ComponentErrorBoundary componentName="ScanHistoryView" resetKeys={[safeSelectedProject?.id]}>
                <ScanHistoryView
                  project={safeSelectedProject}
                  onTriggerScan={handleTriggerScan}
                  userTier={user?.tier}
                  onOpenCheckout={handleOpenCheckoutModal}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'checkout' && (
              <ComponentErrorBoundary componentName="CheckoutView">
                <CheckoutView
                  initialPlanId={user?.tier === 'Pro' ? 'vibecare' : 'zelsis-core'}
                  initialBilling="monthly"
                  onBackToPricing={() => setActiveNav('dashboard')}
                  user={user}
                  onOpenAuth={(mode) => {
                    setAuthInitialMode(mode || 'signup');
                    setIsAuthModalOpen(true);
                  }}
                  onUpgradeSuccess={(newTier) => {
                    handleUpdateUserProfile({ tier: newTier });
                  }}
                />
              </ComponentErrorBoundary>
            )}

            {activeNav === 'settings' && (
              <ComponentErrorBoundary componentName="ProjectSettingsView" resetKeys={[safeSelectedProject?.id]}>
                <ProjectSettingsView
                  project={safeSelectedProject}
                  user={user}
                  onOpenAuth={(mode) => {
                    setAuthInitialMode(mode || 'signin');
                    setIsAuthModalOpen(true);
                  }}
                  onUpdateUser={(updatedUser) => {
                    if (user && user.isLoggedIn) {
                      handleUpdateUserProfile(updatedUser);
                    }
                  }}
                  onOpenCheckout={handleOpenCheckoutModal}
                  onSaveSettings={(updatedFields: Partial<Project>) => {
                    const updatedProject = { ...selectedProject, ...updatedFields };
                    setSelectedProject(updatedProject);
                    setProjects((prev) => {
                      const updatedList = prev.map((p) =>
                        p.id === selectedProject.id ? updatedProject : p
                      );
                      persistProjectsList(updatedList);
                      return updatedList;
                    });
                  }}
                  onDeleteAccount={() => {
                    setUser(null);
                    setProjects([MOCK_PROJECTS[0]]);
                    setSelectedProject(MOCK_PROJECTS[0]);
                    router.push('/');
                  }}
                />
              </ComponentErrorBoundary>
            )}
        </>
      )}
      </div>

      {/* Slide-out Remediation Drawer */}
      <RemediationDrawer
        finding={inspectingFinding}
        onClose={() => setInspectingFinding(null)}
        onToggleResolve={handleToggleResolveFinding}
        onMarkFalsePositive={handleMarkFalsePositive}
        onIgnoreRule={handleIgnoreRule}
        user={user}
        quota={quota}
        onRecordAiPrompt={recordAiPromptUsage}
        onOpenCheckout={handleOpenCheckoutModal}
      />

      {/* Authentication Modal */}
      <AuthModal
        isOpen={isAuthModalOpen && !user?.isLoggedIn}
        onClose={() => {
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined') {
            const cleanUrl = new URL(window.location.href);
            if (cleanUrl.searchParams.has('auth')) {
              cleanUrl.searchParams.delete('auth');
              window.history.replaceState({}, '', cleanUrl.toString());
            }
          }
        }}
        onLoginSuccess={(loggedUser) => {
          let resolvedTier = loggedUser.tier || 'Free';
          let resolvedExpiresAt = loggedUser.expiresAt;
          const savedLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          if (savedLic) {
            const licResult = verifyLicenseKey(savedLic, loggedUser.email);
            if (licResult.valid && (licResult.tier === 'Pro' || licResult.tier === 'Enterprise')) {
              resolvedTier = licResult.tier;
              resolvedExpiresAt = licResult.expiresAt;
            }
          }
          if (resolvedTier !== 'Free' && !resolvedExpiresAt) {
            resolvedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          }
          const finalUser: UserProfile = {
            ...loggedUser,
            tier: resolvedTier,
            expiresAt: resolvedExpiresAt,
            status: resolvedTier !== 'Free' ? 'active' : (loggedUser.status || 'active'),
            lastVerifiedAt: Date.now(),
          };
          setUser(finalUser);
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined') {
            const cleanUrl = new URL(window.location.href);
            if (cleanUrl.searchParams.has('auth')) {
              cleanUrl.searchParams.delete('auth');
              window.history.replaceState({}, '', cleanUrl.toString());
            }
          }
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(finalUser));
            localStorage.removeItem('shipguard_user');
          } catch (e: unknown) {
            console.warn('[Zelsis Auth] Failed to persist user session:', e);
          }
          if (finalUser?.email) {
            try {
              const userProjectsKey = `zelsis_user_projects_${(finalUser.email || '').toLowerCase().trim()}`;
              const savedProjectsStr = localStorage.getItem(userProjectsKey);
              if (savedProjectsStr) {
                const parsed = JSON.parse(savedProjectsStr);
                if (Array.isArray(parsed) && parsed.length > 0) {
                  setProjects(parsed);
                  handleSelectProject(parsed[0]);
                  safeSetStorageItem('zelsis_projects', JSON.stringify(parsed));
                  safeSetStorageItem('zelsis_selected_project_id', parsed[0].id);
                }
              }
            } catch (authProjErr) {
              console.warn('[Zelsis Auth] Failed to restore user projects upon auth modal login:', authProjErr);
            }
          }
        }}
        initialMode={authInitialMode}
      />

      {/* Quota Limit Modal with Honest Guidance and Demo Reset */}
      <QuotaLimitModal
        isOpen={isQuotaModalOpen}
        onClose={() => setIsQuotaModalOpen(false)}
        scansUsed={quota?.scansUsed || 3}
        scansLimit={quota?.scansLimit || 3}
      />
    </AppShell>
  );
}
