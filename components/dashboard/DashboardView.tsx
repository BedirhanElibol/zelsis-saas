'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Project, Finding, UserTier } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/demo-data';
import { KpiCards } from './KpiCards';
import { SeverityChart } from './SeverityChart';
import { FindingsTable } from '../findings/FindingsTable';
import { InteractiveAnalyzer } from '../InteractiveAnalyzer';
import { VulnerabilityPlayground } from './VulnerabilityPlayground';
import { ScaLicenseRiskCard } from './ScaLicenseRiskCard';
import { QuickChartWidget } from './QuickChartWidget';
import { DashboardModals, ActiveModalType } from './DashboardModals';
import { GateStatusBanner } from './GateStatusBanner';
import { gateSeverity, gatingFindings } from '@/lib/scanner/scoring';
import { withLiveStatus } from '@/lib/project-status';
import { OnboardingChecklist } from './OnboardingChecklist';
import { DemoShowcaseBanner } from '../OverviewView';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import { ShieldCheck, Code, Server } from 'lucide-react';
import { ConnectTargetModal } from '../layout/ConnectTargetModal';
import { ClipboardToastBadge, useClipboardToast } from '../ui/Toast';
import { ComponentErrorBoundary } from '../common/ComponentErrorBoundary';

interface DashboardViewProps {
  project: Project;
  onTriggerScan: (projectOverride?: Project) => void;
  onInspectFinding: (f: Finding) => void;
  onNavigatePillar: (pillar: string) => void;
  onLoadDemoFindings?: (findings: Finding[]) => void;
  user?: { isLoggedIn?: boolean; tier?: string } | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onAddNewProject?: (p: Project) => void;
  onSelectProject?: (p: Project) => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  project,
  onTriggerScan,
  onInspectFinding,
  onNavigatePillar,
  onLoadDemoFindings,
  user,
  onOpenAuth,
  onAddNewProject,
  onSelectProject,
  onOpenCheckout,
}) => {
  const [copiedMaster, setCopiedMaster] = useState(false);
  const [isConnectTargetOpen, setIsConnectTargetOpen] = useState(false);
  const [activeModal, setActiveModal] = useState<ActiveModalType>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'sandbox' | 'diagnostics'>('findings');
  const {
    showToast,
    isVisible: isToastVisible,
    message: toastMessage,
    badge: toastBadge,
    hideToast,
  } = useClipboardToast();

  const safeProject: Project = useMemo(() => {
    const p = (project && typeof project === 'object' && !('nativeEvent' in project) && (project as any).id)
      ? project
      : MOCK_PROJECTS[0];
    return withLiveStatus({
      ...p,
      name: p.name || 'Target Repository',
      framework: p.framework || 'Polyglot Web App',
      lastScanAt: p.lastScanAt || (Array.isArray(p.findings) && p.findings.length ? 'Unknown' : 'Never audited'),
      readinessScore: typeof p.readinessScore === 'number' ? p.readinessScore : 100,
      gateStatus: p.gateStatus || 'PASSED',
      findings: Array.isArray(p.findings) ? p.findings : [],
      criticalCount: typeof p.criticalCount === 'number' ? p.criticalCount : 0,
      highCount: typeof p.highCount === 'number' ? p.highCount : 0,
      mediumCount: typeof p.mediumCount === 'number' ? p.mediumCount : 0,
      lowCount: typeof p.lowCount === 'number' ? p.lowCount : 0,
      uiClicheCount: typeof p.uiClicheCount === 'number' ? p.uiClicheCount : 0,
    });
  }, [project]);

  // Cmd+K / Ctrl+K keyboard shortcut listener for Knowledge Base
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setActiveModal((prev: ActiveModalType) => (prev === 'kb' ? null : 'kb'));
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const openFindings = useMemo(
    () => (safeProject.findings || []).filter((f) => f && f.status === 'OPEN'),
    [safeProject.findings]
  );

  // Same basis as the gate and the findings table: proven rules only, at the severity the gate uses.
  // Counting unproven suggestions here showed "PASSED · 2 Critical" side by side.
  const gateFindings = useMemo(
    () => gatingFindings(openFindings.filter(Boolean)).filter((f) => f.maturity !== 'unproven'),
    [openFindings]
  );

  const criticals = useMemo(
    () => gateFindings.filter((f) => gateSeverity(f) === 'CRITICAL'),
    [gateFindings]
  );

  const highs = useMemo(
    () => gateFindings.filter((f) => gateSeverity(f) === 'HIGH'),
    [gateFindings]
  );

  const uiCliches = useMemo(
    () => openFindings.filter((f) => f && f.type === 'VIBEPOLISH'),
    [openFindings]
  );

  const copyMasterPrompt = () => {
    if (openFindings.length === 0) return;

    const prompt = `Act as Senior Lead Security Architect and Principal UI Designer.
Audit target project "${safeProject.name}" (${safeProject.framework}).
Resolve all ${openFindings.length} open vulnerabilities:

${openFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.filePath})\nRemediation: ${f.remediationPrompt}`).join('\n\n')}

Enforce strict OWASP Top 10 compliance, fix the listed UI quality and accessibility (WCAG 2.2 AA) issues, and provide verified drop-in code fixes.`;
    navigator.clipboard.writeText(prompt);
    setCopiedMaster(true);
    showToast('AI prompt copied to clipboard', '[COPIED]');
    setTimeout(() => setCopiedMaster(false), 2000);
  };

  return (
    <div className="flex flex-col gap-6 relative">
      {/* Interactive Demo Showcase Banner for Guests */}
      {(!user || !user.isLoggedIn) && (
        <DemoShowcaseBanner
          onOpenAuth={onOpenAuth}
          onFocusQuickAudit={() => setIsConnectTargetOpen(true)}
        />
      )}

      {/* A signed-in account with no projects yet sees the sample project: say so, so its score is not read as theirs */}
      {user?.isLoggedIn && safeProject.id === MOCK_PROJECTS[0].id && (
        <div role="status" className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
          <p className="text-sm text-[#EDEDED] m-0">
            <strong className="text-amber-300">Sample data.</strong> This demo project shows what a Zelsis report looks like; none of it is from your code.
          </p>
          <button
            type="button"
            onClick={() => setIsConnectTargetOpen(true)}
            className="shrink-0 min-h-[44px] px-4 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black text-sm font-bold"
          >
            Scan your repository
          </button>
        </div>
      )}

      {/* Top Gate Status Banner */}
      <ComponentErrorBoundary componentName="GateStatusBanner" resetKeys={[safeProject?.id, safeProject?.gateStatus]}>
        <GateStatusBanner
          project={safeProject}
          criticals={criticals}
          highs={highs}
          uiCliches={uiCliches}
          onTriggerScan={onTriggerScan}
          onOpenConnectTarget={() => setIsConnectTargetOpen(true)}
          onOpenModal={(type) => setActiveModal(type)}
          user={user}
          onOpenCheckout={onOpenCheckout}
        />
      </ComponentErrorBoundary>

      {/* Onboarding Checklist */}
      <OnboardingChecklist project={safeProject} />

      {/* Swiss Navigation Tabs Bar */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-white/10 pb-3">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#141414] border border-white/10 rounded-xl w-fit">
          <button
            onClick={() => setActiveTab('findings')}
            className={`swiss-tab ${activeTab === 'findings' ? 'swiss-tab-active' : ''}`}
          >
            <ShieldCheck size={14} className={activeTab === 'findings' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Audit &amp; Findings</span>
            <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-white/10 text-white">
              {openFindings.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('sandbox')}
            className={`swiss-tab ${activeTab === 'sandbox' ? 'swiss-tab-active' : ''}`}
          >
            <Code size={14} className={activeTab === 'sandbox' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Code Inspector &amp; Sandbox</span>
          </button>

          <button
            onClick={() => setActiveTab('diagnostics')}
            className={`swiss-tab ${activeTab === 'diagnostics' ? 'swiss-tab-active' : ''}`}
          >
            <Server size={14} className={activeTab === 'diagnostics' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Diagnostics &amp; Telemetry</span>
            <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-white/10 text-[#A1A1AA]">
              4 Tools
            </span>
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs text-[#A1A1AA] font-mono">
          <div className="flex items-center gap-2 bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg">
            <span>Environment:</span>
            <select aria-label="Environment" className="bg-transparent border-none text-white font-medium focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none cursor-pointer">
              <option value="auto">Auto-detect ({safeProject.framework})</option>
              <option value="nextjs">Next.js / React</option>
              <option value="python">Python (FastAPI/Django)</option>
              <option value="go">Go (Gin/Fiber)</option>
              <option value="ruby">Ruby on Rails</option>
              <option value="php">PHP (Laravel)</option>
              <option value="java">Java (Spring Boot)</option>
              <option value="dotnet">.NET / C#</option>
              <option value="mobile">React Native / Flutter</option>
            </select>
          </div>
          <span>Last Scan: <strong className="text-white font-medium">{safeProject.lastScanAt}</strong></span>
        </div>
      </div>

      {/* Tab 1: Primary Audit & Findings View */}
      {activeTab === 'findings' && (
        <div className="flex flex-col gap-6">
          <KpiCards project={safeProject} onNavigatePillar={onNavigatePillar} />
          <SeverityChart project={safeProject} />
          <ComponentErrorBoundary componentName="FindingsTable" resetKeys={[safeProject?.id, safeProject?.findings?.length]}>
            <FindingsTable
              projectId={safeProject.id}
              findings={safeProject.findings}
              onInspectFinding={onInspectFinding}
              onTriggerScan={onTriggerScan}
              onLoadDemoFindings={onLoadDemoFindings}
              onCopyPrompt={copyMasterPrompt}
              copiedPrompt={copiedMaster}
              userTier={user?.tier as UserTier | undefined}
              onOpenCheckout={onOpenCheckout}
            />
          </ComponentErrorBoundary>
        </div>
      )}

      {/* Tab 2: AST Code Inspector & Exploits Sandbox */}
      {activeTab === 'sandbox' && (
        <div className="flex flex-col gap-6">
          <InteractiveAnalyzer />
          <VulnerabilityPlayground />
        </div>
      )}

      {/* Tab 3: Deep Diagnostics, Performance & Telemetry */}
      {activeTab === 'diagnostics' && (
        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-1 gap-6">
            <ComponentErrorBoundary componentName="ScaLicenseRiskCard" resetKeys={[safeProject?.id]}>
              <ScaLicenseRiskCard />
            </ComponentErrorBoundary>
          </div>
          <QuickChartWidget project={safeProject} />
        </div>
      )}

      {/* Extracted Dashboard Modals */}
      <DashboardModals
        project={safeProject}
        activeModal={activeModal}
        onClose={() => setActiveModal(null)}
        userTier={user?.tier as UserTier | undefined}
        onOpenCheckout={onOpenCheckout}
      />

      <ClipboardToastBadge
        isVisible={isToastVisible}
        message={toastMessage}
        badge={toastBadge}
        onDismiss={hideToast}
      />

      <ConnectTargetModal
        isOpen={isConnectTargetOpen}
        onClose={() => setIsConnectTargetOpen(false)}
        onAddNewProject={onAddNewProject}
        onSelectProject={(p) => {
          onSelectProject?.(p);
          setIsConnectTargetOpen(false);
        }}
        onTriggerScan={(p) => {
          onTriggerScan(p);
          setIsConnectTargetOpen(false);
        }}
      />
    </div>
  );
};
