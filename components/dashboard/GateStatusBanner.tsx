'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Project, Finding } from '@/data/schema';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import {
  Play,
  AlertTriangle,
  CheckCircle2,
  Sliders,
  Download,
  Award,
  GitCompare,
  Bell,
  GitBranch,
  GitPullRequest
} from 'lucide-react';
import {
  Server,
  ShieldAlert,
  ShieldCheck,
  BookOpen,
  Code,
  Table,
  FileText,
  ChevronDown,
  ExternalLink
} from 'lucide-react';
import { exportFindingsToCsv, exportScorecardToJson } from '@/lib/export-utils';
import { ActiveModalType } from './DashboardModals';
import { safeReplace, safeTrim, safeString, safeLower } from '@/lib/safe-utils';
import { UNDETECTED_FRAMEWORK } from '@/lib/scanner/stack-detect';
import { priceLabel } from '@/data/pricing-plans';
import { fetchOrgBranding } from '@/lib/supabase';

interface GateStatusBannerProps {
  project: Project;
  criticals: Finding[];
  highs: Finding[];
  uiCliches: Finding[];
  onTriggerScan: () => void;
  onOpenConnectTarget?: () => void;
  onOpenModal: (type: ActiveModalType) => void;
  user?: { tier?: string } | null;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const GateStatusBanner: React.FC<GateStatusBannerProps> = ({
  project,
  criticals,
  highs,
  uiCliches,
  onTriggerScan,
  onOpenConnectTarget,
  onOpenModal,
  user,
  onOpenCheckout,
}) => {
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);
  const [isToolsMenuOpen, setIsToolsMenuOpen] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const toolsMenuRef = useRef<HTMLDivElement>(null);

  // Click outside and Escape key listener for both dropdowns
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (exportMenuRef.current && !exportMenuRef.current.contains(target)) {
        setIsExportMenuOpen(false);
      }
      if (toolsMenuRef.current && !toolsMenuRef.current.contains(target)) {
        setIsToolsMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsExportMenuOpen(false);
        setIsToolsMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const safeProject: Project = (project && typeof project === 'object' && !('nativeEvent' in project) && (project as any).id)
    ? project
    : {
        id: 'proj-fallback',
        name: 'Target Repository',
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

  const gateStatus = safeProject.gateStatus || 'PASSED';
  const readinessScore = typeof safeProject.readinessScore === 'number' ? safeProject.readinessScore : 100;
  const name = safeProject.name || 'Target Repository';
  const repoUrl = safeProject.repoUrl || '';

  return (
    <div
      className={`bg-[#141414] border rounded-xl p-4 sm:p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5 sm:gap-6 ${
        gateStatus === 'FAILED'
          ? 'border-red-500/30'
          : gateStatus === 'WARNING'
          ? 'border-amber-500/30'
          : 'border-white/10'
      }`}
    >
      {/* Left: Clearance Status & Metric Scorecard */}
      <div className="flex items-start sm:items-center gap-3.5 sm:gap-5 min-w-0">
        <div
          className={`w-12 h-12 sm:w-14 sm:h-14 rounded-xl flex items-center justify-center border font-bold shrink-0 ${
            gateStatus === 'FAILED'
              ? 'bg-red-500/10 border-red-500/30 text-red-500'
              : gateStatus === 'WARNING'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
          }`}
        >
          {gateStatus === 'FAILED' ? (
            <AlertTriangle size={24} className="sm:w-7 sm:h-7" />
          ) : gateStatus === 'WARNING' ? (
            <AlertTriangle size={24} className="sm:w-7 sm:h-7" />
          ) : (
            <CheckCircle2 size={24} className="sm:w-7 sm:h-7 text-emerald-400" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] sm:text-xs font-bold text-[#A1A1AA] font-mono tracking-widest uppercase">
              RELEASE GATE EVALUATION
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold ${
                gateStatus === 'FAILED'
                  ? 'bg-red-500/10 border border-red-500/30 text-red-400'
                  : gateStatus === 'WARNING'
                  ? 'bg-amber-500/10 border border-amber-500/30 text-amber-400'
                  : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
              }`}
            >
              {gateStatus}
            </span>
          </div>

          <h1 className="text-lg sm:text-2xl font-extrabold text-[#EDEDED] mt-1 truncate">
            {name}
          </h1>

          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <span className="text-[11px] font-mono text-[#A1A1AA]">Audited Target:</span>
            {safeTrim(repoUrl) ? (
              <a
                href={safeTrim(repoUrl).startsWith('http') ? safeTrim(repoUrl) : `https://${safeTrim(repoUrl)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-mono font-medium text-zinc-300 hover:text-white hover:underline flex items-center gap-1 transition-colors max-w-xs sm:max-w-md truncate"
                title="Open target repository"
              >
                <span className="truncate">{safeReplace(safeTrim(repoUrl), /^https?:\/\//, '')}</span>
                <ExternalLink size={11} className="shrink-0" />
              </a>
            ) : (
              <span className="text-[11px] font-mono font-bold text-zinc-400">Local Workspace</span>
            )}
            {onOpenConnectTarget && (
              <button
                type="button"
                onClick={onOpenConnectTarget}
                className="text-[10px] font-mono text-zinc-400 hover:text-white px-2 py-0.5 rounded border border-white/10 hover:border-white/20 bg-white/[0.03] hover:bg-white/10 transition-all cursor-pointer shrink-0"
              >
                Change Target
              </button>
            )}
          </div>

          <p className="text-[11px] sm:text-xs text-[#A1A1AA] mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
            <span>
              Readiness Score: <strong className="text-white font-mono">{readinessScore}/100</strong>
            </span>
            <span className={criticals.length > 0 ? 'text-red-400 font-bold' : 'text-[#A1A1AA]'}>
              {criticals.length} Critical
            </span>
            <span className={highs.length > 0 ? 'text-amber-400 font-bold' : 'text-[#A1A1AA]'}>
              {highs.length} High
            </span>
            <span className="text-[#A1A1AA]">
              {uiCliches.length} UI Issues
            </span>
          </p>
        </div>
      </div>

      {/* Right: Consolidated, Clean Action Controls (3 Focused CTAs) */}
      <div className="flex flex-wrap items-center gap-2.5 sm:gap-3 w-full lg:w-auto">
        {/* Primary Action: Re-Run Audit */}
        <button
          onClick={() => onTriggerScan()}
          className="btn btn-primary px-4 sm:px-5 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg flex items-center justify-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 flex-1 sm:flex-initial shadow-md transition-all active:scale-95 cursor-pointer"
        >
          <Play size={13} fill="#0A0A0A" />
          <span>Re-Run Audit</span>
        </button>

        {/* Action: Setup CI/CD Gate */}
        <button
          onClick={() => onOpenModal('manifest')}
          className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-2 border-white/10 bg-white/5 text-white hover:bg-white/10 hover:border-white/20 transition-all cursor-pointer shadow-sm"
          title="Configure automated GitHub Actions & CI/CD release gate"
        >
          <GitBranch size={13} className="text-zinc-300" />
          <span className="font-bold">Setup CI/CD Gate</span>
          <span className="text-[11px] uppercase font-extrabold tracking-wider px-1.5 py-0.5 rounded bg-white/10 text-zinc-300 border border-white/15 ml-0.5">
            PR Bot
          </span>
        </button>

        {/* Action 2: Export Report Dropdown (PDF, CSV, JSON) */}
        <div className="relative" ref={exportMenuRef}>
          <button
            onClick={() => {
              setIsExportMenuOpen((prev) => !prev);
              setIsToolsMenuOpen(false);
            }}
            className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-2 border-white/10 text-[#EDEDED] hover:bg-white/10 transition-colors cursor-pointer"
            aria-label="Export Release Reports"
          >
            <Download size={13} className="text-white" />
            <span>Export Report</span>
            <ChevronDown size={12} className={`text-[#A1A1AA] transition-transform duration-200 ${isExportMenuOpen ? 'rotate-180' : ''}`} />
          </button>

          {isExportMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-60 bg-[#141414] border border-white/10 rounded-xl shadow-2xl p-1.5 z-40 flex flex-col gap-1 text-xs font-mono animate-in fade-in duration-150">
              <button
                onClick={() => {
                  if (user?.tier === 'Free') {
                    setIsExportMenuOpen(false);
                    onOpenCheckout?.('Pro');
                    return;
                  }
                  generateAuditPdfReport(safeProject);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <FileText size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold">Executive PDF Report</span>
                    {user?.tier === 'Free' && (
                      <span className="text-[11px] font-mono font-extrabold uppercase px-1 py-0.5 rounded bg-white/10 text-white border border-white/20">
                        PRO
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-[#A1A1AA]">
                    {user?.tier === 'Free' ? `Requires Pro subscription (${priceLabel('Pro')})` : 'Score, gate and findings for stakeholders'}
                  </span>
                </div>
              </button>

              <button
                onClick={async () => {
                  setIsExportMenuOpen(false);
                  // Enterprise owners and workspace members get the white-label SOC 2 report
                  const branding = await fetchOrgBranding().catch(() => null);
                  if (user?.tier !== 'Enterprise' && !branding) {
                    onOpenCheckout?.('Enterprise');
                    return;
                  }
                  generateAuditPdfReport(safeProject, {
                    brandName: branding?.brandName,
                    brandLogoUrl: branding?.brandLogoUrl,
                    includeSoc2: true,
                  });
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <ShieldCheck size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold">White-label SOC 2 Report</span>
                    {user?.tier !== 'Enterprise' && (
                      <span className="text-[11px] font-mono font-extrabold uppercase px-1 py-0.5 rounded bg-white/10 text-white border border-white/20">
                        ENT
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-[#A1A1AA]">Your branding + SOC 2 control mapping</span>
                </div>
              </button>

              <button
                onClick={() => {
                  exportFindingsToCsv(safeProject.findings, safeProject.name);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Table size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">RFC 4180 CSV Export</span>
                  <span className="text-[10px] text-[#A1A1AA]">Import to Jira, Linear &amp; GitHub</span>
                </div>
              </button>

              <button
                onClick={() => {
                  exportScorecardToJson(safeProject);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer border-t border-white/5 pt-1.5"
              >
                <Code size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">JSON Scorecard Payload</span>
                  <span className="text-[10px] text-[#A1A1AA]">CI/CD automation artifact</span>
                </div>
              </button>
            </div>
          )}
        </div>

        {/* Action 3: Audit Tools & Governance Dropdown */}
        <div className="relative" ref={toolsMenuRef}>
          <button
            onClick={() => {
              setIsToolsMenuOpen((prev) => !prev);
              setIsExportMenuOpen(false);
            }}
            className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-2 border-white/10 text-[#EDEDED] hover:bg-white/10 transition-colors cursor-pointer"
            aria-label="Audit Tools and Governance Settings"
          >
            <Sliders size={13} className="text-zinc-400" />
            <span>Audit Tools</span>
            <ChevronDown size={12} className={`text-[#A1A1AA] transition-transform duration-200 ${isToolsMenuOpen ? 'rotate-180' : ''}`} />
          </button>

          {isToolsMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-[#141414] border border-white/10 rounded-xl shadow-2xl p-1.5 z-40 flex flex-col gap-1 text-xs font-mono animate-in fade-in duration-150">
              <button
                onClick={() => {
                  onOpenModal('rules');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Sliders size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Rule Matrix Configurator</span>
                  <span className="text-[10px] text-[#A1A1AA]">Toggle security &amp; UI rule weights</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('briefing');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Award size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Executive Briefing &amp; PDF</span>
                  <span className="text-[10px] text-[#A1A1AA]">Export certified audit PDF &amp; CISO brief</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('compare');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <GitCompare size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Compare Snapshots</span>
                  <span className="text-[10px] text-[#A1A1AA]">Differential regression analysis</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('notif');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Bell size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Webhook Alerts</span>
                  <span className="text-[10px] text-[#A1A1AA]">Slack &amp; Discord dispatch setup</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('cicd');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <GitPullRequest size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">CI/CD &amp; GitHub PR Gate</span>
                  <span className="text-[10px] text-[#A1A1AA]">Automate PR block &amp; Actions workflow</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('manifest');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Server size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Deployment Manifest</span>
                  <span className="text-[10px] text-[#A1A1AA]">Cryptographic release attestation</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('pentest');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <ShieldAlert size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">PenTest Payloads</span>
                  <span className="text-[10px] text-[#A1A1AA]">PoC exploit validation suite</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('badge');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <ShieldCheck size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Release Gate Badge</span>
                  <span className="text-[10px] text-[#A1A1AA]">Live SVG embed for README</span>
                </div>
              </button>

              <button
                onClick={() => {
                  onOpenModal('kb');
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer border-t border-white/10 pt-2"
              >
                <BookOpen size={14} className="text-zinc-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Rule Knowledge Base</span>
                  <span className="text-[10px] text-[#A1A1AA]">Press Cmd+K anytime</span>
                </div>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
