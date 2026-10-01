'use client';

import React, { useState } from 'react';
import { Finding, UserTier } from '@/data/schema';
import { DEMO_AUDIT_FINDINGS } from '@/data/mockData';
import { BulkFixModal } from './BulkFixModal';
import { Search, Filter, ArrowRight, Layers, Check, RotateCcw, Play, Copy, Lock, ShieldCheck, Database, Server, Sliders, AlertOctagon, GitCommit, ChevronDown, SearchX, ExternalLink } from 'lucide-react';
import { ClipboardToastBadge, useClipboardToast } from '../ui/Toast';
import { safeLower, safeString, safeTrim, safeReplace } from '@/lib/safe-utils';
import { hasFixPromptAccess } from '@/lib/subscription-utils';

interface FindingsTableProps {
  findings: Finding[];
  onInspectFinding: (f: Finding) => void;
  onTriggerScan?: () => void;
  onLoadDemoFindings?: (demoFindings: Finding[]) => void;
  onCopyPrompt?: () => void;
  copiedPrompt?: boolean;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onInspectFinding,
  onTriggerScan,
  onLoadDemoFindings,
  onCopyPrompt,
  copiedPrompt,
  userTier,
  onOpenCheckout,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [pillarFilter, setPillarFilter] = useState<string>('ALL');
  const [hasDiffOnly, setHasDiffOnly] = useState<boolean>(false);
  const [isBulkOpen, setIsBulkOpen] = useState(false);
  const [expandedCardIds, setExpandedCardIds] = useState<Set<string>>(new Set());

  const {
    showToast,
    isVisible: isToastVisible,
    message: toastMessage,
    badge: toastBadge,
    hideToast,
  } = useClipboardToast();

  const toggleCardExpand = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedCardIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const canUseFixPrompts = hasFixPromptAccess(userTier);

  const handleCopyFindingPrompt = (e: React.MouseEvent, item: Finding) => {
    e.stopPropagation();
    if (!canUseFixPrompts) {
      onOpenCheckout?.('Pro');
      return;
    }
    const promptText =
      item.remediationPrompt ||
      `Fix vulnerability in ${safeString(item.filePath)} (${safeString(item.lineRange)}): ${safeString(item.title)}`;
    navigator.clipboard.writeText(promptText);
    showToast('AI prompt copied to clipboard', '[COPIED]');
  };

  const safeFindings = Array.isArray(findings) ? findings : [];

  const isScaFinding = (f: Finding) =>
    Boolean(
      f && (
        f.category?.includes('Software Composition Analysis') ||
        f.category?.includes('Open Source License') ||
        (f.ruleId >= 7000 && f.ruleId <= 7050)
      )
    );

  const scaFindingsCount = safeFindings.filter(isScaFinding).length;

  const PILLAR_TABS = [
    { id: 'ALL', label: 'All Findings' },
    { id: 'SECURITY', label: 'Security' },
    { id: 'SCA_DEPS', label: scaFindingsCount > 0 ? `Dependencies (${scaFindingsCount})` : 'Dependencies (SCA)' },
    { id: 'LEGAL_COMPLIANCE', label: 'Legal & Privacy' },
    { id: 'INFRA_DATABASE', label: 'Infra & DB' },
    { id: 'VIBEPOLISH', label: 'VibePolish UI' },
  ];

  const getPillarBadgeStyle = (type: string, category?: string) => {
    if (category?.includes('Software Composition Analysis')) {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
    return type === 'LEGAL_COMPLIANCE'
      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      : type === 'INFRA_DATABASE'
      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
      : type === 'SECURITY'
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
      : type === 'VIBEPOLISH'
      ? 'bg-teal-500/10 text-teal-400 border-teal-500/30'
      : 'bg-blue-500/10 text-blue-400 border-blue-500/30';
  };

  const getSeverityBadgeStyle = (severity: string, type?: string) => {
    if (type === 'VIBEPOLISH' || severity === 'VIBEPOLISH') {
      return 'bg-teal-500/10 text-teal-400 border-teal-500/30';
    }
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  const resetFilters = () => {
    setSearchTerm('');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setPillarFilter('ALL');
    setHasDiffOnly(false);
  };

  // Extract CVE IDs from finding title or remediation prompt for NVD links
  const extractCveIds = (finding: Finding): string[] => {
    const text = `${safeString(finding.title)} ${safeString(finding.remediationPrompt)}`;
    const matches = text.match(/(CVE-\d{4}-\d{4,7})/gi);
    return matches ? [...new Set(matches.map((m) => m.toUpperCase()))] : [];
  };

  const filtered = safeFindings.filter((f) => {
    if (!f) return false;
    const safeSearch = safeLower(safeTrim(searchTerm));
    const titleStr = safeLower(f.title);
    const pathStr = safeLower(f.filePath);
    const catStr = safeLower(f.category);
    const matchesSearch =
      titleStr.includes(safeSearch) ||
      pathStr.includes(safeSearch) ||
      catStr.includes(safeSearch);

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;
    const matchesPillar =
      pillarFilter === 'ALL' ||
      (pillarFilter === 'SCA_DEPS' ? isScaFinding(f) : f.type === pillarFilter);

    return matchesSearch && matchesSeverity && matchesStatus && matchesPillar;
  });

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-6 flex flex-col gap-5 bg-[#141414] border-white/10">
      {/* Snyk-Grade Release Readiness Radar & Category Breakdown Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Security & OWASP */}
        <button
          type="button"
          onClick={() => setPillarFilter(pillarFilter === 'SECURITY' ? 'ALL' : 'SECURITY')}
          className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-2.5 ${
            pillarFilter === 'SECURITY'
              ? 'bg-white/[0.08] border-white/30 shadow-sm'
              : 'bg-[#0E0E10] border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
              <ShieldCheck size={14} className="text-zinc-400" />
              <span>Security &amp; OWASP</span>
            </span>
            <span className="text-[10px] font-mono text-zinc-400 uppercase">Pillar</span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-xl sm:text-2xl font-extrabold font-mono text-white">
              {findings.filter(f => f.type === 'SECURITY').length}
            </span>
            <span className="text-[10px] text-zinc-400 font-mono">
              {findings.filter(f => f.type === 'SECURITY' && f.severity === 'CRITICAL').length} Critical
            </span>
          </div>
          <span className="text-[10px] text-zinc-400 truncate">
            Injection, auth, &amp; API security
          </span>
        </button>

        {/* Card 2: Database & Storage */}
        <button
          type="button"
          onClick={() => setPillarFilter(pillarFilter === 'INFRA_DATABASE' ? 'ALL' : 'INFRA_DATABASE')}
          className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-2.5 ${
            pillarFilter === 'INFRA_DATABASE'
              ? 'bg-white/[0.08] border-white/30 shadow-sm'
              : 'bg-[#0E0E10] border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
              <Database size={14} className="text-zinc-400" />
              <span>Database &amp; Storage</span>
            </span>
            <span className="text-[10px] font-mono text-zinc-400 uppercase">Pillar</span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-xl sm:text-2xl font-extrabold font-mono text-white">
              {findings.filter(f => f.type === 'INFRA_DATABASE' || safeLower(f.category).includes('sql') || safeLower(f.category).includes('rls') || safeLower(f.category).includes('database')).length}
            </span>
            <span className="text-[10px] text-zinc-400 font-mono">
              Postgres &amp; SQL
            </span>
          </div>
          <span className="text-[10px] text-zinc-400 truncate">
            RLS, pools, SQL &amp; data leaks
          </span>
        </button>

        {/* Card 3: Cloud & Docker */}
        <button
          type="button"
          onClick={() => setPillarFilter(pillarFilter === 'LEGAL_COMPLIANCE' ? 'ALL' : 'LEGAL_COMPLIANCE')}
          className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-2.5 ${
            pillarFilter === 'LEGAL_COMPLIANCE'
              ? 'bg-white/[0.08] border-white/30 shadow-sm'
              : 'bg-[#0E0E10] border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
              <Server size={14} className="text-zinc-400" />
              <span>Legal &amp; Privacy</span>
            </span>
            <span className="text-[10px] font-mono text-zinc-400 uppercase">Pillar</span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-xl sm:text-2xl font-extrabold font-mono text-white">
              {findings.filter(f => f.type === 'LEGAL_COMPLIANCE').length}
            </span>
            <span className="text-[10px] text-zinc-400 font-mono">
              GDPR &amp; CCPA
            </span>
          </div>
          <span className="text-[10px] text-zinc-400 truncate">
            Statutory compliance gates
          </span>
        </button>

        {/* Card 4: UX & VibePolish */}
        <button
          type="button"
          onClick={() => setPillarFilter(pillarFilter === 'VIBEPOLISH' ? 'ALL' : 'VIBEPOLISH')}
          className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-2.5 ${
            pillarFilter === 'VIBEPOLISH'
              ? 'bg-white/[0.08] border-white/30 shadow-sm'
              : 'bg-[#0E0E10] border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
              <Sliders size={14} className="text-zinc-400" />
              <span>UX &amp; VibePolish</span>
            </span>
            <span className="text-[10px] font-mono text-zinc-400 uppercase">Pillar</span>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-xl sm:text-2xl font-extrabold font-mono text-white">
              {findings.filter(f => f.type === 'VIBEPOLISH').length}
            </span>
            <span className="text-[10px] text-zinc-400 font-mono">
              WCAG 2.2
            </span>
          </div>
          <span className="text-[10px] text-zinc-400 truncate">
            Design tokens &amp; a11y gates
          </span>
        </button>
      </div>

      {/* Quick Triage Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs font-mono">
        <span className="text-zinc-400 text-[11px] uppercase tracking-wider shrink-0">Quick Triage:</span>
        <button
          type="button"
          onClick={() => { resetFilters(); }}
          className={`px-2.5 py-1 rounded-md border text-[11px] transition-all cursor-pointer shrink-0 ${
            severityFilter === 'ALL' && pillarFilter === 'ALL' && !hasDiffOnly
              ? 'bg-white text-black font-bold border-white'
              : 'bg-[#0E0E10] border-white/10 text-zinc-400 hover:text-white'
          }`}
        >
          All ({findings.length})
        </button>
        <button
          type="button"
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
          className={`px-2.5 py-1 rounded-md border text-[11px] transition-all cursor-pointer shrink-0 flex items-center gap-1 ${
            severityFilter === 'CRITICAL'
              ? 'bg-red-500 text-white font-bold border-red-500 shadow-sm'
              : 'bg-[#0E0E10] border-red-500/30 text-red-400 hover:bg-red-500/10'
          }`}
        >
          <AlertOctagon size={12} />
          <span>Critical Only ({findings.filter(f => f.severity === 'CRITICAL').length})</span>
        </button>
        <button
          type="button"
          onClick={() => setHasDiffOnly(!hasDiffOnly)}
          className={`px-2.5 py-1 rounded-md border text-[11px] transition-all cursor-pointer shrink-0 flex items-center gap-1 ${
            hasDiffOnly
              ? 'bg-white text-black font-bold border-white shadow-sm'
              : 'bg-[#0E0E10] border-white/10 text-zinc-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <GitCommit size={12} />
          <span>Has 1-Click Code Patch ({findings.filter(f => Boolean(f.diffPatch || f.remediationPrompt)).length})</span>
        </button>
      </div>

      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-base sm:text-lg font-extrabold text-[#EDEDED]">
              Audit Findings &amp; Risk Inventory
            </h2>
            {findings.length > 0 && (
              <div className="flex items-center gap-2">
                {onCopyPrompt && (
                  <button
                    type="button"
                    onClick={() => {
                      if (!canUseFixPrompts) {
                        onOpenCheckout?.('Pro');
                        return;
                      }
                      onCopyPrompt();
                      showToast('AI prompt copied to clipboard', '[COPIED]');
                    }}
                    className="btn btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 border-white/10 text-white hover:bg-white/5 transition-colors cursor-pointer"
                    title={canUseFixPrompts ? 'Copy AI master fix prompt' : 'Fix prompts are a Pro feature'}
                  >
                    {!canUseFixPrompts ? (
                      <Lock size={13} className="shrink-0 text-amber-400" />
                    ) : copiedPrompt ? (
                      <Check size={13} className="text-emerald-400" />
                    ) : (
                      <Copy size={13} className="shrink-0" />
                    )}
                    <span>{canUseFixPrompts ? 'Copy Fix Prompt' : 'Copy Fix Prompt (Pro)'}</span>
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => setIsBulkOpen(true)}
                  className="btn btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 border-white/10 text-white hover:bg-white/5 transition-colors cursor-pointer"
                >
                  <Layers size={13} />
                  <span>Bulk Remediate .patch</span>
                </button>
              </div>
            )}
          </div>
          <div className="text-xs text-[#A1A1AA] mt-0.5">
            Operational audit mapping of security vulnerabilities &amp; UI anti-patterns
          </div>
        </div>

        <BulkFixModal
          isOpen={isBulkOpen}
          onClose={() => setIsBulkOpen(false)}
          findings={findings}
          projectName="Target-Project"
          userTier={userTier}
          onOpenCheckout={onOpenCheckout}
        />

        {/* Search & Filters */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          {/* Search */}
          <div className="flex items-center gap-2 bg-[#0A0A0A] px-3 py-1.5 rounded-lg border border-white/10 flex-1 sm:w-64">
            <Search size={14} className="text-[#A1A1AA]" />
            <input
              id="findings-search-input"
              name="findingsSearch"
              aria-label="Search filter input"
              type="text"
              placeholder="Search findings or files..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 w-full placeholder:text-[#A1A1AA] rounded"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-2 bg-[#0A0A0A] px-3 py-1.5 rounded-lg border border-white/10">
            <Filter size={14} className="text-[#A1A1AA]" />
            <select
              aria-label="Filter findings by severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs font-bold text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/20 cursor-pointer rounded"
            >
              <option value="ALL" className="bg-[#141414]">All Severities</option>
              <option value="CRITICAL" className="bg-[#141414] text-[#EF4444]">Critical</option>
              <option value="HIGH" className="bg-[#141414] text-[#F97316]">High</option>
              <option value="MEDIUM" className="bg-[#141414] text-[#F59E0B]">Medium</option>
              <option value="LOW" className="bg-[#141414] text-white">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Category Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-white/5">
        {PILLAR_TABS.map((tab) => {
          const isActive = pillarFilter === tab.id;
          const count =
            tab.id === 'ALL'
              ? findings.length
              : findings.filter((f) => f.type === tab.id).length;
          return (
            <button
              key={tab.id}
              onClick={() => setPillarFilter(tab.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-white text-black font-extrabold shadow-sm'
                  : 'bg-white/5 text-[#A1A1AA] hover:text-white hover:bg-white/10 border border-white/5'
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] ${
                  isActive ? 'bg-black/15 text-black font-bold' : 'bg-white/10 text-[#EDEDED]'
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Mobile Stacked Card View (block md:hidden) */}
      <div className="block md:hidden space-y-3">
        {filtered.length === 0 ? (
          findings.length === 0 ? (
            <div className="p-8 rounded-xl bg-[#0A0A0A] border border-white/10 text-center flex flex-col items-center gap-4">
              {/* Animated green shield */}
              <div className="relative flex items-center justify-center w-14 h-14">
                <div className="absolute inset-0 rounded-full bg-emerald-500/10" />
                <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" className="relative w-10 h-10">
                  <path d="M20 3L5 9v11c0 9.4 6.4 18.2 15 20.4C29.6 38.2 36 29.4 36 20V9L20 3z" fill="rgba(16,185,129,0.15)" stroke="#10b981" strokeWidth="1.5" strokeLinejoin="round"/>
                  <path d="M14 20l4 4 8-8" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-extrabold text-[#EDEDED]">You&apos;re clear to deploy</h3>
                <p className="text-xs text-[#A1A1AA] mt-1 leading-relaxed">
                  No vulnerabilities, dependency risks, or UI anti-patterns detected.
                </p>
              </div>
              <div className="flex flex-col w-full gap-2 pt-1">
                {onLoadDemoFindings && (
                  <button
                    type="button"
                    onClick={() => onLoadDemoFindings(DEMO_AUDIT_FINDINGS)}
                    className="btn btn-primary py-2.5 px-3 text-xs font-bold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
                  >
                    <Layers size={14} />
                    <span>Load 1-Click Demo Template</span>
                  </button>
                )}
                {onTriggerScan && (
                  <button
                    type="button"
                    onClick={() => onTriggerScan?.()}
                    className="btn btn-secondary py-2 px-3 text-xs font-mono font-bold w-full flex items-center justify-center gap-2"
                  >
                    <Play size={13} />
                    <span>Run New Audit Scan</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="p-6 rounded-xl bg-[#0A0A0A] border border-white/10 text-center flex flex-col items-center gap-3">
              <SearchX size={22} className="text-zinc-400" />
              <p className="text-xs text-[#A1A1AA]">
                No findings match the active search or filter rules.{' '}
                <button type="button" onClick={resetFilters} className="text-blue-400 hover:underline font-semibold">Try clearing your filters.</button>
              </p>
              <button
                type="button"
                onClick={resetFilters}
                className="btn btn-secondary btn-sm text-xs font-mono font-bold flex items-center gap-1.5"
              >
                <RotateCcw size={12} />
                <span>Reset Filters</span>
              </button>
            </div>
          )
        ) : (
          filtered.map((item) => {
            const isExpanded = expandedCardIds.has(item.id);
            return (
              <div
                key={item.id}
                className="p-3.5 sm:p-4 rounded-xl bg-[#0A0A0A] border border-white/10 hover:border-white/20 transition-all flex flex-col gap-3"
              >
                {/* Top Row: Severity & Pillar & Status */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span
                      className={`px-2 py-[3px] rounded text-[10px] font-mono font-extrabold uppercase border min-w-[62px] text-center tracking-[0.6px] ${getSeverityBadgeStyle(
                        item.severity,
                        item.type
                      )}`}
                    >
                      {item.severity}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPillarBadgeStyle(
                        item.type,
                        item.category
                      )}`}
                    >
                      {item.category?.includes('Software Composition Analysis')
                        ? 'SCA Dependency'
                        : item.type === 'LEGAL_COMPLIANCE'
                        ? 'Legal & Privacy'
                        : item.type === 'VIBEPOLISH'
                        ? 'VibePolish UI'
                        : item.type}
                    </span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      item.status === 'RESOLVED'
                        ? 'bg-white/5 text-zinc-300 border border-white/10'
                        : 'bg-red-500/10 text-red-400 border border-red-500/30'
                    }`}
                  >
                    {item.status}
                  </span>
                </div>

                {/* Finding Title & Category */}
                <div>
                  <h3 className="text-xs sm:text-sm font-extrabold text-[#EDEDED] leading-snug">
                    {item.title}
                  </h3>
                  <div className="flex flex-wrap items-center gap-2 mt-1">
                    <span className="px-1.5 py-0.5 rounded bg-white/10 text-zinc-300 font-semibold text-[10px]">
                      {item.category}
                    </span>
                  </div>
                </div>

                {/* Relative File Path & Line Range */}
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 min-w-0">
                  <span className="text-zinc-400 shrink-0">Path:</span>
                  <span className="text-zinc-300 truncate" title={item.filePath}>
                    {item.filePath}
                  </span>
                  <span className="text-zinc-400 shrink-0">({item.lineRange})</span>
                </div>

                {/* Compact Expand/Collapse Details Toggle */}
                <div className="border-t border-white/5 pt-2">
                  <button
                    type="button"
                    onClick={(e) => toggleCardExpand(item.id, e)}
                    className="w-full flex items-center justify-between text-[11px] font-mono text-zinc-400 hover:text-white transition-colors cursor-pointer py-0.5"
                    aria-expanded={isExpanded}
                  >
                    <span className="font-semibold">
                      {isExpanded ? 'Hide Remediations & Details' : 'View Remediations & Details'}
                    </span>
                    <ChevronDown
                      size={14}
                      className={`text-zinc-400 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                    />
                  </button>

                  {isExpanded && (
                    <div className="mt-2.5 pt-2.5 border-t border-white/5 flex flex-col gap-2.5 text-xs text-zinc-300 animate-in fade-in duration-150">
                      {item.remediationPrompt && (
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-300 font-bold">
                            Remediation Guidance
                          </span>
                          {canUseFixPrompts ? (
                            <p className="text-[11px] text-zinc-300 leading-relaxed bg-white/[0.02] p-2 rounded-lg border border-white/5">
                              {item.remediationPrompt}
                            </p>
                          ) : (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onOpenCheckout?.('Pro');
                              }}
                              className="text-[11px] text-left text-zinc-400 leading-relaxed bg-white/[0.02] p-2 rounded-lg border border-white/5 flex items-center gap-1.5 hover:text-white transition-colors cursor-pointer"
                            >
                              <Lock size={11} className="shrink-0 text-amber-400" />
                              <span>Fix guidance and copy-paste prompts are included in Zelsis Pro.</span>
                            </button>
                          )}
                        </div>
                      )}

                      {item.snippet && (
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-300 font-bold">
                            Vulnerable Code Snippet
                          </span>
                          <pre className="text-[10px] font-mono text-zinc-300 bg-black/60 p-2.5 rounded-lg border border-white/10 overflow-x-auto">
                            <code>{item.snippet}</code>
                          </pre>
                        </div>
                      )}

                      {item.reproductionSteps && item.reproductionSteps.length > 0 && (
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold">
                            Reproduction Steps
                          </span>
                          <ol className="list-decimal list-inside text-[11px] text-zinc-400 space-y-0.5 pl-1">
                            {item.reproductionSteps.map((step, sIdx) => (
                              <li key={sIdx}>{step}</li>
                            ))}
                          </ol>
                        </div>
                      )}

                      <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 pt-1 flex-wrap gap-1">
                        <span className="flex items-center gap-1.5 flex-wrap">
                          {extractCveIds(item).length > 0 ? (
                            extractCveIds(item).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="cve-link"
                                onClick={(e) => e.stopPropagation()}
                              >
                                {cve} <ExternalLink size={9} />
                              </a>
                            ))
                          ) : (
                            <span>Rule ID: #{item.ruleId}</span>
                          )}
                        </span>
                        <span>Pillar: {item.type}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Action Buttons: "Copy Prompt" and "Inspect Fix" */}
                <div className="pt-2.5 border-t border-white/5 flex items-center gap-2">
                  <button
                    type="button"
                    onClick={(e) => handleCopyFindingPrompt(e, item)}
                    className="btn btn-secondary text-xs px-3 py-2 flex-1 flex items-center justify-center gap-1.5 border-white/10 text-white hover:bg-white/10 transition-colors cursor-pointer font-mono"
                    title={canUseFixPrompts ? 'Copy remediation prompt for this finding' : 'Fix prompts are a Pro feature'}
                  >
                    {canUseFixPrompts ? <Copy size={12} className="shrink-0" /> : <Lock size={12} className="shrink-0 text-amber-400" />}
                    <span>{canUseFixPrompts ? 'Copy Prompt' : 'Copy Prompt (Pro)'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onInspectFinding(item);
                    }}
                    className="btn btn-primary text-xs px-3 py-2 flex-1 flex items-center justify-center gap-1.5 bg-white text-black hover:bg-neutral-200 transition-colors cursor-pointer font-mono font-bold shadow-sm"
                  >
                    <span>Inspect Fix</span>
                    <ArrowRight size={12} className="shrink-0" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Dense B2B Data Table (Desktop md+) */}
      <div className="hidden md:block overflow-x-auto border border-white/10 rounded-xl">
        <table className="w-full text-left text-xs text-[#EDEDED]">
          <thead className="bg-[#0A0A0A] text-[#A1A1AA] uppercase font-mono font-bold border-b border-white/10">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Pillar</th>
              <th className="py-3 px-4">Finding Title</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Affected Area</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-10 text-center">
                  {findings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center gap-4">
                      {/* Animated green shield — desktop */}
                      <div className="relative flex items-center justify-center w-16 h-16">
                        <div className="absolute inset-0 rounded-full bg-emerald-500/10" />
                        <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" className="relative w-11 h-11">
                          <path d="M20 3L5 9v11c0 9.4 6.4 18.2 15 20.4C29.6 38.2 36 29.4 36 20V9L20 3z" fill="rgba(16,185,129,0.15)" stroke="#10b981" strokeWidth="1.5" strokeLinejoin="round"/>
                          <path d="M14 20l4 4 8-8" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                      </div>
                      <div>
                        <h4 className="text-sm font-extrabold text-[#EDEDED]">You&apos;re clear to deploy</h4>
                        <p className="text-xs text-[#A1A1AA] mt-1 max-w-sm">
                          No vulnerabilities, dependency risks, or UI anti-patterns detected.
                        </p>
                      </div>
                      <div className="flex items-center gap-3 pt-2">
                        {onLoadDemoFindings && (
                          <button
                            type="button"
                            onClick={() => onLoadDemoFindings(DEMO_AUDIT_FINDINGS)}
                            className="btn btn-primary btn-sm px-4 py-2 text-xs font-bold flex items-center gap-2"
                          >
                            <Layers size={13} />
                            <span>Load 1-Click Demo Template</span>
                          </button>
                        )}
                        {onTriggerScan && (
                          <button
                            type="button"
                            onClick={() => onTriggerScan?.()}
                            className="btn btn-secondary btn-sm px-4 py-2 text-xs font-bold flex items-center gap-2"
                          >
                            <Play size={13} />
                            <span>Run New Audit Scan</span>
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center gap-2 py-4">
                      <SearchX size={22} className="text-zinc-400" />
                      <p className="text-xs text-[#A1A1AA]">
                        No findings match the selected search or filter rules.{' '}
                        <button type="button" onClick={resetFilters} className="text-blue-400 hover:underline font-semibold">Try clearing your filters.</button>
                      </p>
                      <button
                        type="button"
                        onClick={resetFilters}
                        className="btn btn-secondary btn-sm text-xs font-bold flex items-center gap-1.5"
                      >
                        <RotateCcw size={12} />
                        <span>Clear Filters</span>
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr
                  key={item.id}
                  className="hover:bg-white/[0.04] transition-colors cursor-pointer"
                  onClick={() => onInspectFinding(item)}
                >
                  {/* Severity Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`badge ${
                        item.severity === 'CRITICAL'
                          ? 'badge-critical'
                          : item.severity === 'HIGH'
                          ? 'badge-high'
                          : item.severity === 'MEDIUM'
                          ? 'badge-medium'
                          : 'badge-passed'
                      }`}
                    >
                      {item.severity}
                    </span>
                  </td>

                  {/* Type Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[0.68rem] font-bold font-mono border ${getPillarBadgeStyle(
                        item.type,
                        item.category
                      )}`}
                    >
                      {item.category?.includes('Software Composition Analysis')
                        ? 'SCA Dependency'
                        : item.type === 'LEGAL_COMPLIANCE'
                        ? 'Legal & Privacy'
                        : item.type}
                    </span>
                  </td>

                  {/* Title */}
                  <td className="py-3.5 px-4 font-bold text-[#EDEDED] max-w-xs truncate">
                    {item.title}
                  </td>

                  {/* Category */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-white/10 text-white font-semibold text-[0.7rem]">
                      {item.category}
                    </span>
                  </td>

                  {/* Affected Area / File Path */}
                  <td className="py-3.5 px-4 font-mono text-[#A1A1AA] max-w-xs truncate">
                    {item.filePath} ({item.lineRange})
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[0.7rem] font-bold ${
                        item.status === 'RESOLVED'
                          ? 'bg-white/5 text-white border border-white/10'
                          : 'bg-red-500/10 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>

                  {/* Action */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onInspectFinding(item);
                      }}
                      className="btn btn-secondary btn-sm text-[0.7rem] px-3 py-1"
                    >
                      <span>Inspect</span>
                      <ArrowRight size={12} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Discreet Dark Obsidian Toast for Copy Actions */}
      <ClipboardToastBadge
        isVisible={isToastVisible}
        message={toastMessage}
        badge={toastBadge}
        onDismiss={hideToast}
      />
    </div>
  );
};
