'use client';

import React, { useState } from 'react';
import { Project, Finding } from '@/data/schema';
import { ShieldCheck, Palette, Layers, Activity, AlertTriangle, ArrowRight, Play, Copy, CheckCircle2, X, Loader2 } from 'lucide-react';

export interface DemoShowcaseBannerProps {
  onFocusQuickAudit?: () => void;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onDismiss?: () => void;
}

export const DemoShowcaseBanner: React.FC<DemoShowcaseBannerProps> = ({
  onFocusQuickAudit,
  onOpenAuth,
  onDismiss,
}) => {
  const [repoInput, setRepoInput] = useState('');
  const [isDismissed, setIsDismissed] = useState(false);
  const [isPending, setIsPending] = useState(false);

  if (isDismissed) return null;

  const handleAuditClick = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsPending(true);
    try {
      if (repoInput.trim() && onFocusQuickAudit) {
        // Pass the repoInput logic outwards if needed, or simply focus the target input and set its value.
        const targetInput = document.querySelector('input[aria-label="Target repository or deployment URL"]') as HTMLInputElement | null;
        if (targetInput) {
          targetInput.value = repoInput;
          // trigger a change event to update the react state
          const event = new Event('input', { bubbles: true });
          targetInput.dispatchEvent(event);
        }
        await onFocusQuickAudit();
      } else {
        if (onFocusQuickAudit) await onFocusQuickAudit();
      }
    } finally {
      setIsPending(false);
    }
  };

  const handleClose = () => {
    setIsDismissed(true);
    onDismiss?.();
  };

  return (
    <div className="relative overflow-hidden rounded-xl border border-white/10 bg-[#141414] shadow-lg flex flex-col p-0">
      <div className="p-4 sm:p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3.5 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center shrink-0 text-zinc-300">
            <Layers size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-white/10 border border-white/15 text-zinc-200 tracking-wider uppercase">
                Kayıtsız Hızlı Deneme / INTERACTIVE DEMO PREVIEW
              </span>
            </div>
            <p className="text-xs sm:text-sm text-zinc-300 max-w-2xl leading-relaxed m-0">
              You are exploring a sample pre-flight audit for <strong className="text-white font-semibold">Production Web App</strong>. Run a fast, unregistered audit on any public repository to see Zelsis in action.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 self-end md:self-center">
          <button
            type="button"
            onClick={() => onOpenAuth?.('signup')}
            className="btn btn-primary text-xs font-mono font-bold px-3.5 py-1.5 rounded-lg bg-white text-black hover:bg-neutral-200 transition-colors shadow-sm"
          >
            Sign Up Free
          </button>
          <button
            type="button"
            onClick={handleClose}
            className="p-1.5 rounded-lg text-[#A1A1AA] hover:text-white hover:bg-white/5 transition-colors shrink-0"
            aria-label="Dismiss Demo Preview Banner"
          >
            <X size={16} />
          </button>
        </div>
      </div>
      
      {/* Quick Scan Input Form */}
      <div className="bg-black/40 border-t border-white/5 p-4 flex items-center gap-3">
        <form onSubmit={handleAuditClick} className="flex items-center gap-2 w-full max-w-xl">
          <input
            type="text"
            placeholder="https://github.com/your-org/your-repo"
            value={repoInput}
            aria-label="Target repository URL"
            onChange={(e) => setRepoInput(e.target.value)}
            className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-4 py-2 text-sm font-mono text-white focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
          />
          <button
            type="submit"
            disabled={isPending}
            className="btn btn-secondary text-xs font-mono font-bold px-4 py-2 rounded-lg border-white/10 hover:bg-white/5 text-white flex items-center gap-1.5 transition-colors shrink-0 disabled:opacity-50"
          >
            {isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play size={13} fill="currentColor" />}
            <span>{isPending ? 'Starting...' : 'Hızlı Analiz (Quick Scan)'}</span>
          </button>
        </form>
        <span className="text-[10px] text-zinc-400 font-mono ml-auto hidden sm:block">No account required</span>
      </div>
    </div>
  );
};

interface OverviewViewProps {
  project: Project;
  onTriggerScan: () => void;
  onInspectFinding: (f: Finding) => void;
  onNavigateTab: (tab: unknown) => void;
  user?: { isLoggedIn?: boolean } | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onFocusQuickAudit?: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  project,
  onTriggerScan,
  onInspectFinding,
  onNavigateTab,
  user,
  onOpenAuth,
  onFocusQuickAudit,
}) => {
  const [copiedMaster, setCopiedMaster] = useState(false);
  const [isDemoBannerDismissed, setIsDemoBannerDismissed] = useState(false);

  const isGuest = !user || !user.isLoggedIn;

  const openFindings = project.findings.filter(f => f.status === 'OPEN');
  const criticals = openFindings.filter(f => f.severity === 'CRITICAL');
  const highs = openFindings.filter(f => f.severity === 'HIGH');

  const openUiCliches = openFindings.filter((f) => f.type === 'VIBEPOLISH').length;
  const uiCleanCount = Math.max(0, 30 - openUiCliches);

  const masterFixPrompt = `Act as an Expert Full-Stack Security & Software Architect.
Audit target project "${project.name}" (${project.framework}).
Resolve all ${openFindings.length} open release blockers:

${openFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.filePath})
   Remediation: ${f.remediationPrompt}`).join('\n\n')}`;

  const copyMasterPrompt = () => {
    navigator.clipboard.writeText(masterFixPrompt);
    setCopiedMaster(true);
    setTimeout(() => setCopiedMaster(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Interactive Demo Showcase Banner for Guests */}
      {isGuest && !isDemoBannerDismissed && (
        <DemoShowcaseBanner
          onFocusQuickAudit={onFocusQuickAudit}
          onOpenAuth={onOpenAuth}
          onDismiss={() => setIsDemoBannerDismissed(true)}
        />
      )}

      {/* Top Banner / Gate Status Card */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{
        padding: '24px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '16px',
            background: project.gateStatus === 'FAILED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(20, 184, 166, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${project.gateStatus === 'FAILED' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`
          }}>
            {project.gateStatus === 'FAILED' ? <AlertTriangle size={32} color="#EF4444" /> : <ShieldCheck size={32} color="#10B981" />}
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Release Readiness Audit Evaluation
            </div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#EDEDED', margin: '2px 0 6px 0' }}>
              {project.name} · <span style={{ color: project.gateStatus === 'FAILED' ? '#EF4444' : '#10B981' }}>GATE STATUS: {project.gateStatus}</span>
            </h1>
            <p style={{ fontSize: '0.875rem', color: '#A1A1AA', maxWidth: '650px', margin: 0 }}>
              {project.gateStatus === 'FAILED'
                ? `Release BLOCKED. Detected ${criticals.length} Critical & ${highs.length} High severity security vulnerabilities in ${project.framework} stack.`
                : `Production Audit PASSED. ${project.name} complies with OWASP Security Pre-flight Checks and VibePolish & AI Anti-Pattern rules.`}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button className="btn btn-secondary" onClick={copyMasterPrompt}>
            {copiedMaster ? <CheckCircle2 size={16} color="#10B981" /> : <Copy size={16} />}
            <span>{copiedMaster ? 'Prompt Copied!' : 'Copy Master Fix Prompt'}</span>
          </button>

          <button className="btn btn-primary" onClick={() => onTriggerScan?.()}>
            <Play size={16} fill="#FFF" />
            <span>Run New Audit</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
        {/* Metric 1: Readiness Score */}
        <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>Overall Score</span>
            <Activity size={18} className="text-zinc-400" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: project.readinessScore < 50 ? '#EF4444' : project.readinessScore < 85 ? '#F59E0B' : '#EDEDED' }}>
            {project.readinessScore} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#A1A1AA', marginTop: '6px' }}>
            Combined Security + UI + Health score
          </div>
        </div>

        {/* Metric 2: Security Checks */}
        <div
          role="button"
          tabIndex={0}
          className="bg-[#141414] border border-white/10 rounded-xl focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
          style={{ padding: '20px', cursor: 'pointer' }}
          onClick={() => onNavigateTab('security')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateTab('security');
            }
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>Security Pre-Flight</span>
            <ShieldCheck size={18} className="text-zinc-400" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#EDEDED' }}>
            {criticals.length + highs.length === 0 ? '100%' : `${criticals.length + highs.length} Open`} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>{criticals.length + highs.length === 0 ? 'Passed' : 'Issues'}</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#EF4444', marginTop: '6px', fontWeight: 600 }}>
            {criticals.length} Critical &amp; {highs.length} High Risks Open
          </div>
        </div>

        {/* Metric 3: VibePolish UI Matrix */}
        <div
          role="button"
          tabIndex={0}
          className="bg-[#141414] border border-white/10 rounded-xl focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
          style={{ padding: '20px', cursor: 'pointer' }}
          onClick={() => onNavigateTab('vibepolish')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateTab('vibepolish');
            }
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>VibePolish UI</span>
            <Palette size={18} className="text-zinc-400" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#F8FAFC' }}>
            {openUiCliches === 0 ? '100%' : `${openUiCliches} Open`} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>{openUiCliches === 0 ? 'Clean' : 'Findings'}</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: openUiCliches > 0 ? '#EF4444' : '#A1A1AA', marginTop: '6px', fontWeight: 600 }}>
            {openUiCliches > 0 ? `${openUiCliches} UI Cliché Findings Open` : 'VibePolish UI Rules Cleared'}
          </div>
        </div>

        {/* Metric 4: AI Master Slop Matrix */}
        <div
          role="button"
          tabIndex={0}
          className="bg-[#141414] border border-white/10 rounded-xl focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
          style={{ padding: '20px', cursor: 'pointer' }}
          onClick={() => onNavigateTab('aimaster')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateTab('aimaster');
            }
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>AI Master Matrix</span>
            <Layers size={18} className="text-zinc-400" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#F8FAFC' }}>
            {200 - project.uiClicheCount} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 200 Clean</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#F59E0B', marginTop: '6px', fontWeight: 600 }}>
            {project.uiClicheCount} Out of 200 Full-Stack Master Rules
          </div>
        </div>
      </div>

      {/* Priority Action Items List */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#F8FAFC', margin: 0 }}>
              Priority Release Blockers
            </h2>
            <div style={{ fontSize: '0.8rem', color: '#A1A1AA', marginTop: '2px' }}>
              Items preventing safe production release for {project.name}
            </div>
          </div>

          <button className="btn btn-secondary btn-sm" onClick={() => onNavigateTab('remediation')}>
            <span>View All Queue ({openFindings.length})</span>
            <ArrowRight size={14} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {openFindings.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: '#10B981', background: 'rgba(16, 185, 129, 0.05)', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
              Zero release blockers. All pre-flight quality checks passed.
            </div>
          ) : (
            openFindings.slice(0, 5).map(f => (
              <div
                key={f.id}
                style={{
                  padding: '16px 20px',
                  borderRadius: '10px',
                  background: 'var(--bg-surface-hover)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '16px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <span className={`badge ${f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                    {f.severity}
                  </span>
                  <div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#F8FAFC' }}>
                      {f.title}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#A1A1AA', fontFamily: 'monospace', marginTop: '2px' }}>
                      {f.filePath} ({f.lineRange})
                    </div>
                  </div>
                </div>

                <button className="btn btn-secondary btn-sm" onClick={() => onInspectFinding(f)}>
                  <span>Inspect &amp; Fix</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
