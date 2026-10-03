'use client';

import React, { useState, useEffect } from 'react';
import { Project } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/demo-data';
import { FolderGit2, Plus, ArrowRight, Play, ExternalLink, ShieldCheck, Trash2, Layers, Lock, X } from 'lucide-react';
import { NewProjectModal } from '@/components/projects/NewProjectModal';
import { UserProfile } from '@/components/auth/AuthModal';
import { priceLabel } from '@/data/pricing-plans';

interface ProjectsViewProps {
  projects: Project[];
  onSelectProject: (p: Project) => void;
  onAddNewProject: (p: Project) => void;
  onTriggerScan: (projectOverride?: Project) => void;
  onDeleteProject?: (id: string) => void;
  user?: UserProfile | null;
  onOpenCheckout?: () => void;
}

export const ProjectsView: React.FC<ProjectsViewProps> = ({
  projects,
  onSelectProject,
  onAddNewProject,
  onTriggerScan,
  onDeleteProject,
  user,
  onOpenCheckout
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isQuotaModalOpen, setIsQuotaModalOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isQuotaModalOpen) setIsQuotaModalOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isQuotaModalOpen]);

  const isFree = !user || user.tier === 'Free';
  const customProjects = projects.filter(
    (p) => !p.id.startsWith('proj-preset') && p.id !== 'proj-shipguard-self' && p.id !== 'proj-saas-starter' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-react-core'
  );
  const isAtFreeLimit = isFree && customProjects.length >= 1;

  const handleConnectClick = () => {
    if (isAtFreeLimit) {
      setIsQuotaModalOpen(true);
    } else {
      setIsModalOpen(true);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-[#141414] p-6 sm:p-8 shadow-lg">
        <div className="relative z-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-white/5 border border-white/10 text-white shadow-lg">
                <FolderGit2 size={22} />
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                Connected AI Applications
              </h1>
            </div>
            <p className="text-sm text-[#A1A1AA] max-w-2xl leading-relaxed">
              Connect AI-generated repositories or Vercel preview URLs for automated production release gate audits.
            </p>
          </div>

          <button
            className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm bg-white text-black hover:bg-neutral-200 shadow-lg transition-all duration-200 shrink-0 cursor-pointer"
            onClick={handleConnectClick}
          >
            <Plus size={18} strokeWidth={2.5} />
            <span>Connect New AI App</span>
          </button>
        </div>
      </div>

      {/* Quick Target Presets Bar */}
      <div className="rounded-xl border border-white/10 bg-[#141414] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-white tracking-wider uppercase">
          <Layers size={14} />
          <span>Quick Target Presets:</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: 'proj-preset-nextjs',
                name: 'Enterprise Backend (Django/Go)',
                repoUrl: 'https://github.com/vercel/next.js',
                previewUrl: 'https://demo.zelsis.com',
                framework: 'Next.js 15 + Tailwind',
                providers: ['PostgreSQL', 'Prisma', 'Stripe', 'Vercel'],
                lastScanAt: 'Just now',
                readinessScore: 88,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 2,
                mediumCount: 2,
                lowCount: 2,
                uiClicheCount: 2,
                findings: MOCK_PROJECTS[0]?.findings || []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>Next.js 15 + Prisma (Postgres)</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: 'proj-preset-fastapi',
                name: 'FastAPI + MySQL API',
                repoUrl: 'https://github.com/tiangolo/fastapi',
                previewUrl: 'https://fastapi.tiangolo.com',
                framework: 'FastAPI (Python)',
                providers: ['Python 3.12', 'MySQL', 'SQLAlchemy', 'Docker'],
                lastScanAt: 'Ready for Audit',
                readinessScore: 92,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 1,
                mediumCount: 1,
                lowCount: 1,
                uiClicheCount: 0,
                findings: []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>FastAPI + SQLAlchemy (MySQL)</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: 'proj-preset-mongodb',
                name: 'Node.js + MongoDB & Redis',
                repoUrl: 'https://github.com/expressjs/express',
                previewUrl: 'https://expressjs.com',
                framework: 'Node.js Microservice',
                providers: ['MongoDB', 'Mongoose', 'Redis Cache', 'Docker'],
                lastScanAt: 'Ready for Audit',
                readinessScore: 91,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 1,
                mediumCount: 1,
                lowCount: 1,
                uiClicheCount: 0,
                findings: []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>Node.js + MongoDB &amp; Redis</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: 'proj-preset-go-postgres',
                name: 'Go + PostgreSQL & Redis (Cloud-Native)',
                repoUrl: 'https://github.com/gin-gonic/gin',
                previewUrl: 'https://gin-gonic.com',
                framework: 'Go + PostgreSQL & Redis',
                providers: ['PostgreSQL', 'Redis Cache', 'Docker Engine', 'AWS / Cloud'],
                lastScanAt: 'Ready for Audit',
                readinessScore: 98,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 1,
                uiClicheCount: 0,
                findings: []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>Go + PostgreSQL &amp; Redis (Cloud-Native)</span>
          </button>
        </div>
      </div>

      {/* Projects Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {projects.length === 0 ? (
          <div className="col-span-full py-16 px-6 text-center rounded-2xl border border-dashed border-white/15 bg-[#0D0D14] flex flex-col items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-white">
              <FolderGit2 size={24} />
            </div>
            <div>
              <h3 className="text-base font-bold text-white mb-1">No AI Applications Connected Yet</h3>
              <p className="text-xs text-[#A1A1AA] max-w-md">
                Connect your GitHub repository or preview URL to run automated OWASP security and VibePolish audits.
              </p>
            </div>
            <button
              onClick={() => setIsModalOpen(true)}
              className="btn btn-primary px-4 py-2 text-xs font-bold uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400"
            >
              Connect First App
            </button>
          </div>
        ) : (
          projects.map((p) => {
            const isFailed = p.gateStatus === 'FAILED';
            const isWarning = p.gateStatus === 'WARNING';

            return (
              <div
                key={p.id}
                className="group relative flex flex-col justify-between rounded-2xl border border-white/10 bg-[#0D0D14] hover:bg-[#11111B] p-5 transition-all duration-200 hover:border-white/20 hover:shadow-lg min-h-[14rem]"
              >
                <div>
                  {/* Top Status & Framework Bar */}
                  <div className="flex items-center justify-between mb-4">
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-bold tracking-wide border ${
                        isFailed
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                          : isWarning
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                          : 'bg-white/5 text-white border-white/10'
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${isFailed ? 'bg-rose-400' : isWarning ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                      <span>GATE: {p.gateStatus}</span>
                    </span>

                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md text-[11px] font-mono font-medium bg-white/5 border border-white/10 text-[#A1A1AA]">
                        {p.framework}
                      </span>
                      {onDeleteProject && (
                        <button
                          onClick={() => {
                            if (confirm(`Remove "${p.name}" from saved projects?`)) {
                              onDeleteProject(p.id);
                            }
                          }}
                          className="p-1 rounded-lg text-[#A1A1AA] hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                          title="Delete Project"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Project Name & Repo Link */}
                  <h2 className="text-base font-extrabold text-white truncate mb-1" title={p.name}>
                    {p.name}
                  </h2>
                  <div className="flex items-center gap-1.5 text-xs font-mono text-[#A1A1AA] truncate mb-4">
                    <ExternalLink size={12} className="shrink-0 text-white/50" />
                    <span className="truncate">{p.repoUrl}</span>
                  </div>

                  {/* Clean direct score indicator without count-up animation */}
                  <div className="flex items-center justify-between py-2 border-t border-white/10 text-xs font-mono">
                    <span className="text-[#A1A1AA]">Readiness Score:</span>
                    <span className={`font-extrabold ${isFailed ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {p.readinessScore}%
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs font-mono text-[#A1A1AA]">
                    <span>Open Findings:</span>
                    <span className="font-bold text-white">{p.findings.length}</span>
                  </div>
                </div>

                {/* Footer Action Buttons */}
                <div className="flex items-center gap-2 pt-4 border-t border-white/10 mt-4">
                  <button
                    onClick={() => onSelectProject(p)}
                    className="flex-1 py-2 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/10 text-white flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <span>View Findings</span>
                    <ArrowRight size={13} />
                  </button>

                  <button
                    onClick={() => {
                      onSelectProject(p);
                      onTriggerScan(p);
                    }}
                    className="px-3 py-2 rounded-lg text-xs font-mono font-bold bg-white text-black hover:bg-neutral-200 flex items-center justify-center gap-1 transition-colors"
                    title="Run Release Gate Audit"
                  >
                    <Play size={12} fill="#0A0A0A" />
                    <span>Audit</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      <NewProjectModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onAddNewProject={onAddNewProject}
      />

      {/* Free Tier Project Limit Modal */}
      {isQuotaModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150"
          onClick={(e) => { if (e.target === e.currentTarget) setIsQuotaModalOpen(false); }}
        >
          <div className="bg-[#141414] border border-white/20 rounded-2xl w-full max-w-md p-6 sm:p-8 flex flex-col gap-5 shadow-2xl relative">
            <button
              type="button"
              aria-label="Close"
              onClick={() => setIsQuotaModalOpen(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-[#71717A] hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
            >
              <X size={16} aria-hidden="true" />
            </button>

            <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center">
              <Lock size={22} />
            </div>

            <div className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                  Quota Limit: 1/1 Project
                </span>
              </div>
              <h2 className="text-lg sm:text-xl font-extrabold text-white">
                Free Tier Project Limit Reached
              </h2>
              <p className="text-xs text-[#A1A1AA] leading-relaxed mt-1">
                The Free plan supports up to <strong>1 active custom repository</strong>. Upgrade to <strong>Zelsis Pro</strong> for unlimited connected AI repositories, automated GitHub PR release gates, and AI auto-remediations.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => {
                  setIsQuotaModalOpen(false);
                  if (onOpenCheckout) {
                    onOpenCheckout();
                  }
                }}
                className="w-full sm:flex-1 py-3 px-4 rounded-xl bg-white text-black font-extrabold text-xs uppercase tracking-wider hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 cursor-pointer font-mono"
              >
                <ArrowRight size={14} />
                <span>Upgrade to Pro ({priceLabel('Pro')})</span>
              </button>
              <button
                type="button"
                onClick={() => setIsQuotaModalOpen(false)}
                className="w-full sm:w-auto py-3 px-4 rounded-xl bg-white/5 hover:bg-white/10 text-[#A1A1AA] hover:text-white font-bold text-xs transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
