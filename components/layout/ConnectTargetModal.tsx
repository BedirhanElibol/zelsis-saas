'use client';

import React, { useState, useEffect } from 'react';
import { Project } from '@/data/schema';
import { FolderGit2, X, Globe, Eye, EyeOff, Play } from 'lucide-react';
import { isValidGithubUrl, sanitizeTargetUrl } from '@/lib/github-api';
import { isValidWebUrl } from '@/lib/website-scanner';
import { FRAMEWORK_CHOICES, UNDETECTED_FRAMEWORK } from '@/lib/scanner/stack-detect';

interface ConnectTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddNewProject?: (p: Project) => void;
  onSelectProject: (p: Project) => void;
  onTriggerScan?: (p: Project) => void;
}

export const ConnectTargetModal: React.FC<ConnectTargetModalProps> = ({
  isOpen,
  onClose,
  onAddNewProject,
  onSelectProject,
  onTriggerScan
}) => {
  const [targetType, setTargetType] = useState<'GITHUB' | 'WEB'>('GITHUB');
  const [repoName, setRepoName] = useState<string>('');
  const [githubUrl, setGithubUrl] = useState('https://github.com/user/example-app');
  const [webSiteUrl, setWebSiteUrl] = useState('https://my-app.vercel.app');
  const [branch, setBranch] = useState<string>('main');
  const [framework, setFramework] = useState<string>(UNDETECTED_FRAMEWORK);
  const [githubToken, setGithubToken] = useState<string>('');
  const [urlError, setUrlError] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const [isConnecting, setIsConnecting] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen) {
      try {
        const saved =
          sessionStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('github_token') ||
          '';
        if (saved && !githubToken) {
          setGithubToken(saved);
        }
      } catch {
        // Sandboxed storage fallback
      }
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleConnectRepo = (e: React.FormEvent) => {
    e.preventDefault();
    setUrlError('');
    setIsConnecting(true);

    let finalUrl = targetType === 'GITHUB' ? githubUrl : webSiteUrl;
    let customName = repoName.trim();

    const rawCustom = (customName || '').trim();
    if (rawCustom.startsWith('http') || rawCustom.includes('github.com')) {
      const sanitized = sanitizeTargetUrl(rawCustom);
      finalUrl = sanitized;
      const parts = (sanitized || '').replace('https://', '').replace('github.com/', '').split('/');
      customName = parts[1] || parts[0] || 'GitHub Repository';
    }

    const safeFinal = (finalUrl || '').trim();
    const fullUrl = safeFinal.startsWith('http') ? safeFinal : `https://${safeFinal}`;
    const isGithub = isValidGithubUrl(fullUrl);
    const isWeb = isValidWebUrl(fullUrl);

    if (targetType === 'GITHUB' && !isGithub) {
      setUrlError('Invalid GitHub URL format. Please enter a valid repository URL (e.g. "https://github.com/owner/repo").');
      setIsConnecting(false);
      return;
    }
    if (targetType === 'WEB' && !isWeb) {
      setUrlError('Invalid Web App URL format. Please enter a valid website URL (e.g. "https://my-app.vercel.app").');
      setIsConnecting(false);
      return;
    }

    let hostname = 'Target Web App';
    try {
      hostname = new URL(fullUrl).hostname || 'Target Web App';
    } catch {
      hostname = 'Target Web App';
    }
    const extractedName = isGithub
      ? ((fullUrl || '').replace('https://', '').replace('github.com/', '').split('/')[1] || 'GitHub Repository')
      : hostname;
    const displayName = customName || extractedName;

    const newProject: Project = {
      id: `proj-${(targetType || 'target').toLowerCase()}-${Date.now()}`,
      name: `${displayName} (${targetType === 'GITHUB' ? branch : 'Live Site'})`,
      repoUrl: fullUrl,
      githubToken: githubToken.trim() || undefined,
      framework,
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

    const cleanToken = githubToken.trim();
    if (cleanToken) {
      try {
        sessionStorage.setItem('zelsis_github_token', cleanToken);
        localStorage.removeItem('zelsis_github_token');
        localStorage.removeItem('github_token');
      } catch {
        // Sandboxed storage fallback
      }
    }

    if (onAddNewProject) {
      onAddNewProject(newProject);
    }
    onSelectProject(newProject);
    if (onTriggerScan) {
      onTriggerScan(newProject);
    }
    setIsConnecting(false);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-[#141414] border border-white/10 rounded-2xl w-full max-w-lg p-6 sm:p-8 relative shadow-lg">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-[#A1A1AA] hover:text-white"
        >
          <X size={20} />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
            {targetType === 'GITHUB' ? <FolderGit2 size={22} className="text-white" /> : <Globe size={22} className="text-[#3B82F6]" />}
          </div>
          <div>
            <h2 className="text-lg font-extrabold text-[#EDEDED]">
              Connect Target
            </h2>
            <p className="text-xs text-[#A1A1AA]">
              Select a GitHub repository or live deployment endpoint.
            </p>
          </div>
        </div>

        {urlError && (
          <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-xs font-mono text-red-400">
            {urlError}
          </div>
        )}

        <form onSubmit={handleConnectRepo} className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-2 bg-[#0A0A0A] p-1 rounded-xl border border-white/10">
            <button
              type="button"
              onClick={() => setTargetType('GITHUB')}
              className={`py-2 text-xs font-mono font-bold rounded-lg transition-colors ${
                targetType === 'GITHUB' ? 'bg-white/10 text-white' : 'text-[#A1A1AA] hover:text-white'
              }`}
            >
              GitHub Repository
            </button>
            <button
              type="button"
              onClick={() => setTargetType('WEB')}
              className={`py-2 text-xs font-mono font-bold rounded-lg transition-colors ${
                targetType === 'WEB' ? 'bg-white/10 text-white' : 'text-[#A1A1AA] hover:text-white'
              }`}
            >
              Live Web Endpoint
            </button>
          </div>

          <div className="flex flex-col gap-1">
            <label htmlFor="target-project-name" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Target Display Name (Optional)</label>
            <input
              id="target-project-name"
              name="repoName"
              aria-label="Target Display Name"
              type="text"
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="e.g. My Next.js SaaS App"
              className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
            />
          </div>

          {targetType === 'GITHUB' ? (
            <>
              <div className="flex flex-col gap-1">
                <label htmlFor="target-github-url" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">GitHub Repository URL *</label>
                <input
                  id="target-github-url"
                  name="githubUrl"
                  aria-label="GitHub Repository URL"
                  type="text"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/user/my-saas"
                  className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1">
                  <label htmlFor="target-branch" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Branch</label>
                  <input
                    id="target-branch"
                    name="branch"
                    aria-label="Branch"
                    type="text"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <label htmlFor="target-framework-select" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Framework</label>
                  <select
                    id="target-framework-select"
                    name="framework"
                    aria-label="Framework"
                    value={framework}
                    onChange={(e) => setFramework(e.target.value)}
                    className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
                  >
                    {FRAMEWORK_CHOICES.map((choice) => (
                      <option key={choice} value={choice}>{choice}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <label htmlFor="target-github-token" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">
                    GitHub Personal Access Token (PAT)
                  </label>
                  <span className="text-[10px] text-amber-400 font-mono font-medium">
                    Required for Private Repos
                  </span>
                </div>
                <div className="relative flex items-center">
                  <input
                    id="target-github-token"
                    name="githubToken"
                    aria-label="GitHub Personal Access Token (PAT)"
                    type={showToken ? 'text' : 'password'}
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    placeholder="github_pat_... (Required for private repositories)"
                    className="w-full px-3 py-2 pr-10 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    aria-label={showToken ? 'Hide PAT token' : 'Show PAT token'}
                    className="absolute right-3 text-[#A1A1AA] hover:text-white transition-colors"
                  >
                    {showToken ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                <p className="text-[10px] text-[#A1A1AA] font-mono">
                  Optional for public repositories. Required with read permission for private repositories.
                </p>
              </div>
            </>
          ) : (
            <div className="flex flex-col gap-1">
              <label htmlFor="target-website-url" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Live Web App Endpoint URL *</label>
              <input
                id="target-website-url"
                name="webSiteUrl"
                aria-label="Live Web App Endpoint URL"
                type="text"
                value={webSiteUrl}
                onChange={(e) => setWebSiteUrl(e.target.value)}
                placeholder="https://my-app.vercel.app"
                className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={isConnecting}
            className="mt-2 btn btn-primary py-3 text-xs uppercase tracking-wider font-extrabold w-full rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
          >
            <Play size={13} fill="currentColor" />
            <span>{isConnecting ? 'Connecting & Auditing...' : 'Connect & Run Audit'}</span>
          </button>
        </form>
      </div>
    </div>
  );
};
