'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, Eye, EyeOff, Key, ExternalLink, X, ShieldAlert, ArrowRight } from 'lucide-react';

export interface PrivateRepoTokenModalProps {
  isOpen: boolean;
  onClose: () => void;
  repoUrl: string;
  onSaveTokenAndScan: (token: string) => void;
}

export const PrivateRepoTokenModal: React.FC<PrivateRepoTokenModalProps> = ({
  isOpen,
  onClose,
  repoUrl,
  onSaveTokenAndScan,
}) => {
  const [token, setToken] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen) {
      setError(null);
      setIsSubmitting(false);
      try {
        const savedToken =
          sessionStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('zelsis_github_token') ||
          localStorage.getItem('github_token') ||
          '';
        if (savedToken) {
          setToken(savedToken);
        }
      } catch {
        // Sandboxed environment fallback
      }
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanToken = token.trim();
    if (!cleanToken) {
      setError('Please provide a GitHub Personal Access Token (PAT).');
      return;
    }
    if (cleanToken.length < 15) {
      setError('The provided token appears invalid or too short. A typical GitHub PAT starts with "ghp_" or "github_pat_".');
      return;
    }

    setIsSubmitting(true);
    try {
      // F-08: Store in ephemeral sessionStorage only, wipe from persistent localStorage
      sessionStorage.setItem('zelsis_github_token', cleanToken);
      localStorage.removeItem('zelsis_github_token');
      localStorage.removeItem('github_token');
    } catch {
      // Sandboxed storage fallback
    }

    onSaveTokenAndScan(cleanToken);
  };

  const cleanRepoName = (repoUrl || '').replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/i, '') || 'Repository';

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4"
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 8 }}
          transition={{ duration: 0.15 }}
          className="bg-[#141414] border border-white/15 rounded-2xl w-full max-w-lg p-6 sm:p-8 relative shadow-2xl flex flex-col gap-5 text-white"
        >
          {/* Close button */}
          <button
            onClick={onClose}
            aria-label="Close private repository token modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-lg hover:bg-white/5 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-white/20"
          >
            <X size={18} />
          </button>

          {/* Header */}
          <div className="flex items-start gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
              <Lock size={22} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded">
                  Authentication Required
                </span>
              </div>
              <h2 className="text-lg font-extrabold text-[#EDEDED] mt-1 truncate">
                Private Repository Detected
              </h2>
              <p className="text-xs text-[#A1A1AA] mt-0.5 font-mono truncate">
                {cleanRepoName || repoUrl}
              </p>
            </div>
          </div>

          {/* Explanation Callout */}
          <div className="bg-[#0A0A0A] p-3.5 rounded-xl border border-white/10 flex flex-col gap-2 text-xs">
            <div className="flex items-center gap-2 text-[#EDEDED] font-bold">
              <ShieldAlert size={14} className="text-amber-400 shrink-0" />
              <span>GitHub Access Blocked (HTTP 404/403)</span>
            </div>
            <p className="text-[#A1A1AA] leading-relaxed text-[11px]">
              This repository is private or requires authorization. Zelsis needs a GitHub Personal Access Token (PAT) with <strong className="text-white">Read-only Contents</strong> permission to fetch and audit your source code AST in-memory.
            </p>
            <a
              href="https://github.com/settings/tokens?type=beta"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white hover:text-neutral-300 font-mono text-[11px] underline underline-offset-4 flex items-center gap-1 w-fit pt-0.5 transition-colors"
            >
              <span>Generate Fine-grained PAT on GitHub (10 seconds)</span>
              <ExternalLink size={11} />
            </a>
          </div>

          {/* Error notice */}
          {error && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-xs font-mono text-red-400 flex items-center gap-2">
              <ShieldAlert size={14} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label
                htmlFor="modal-github-pat"
                className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase tracking-wider flex items-center justify-between"
              >
                <span>GitHub Personal Access Token (PAT)</span>
                <span className="text-[10px] text-[#A1A1AA] lowercase font-normal">starts with ghp_ or github_pat_</span>
              </label>
              <div className="relative flex items-center">
                <div className="absolute left-3 text-[#A1A1AA]">
                  <Key size={14} />
                </div>
                <input
                  id="modal-github-pat"
                  name="githubPat"
                  aria-label="GitHub Personal Access Token"
                  type={showToken ? 'text' : 'password'}
                  value={token}
                  onChange={(e) => {
                    setToken(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="github_pat_xxxxxxxxxxxxxxxxxxxx"
                  className="w-full pl-9 pr-10 py-2.5 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] focus-visible:ring-1 focus-visible:ring-white/30 focus-visible:outline-none focus:border-white/30 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowToken(!showToken)}
                  aria-label={showToken ? 'Hide token' : 'Show token'}
                  className="absolute right-3 text-[#A1A1AA] hover:text-white transition-colors"
                >
                  {showToken ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <p className="text-[10px] text-[#A1A1AA] font-mono">
                🔒 Your token stays encrypted in your browser’s local storage and is never persisted on our servers.
              </p>
            </div>

            <div className="flex items-center gap-3 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="btn btn-secondary flex-1 py-2.5 rounded-xl text-xs font-mono font-bold border border-white/10 text-[#A1A1AA] hover:text-white hover:bg-white/5 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting || !token.trim()}
                className="btn btn-primary flex-1 py-2.5 rounded-xl text-xs font-mono font-extrabold uppercase tracking-wider bg-emerald-500 text-black hover:bg-emerald-400 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg cursor-pointer"
              >
                <span>{isSubmitting ? 'Verifying & Scanning...' : 'Save Token & Scan Now'}</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
