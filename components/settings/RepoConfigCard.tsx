'use client';

import React from 'react';
import { Eye, EyeOff } from 'lucide-react';

interface RepoConfigCardProps {
  repoUrl: string;
  setRepoUrl: (url: string) => void;
  patToken: string;
  setPatToken: (pat: string) => void;
  showPatToken: boolean;
  setShowPatToken: (show: boolean) => void;
  saved: boolean;
  onSaveSettings: (e: React.FormEvent) => void;
}

export const RepoConfigCard: React.FC<RepoConfigCardProps> = ({
  repoUrl,
  setRepoUrl,
  patToken,
  setPatToken,
  showPatToken,
  setShowPatToken,
  saved,
  onSaveSettings,
}) => {
  return (
    <form onSubmit={onSaveSettings} className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col gap-6 shadow-xl">
      <div className="flex flex-col gap-2">
        <label htmlFor="settings-repo-url" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
          <span>Target Repository / Web Deployment URL:</span>
        </label>
        <input
          id="settings-repo-url"
          name="repoUrl"
          aria-label="Target Repository or Web Deployment URL"
          type="text"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repository"
          className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-[#EDEDED] font-mono focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none focus:border-white/20"
        />
      </div>

      <div className="flex flex-col gap-2">
        <label htmlFor="settings-pat-token" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
          <span>GitHub Personal Access Token (PAT) (Optional for Private Repos):</span>
        </label>
        <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-emerald-500 focus-within:ring-2 focus-within:ring-emerald-500">
          <input
            id="settings-pat-token"
            name="patToken"
            aria-label="GitHub Personal Access Token"
            type={showPatToken ? 'text' : 'password'}
            placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            value={patToken}
            onChange={(e) => setPatToken(e.target.value)}
            className="w-full bg-transparent py-1.5 text-xs text-[#EDEDED] font-mono focus-visible:outline-none"
          />
          <button
            type="button"
            onClick={() => setShowPatToken(!showPatToken)}
            aria-label={showPatToken ? 'Hide PAT token' : 'Show PAT token'}
            className="min-h-[44px] min-w-[44px] text-[#A1A1AA] hover:text-white transition-colors flex items-center justify-center shrink-0 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded-lg"
          >
            {showPatToken ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-white/10 flex-wrap gap-3">
        <div className="text-xs text-[#A1A1AA] font-mono">
          {saved ? 'Settings successfully saved to local project state.' : 'Changes take effect immediately on next audit run.'}
        </div>

        <button
          type="submit"
          disabled={saved}
          className="min-h-[44px] px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50 cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
        >
          <span>{saved ? 'Saved!' : 'Save Settings'}</span>
        </button>
      </div>
    </form>
  );
};
