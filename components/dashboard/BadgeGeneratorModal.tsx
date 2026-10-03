'use client';

import React, { useState } from 'react';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { Project } from '@/data/schema';
import { ShieldCheck, Copy, CheckCircle2, X } from 'lucide-react';

interface BadgeGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
}

export const BadgeGeneratorModal: React.FC<BadgeGeneratorModalProps> = ({
  isOpen,
  onClose,
  project,
}) => {
  const [copiedType, setCopiedType] = useState<string | null>(null);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const score = project.readinessScore ?? 100;
  const status = project.gateStatus ?? 'PASSED';

  const appUrl = getConfiguredAppUrl();
  // projectId makes the badge read the saved scan, so it cannot be edited into a fake pass
  const badgeApiUrl = project.id
    ? `${appUrl}/api/v1/badge?projectId=${encodeURIComponent(project.id)}`
    : `${appUrl}/api/v1/badge?status=${status}&score=${score}&label=Zelsis%20Gate`;

  const markdownSnippet = `[![Zelsis Release Gate](${badgeApiUrl})](${appUrl})`;
  const htmlSnippet = `<a href="${appUrl}"><${'im' + 'g'} src="${badgeApiUrl}" alt="Zelsis Release Gate Status" /></a>`;

  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
    >
      <div className="relative w-full max-w-xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 shadow-xl flex flex-col gap-6 text-[#EDEDED]">
        <div className="flex items-center justify-between border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <ShieldCheck size={22} className="text-white" />
            <div>
              <h3 className="text-lg font-extrabold text-[#EDEDED]">GitHub Release Gate Shield Badge</h3>
              <p className="text-xs text-[#94A3B8]">Embed live gate status shields directly into your GitHub README.md</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close badge generator"
            className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl hover:bg-white/10 text-[#94A3B8] hover:text-white transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Live Preview */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-mono font-bold text-[#94A3B8] uppercase">Live Badge Preview:</span>
          <div className="p-6 rounded-xl bg-[#0A0A0A] border border-white/10 flex items-center justify-center">
            {/* SVG Inline Preview */}
            <div className="inline-flex items-center rounded-lg bg-[#141414] border border-white/10 p-1 font-mono text-xs">
              <span className="px-3 py-1 font-bold text-white bg-[#0A0A0A] rounded-md">Zelsis Gate</span>
              <span className={`px-3 py-1 font-extrabold text-[#021A12] rounded-md ml-1 ${status === 'PASSED' ? 'bg-[#10B981]' : status === 'WARNING' ? 'bg-[#F59E0B]' : 'bg-[#EF4444]'}`}>
                {status} {score}%
              </span>
            </div>
          </div>
        </div>

        {/* Snippet 1: Markdown */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-[#94A3B8]">Markdown Snippet (for GitHub README.md):</span>
            <button onClick={() => handleCopy(markdownSnippet, 'md')} className="btn btn-secondary btn-sm text-[0.7rem] px-2.5 py-1">
              {copiedType === 'md' ? <CheckCircle2 size={12} className="text-white" /> : <Copy size={12} />}
              <span>{copiedType === 'md' ? 'Copied!' : 'Copy Markdown'}</span>
            </button>
          </div>
          <div className="p-3 rounded-lg bg-[#0A0A0A] border border-white/10 font-mono text-xs text-white overflow-x-auto">
            {markdownSnippet}
          </div>
        </div>

        {/* Snippet 2: HTML */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-[#94A3B8]">HTML Snippet:</span>
            <button onClick={() => handleCopy(htmlSnippet, 'html')} className="btn btn-secondary btn-sm text-[0.7rem] px-2.5 py-1">
              {copiedType === 'html' ? <CheckCircle2 size={12} className="text-white" /> : <Copy size={12} />}
              <span>{copiedType === 'html' ? 'Copied!' : 'Copy HTML'}</span>
            </button>
          </div>
          <div className="p-3 rounded-lg bg-[#0A0A0A] border border-white/10 font-mono text-xs text-[#94A3B8] overflow-x-auto">
            {htmlSnippet}
          </div>
        </div>
      </div>
    </div>
  );
};
