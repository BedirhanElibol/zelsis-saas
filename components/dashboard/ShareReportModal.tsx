'use client';

import React, { useActionState, useEffect, useRef, useState } from 'react';
import { Check, Copy, Link2, Loader2, X } from 'lucide-react';
import type { Project } from '@/data/schema';
import { createReportShare, revokeReportShare } from '@/app/actions/report-share';
import { initialReportShareState } from '@/lib/report-share-state';
import { getActiveUserAuth } from '@/lib/supabase-client';
import { TrustPageSection } from '@/components/dashboard/TrustPageSection';

interface ShareReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
}

/** Creates a read-only /r/<token> link for the project's latest cloud scan, and revokes it. */
export const ShareReportModal: React.FC<ShareReportModalProps> = ({ isOpen, onClose, project }) => {
  const [accessToken, setAccessToken] = useState('');
  const [copied, setCopied] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const [created, createAction, creating] = useActionState(createReportShare, initialReportShareState);
  const [revoked, revokeAction, revoking] = useActionState(revokeReportShare, initialReportShareState);

  useEffect(() => {
    if (!isOpen) return;
    let alive = true;
    void getActiveUserAuth().then(({ accessToken: token }) => { if (alive) setAccessToken(token || ''); });
    // Keep keyboard focus inside the dialog: focus the first control on open, wrap Tab / Shift+Tab at the ends
    const focusable = () => [...(dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([type="hidden"]), [tabindex]:not([tabindex="-1"])') ?? [])];
    setTimeout(() => focusable()[0]?.focus(), 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key !== 'Tab') return;
      const els = focusable();
      if (els.length === 0) return;
      const first = els[0];
      const last = els[els.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', onKey);
    return () => { alive = false; window.removeEventListener('keydown', onKey); };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // The link on screen was turned off (a link created after that has a different token and shows again)
  const isRevoked = revoked.status === 'success' && revoked.token === created.token;
  const link = created.status === 'success' && !isRevoked ? created.url : undefined;
  const copy = async () => {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
    >
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="share-report-title"
        className="relative w-full max-w-lg max-h-[90vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 shadow-xl flex flex-col gap-5 text-[#EDEDED]">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link2 size={20} className="text-white" aria-hidden="true" />
            <div>
              <h3 id="share-report-title" className="text-lg font-extrabold">Share report link</h3>
              <p className="text-xs text-zinc-400">A read-only page with the score and findings of the latest scan of {project.name}.</p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close share dialog"
            className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl hover:bg-white/10 text-zinc-400 hover:text-white focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
            <X size={20} />
          </button>
        </div>

        <ul className="text-xs text-zinc-400 list-disc pl-5 space-y-1">
          <li>Anyone with the link can open it; it is not listed or indexed anywhere.</li>
          <li>It never includes code snippets or fix instructions, so it is safe for private repositories.</li>
          <li>You can turn it off at any time.</li>
        </ul>

        {link ? (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2">
              <code className="text-xs text-zinc-200 truncate flex-1">{link}</code>
              <button type="button" onClick={copy} aria-label="Copy report link"
                className="p-1.5 rounded text-zinc-400 hover:text-white hover:bg-white/5 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
                {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
              </button>
            </div>
            <form action={revokeAction} className="self-start">
              <input type="hidden" name="accessToken" value={accessToken} />
              <input type="hidden" name="token" value={created.token ?? ''} />
              <button type="submit" disabled={revoking}
                className="text-xs text-zinc-400 hover:text-red-400 underline underline-offset-4 disabled:opacity-60 flex items-center gap-1.5">
                {revoking && <Loader2 size={12} className="animate-spin" aria-hidden="true" />}
                Turn this link off
              </button>
            </form>
          </div>
        ) : (
          <form action={createAction}>
            <input type="hidden" name="accessToken" value={accessToken} />
            <input type="hidden" name="projectId" value={project.id ?? ''} />
            <input type="hidden" name="repoUrl" value={project.repoUrl ?? ''} />
            <button type="submit" disabled={creating || !accessToken}
              className="px-4 min-h-11 rounded-lg bg-emerald-500 text-black text-sm font-bold hover:bg-emerald-400 disabled:opacity-60 flex items-center gap-2 focus-visible:ring-2 focus-visible:ring-white focus-visible:outline-none">
              {creating && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
              Create link
            </button>
            {!accessToken && <p className="text-xs text-zinc-400 mt-2">Sign in to share reports.</p>}
          </form>
        )}

        {created.status === 'error' && <p role="alert" className="text-xs text-red-400">{created.message}</p>}
        {revoked.status === 'error' && <p role="alert" className="text-xs text-red-400">{revoked.message}</p>}
        {isRevoked && <p role="status" className="text-xs text-zinc-300">{revoked.message}</p>}

        <TrustPageSection project={project} accessToken={accessToken} />
      </div>
    </div>
  );
};
