'use client';

import React, { useActionState, useState } from 'react';
import { Check, Copy, Loader2, ShieldCheck } from 'lucide-react';
import type { Project } from '@/data/schema';
import { disableTrustPage, enableTrustPage } from '@/app/actions/trust-page';
import { initialTrustPageState } from '@/lib/trust-page-state';

/** Turns the project's public /verified/<slug> page on or off, and shows what still blocks a clear result. */
export function TrustPageSection({ project, accessToken }: { project: Project; accessToken: string }) {
  const [enabled, enableAction, enabling] = useActionState(enableTrustPage, initialTrustPageState);
  const [disabled, disableAction, disabling] = useActionState(disableTrustPage, initialTrustPageState);
  const [name, setName] = useState(project.name ?? '');
  const [copied, setCopied] = useState(false);
  const live = enabled.status === 'success' && disabled.status !== 'success' ? enabled.url : undefined;
  const embed = live ? `[![Checked by Zelsis](${live.replace(/\/verified\/.*/, '')}/api/v1/badge?projectId=${project.id})](${live})` : '';

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <section className="border-t border-white/10 pt-5 flex flex-col gap-3" aria-labelledby="trust-page-title">
      <div className="flex items-center gap-2">
        <ShieldCheck size={18} className="text-emerald-400" aria-hidden="true" />
        <h4 id="trust-page-title" className="text-sm font-bold">Public trust page</h4>
      </div>
      <p className="text-xs text-zinc-400">
        A page you can send to customers: when it was last checked and whether critical or high issues are open, by risk area.
        It never shows findings, files or code, and it updates after every scan.
      </p>

      {live ? (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2">
            <code className="text-xs text-zinc-200 truncate flex-1">{live}</code>
            <button type="button" onClick={() => copy(live)} aria-label="Copy trust page link"
              className="p-1.5 rounded text-zinc-400 hover:text-white hover:bg-white/5 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
              {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
            </button>
          </div>
          <p role="status" className={`text-xs ${enabled.blockers ? 'text-amber-300' : 'text-emerald-400'}`}>{enabled.message}</p>
          {project.id && (
            <button type="button" onClick={() => copy(embed)} className="self-start text-xs text-zinc-300 underline underline-offset-4 hover:text-white">
              Copy README badge that links here
            </button>
          )}
          <form action={disableAction} className="self-start">
            <input type="hidden" name="accessToken" value={accessToken} />
            <input type="hidden" name="projectId" value={project.id ?? ''} />
            <button type="submit" disabled={disabling}
              className="text-xs text-zinc-400 hover:text-red-400 underline underline-offset-4 disabled:opacity-60 flex items-center gap-1.5">
              {disabling && <Loader2 size={12} className="animate-spin" aria-hidden="true" />}
              Turn the trust page off
            </button>
          </form>
        </div>
      ) : (
        <form action={enableAction} className="flex flex-col sm:flex-row gap-2">
          <input type="hidden" name="accessToken" value={accessToken} />
          <input type="hidden" name="projectId" value={project.id ?? ''} />
          <label className="sr-only" htmlFor="trust-display-name">Name shown on the page</label>
          <input id="trust-display-name" name="displayName" value={name} onChange={(e) => setName(e.target.value)} maxLength={80}
            placeholder="Name customers know"
            className="flex-1 min-h-11 px-3 rounded-lg bg-[#0A0A0A] border border-white/10 text-sm text-white focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none" />
          <button type="submit" disabled={enabling || !accessToken || !name.trim()}
            className="px-4 min-h-11 rounded-lg bg-white text-black text-sm font-bold hover:bg-zinc-200 disabled:opacity-60 flex items-center justify-center gap-2 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
            {enabling && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
            Publish page
          </button>
        </form>
      )}
      {enabled.status === 'error' && <p role="alert" className="text-xs text-red-400">{enabled.message}</p>}
      {disabled.status === 'error' && <p role="alert" className="text-xs text-red-400">{disabled.message}</p>}
      {disabled.status === 'success' && <p role="status" className="text-xs text-zinc-300">{disabled.message}</p>}
    </section>
  );
}
