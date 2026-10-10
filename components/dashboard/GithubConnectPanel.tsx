'use client';

import React, { useEffect, useState } from 'react';
import { GitBranch, Loader2, RefreshCw } from 'lucide-react';
import { getActiveUserAuth } from '@/lib/supabase-client';

/** Shown only when the Zelsis GitHub App is configured for this deployment. */
export const GITHUB_APP_ENABLED = Boolean(process.env.NEXT_PUBLIC_GITHUB_APP_SLUG);

interface Repo { fullName: string; private: boolean; url: string }

/**
 * "Connect GitHub" for private repositories: install the Zelsis GitHub App on the repos you choose, then pick one.
 * No token to create or paste; scans get a short-lived read token from the server.
 */
export function GithubConnectPanel({ onPickRepo }: { onPickRepo: (url: string) => void }) {
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    const { accessToken } = await getActiveUserAuth();
    if (!accessToken) { setRepos([]); return; }
    try {
      const res = await fetch('/api/v1/github-app/repos', { headers: { Authorization: `Bearer ${accessToken}` } });
      const data = (await res.json()) as { repos?: Repo[] };
      setRepos(Array.isArray(data.repos) ? data.repos : []);
    } catch {
      setRepos([]);
    }
  };

  useEffect(() => {
    if (!GITHUB_APP_ENABLED) return;
    let alive = true;
    void (async () => { if (alive) await load(); })();
    return () => { alive = false; };
  }, []);

  const connect = async (mode: 'install' | 'link' = 'install') => {
    setBusy(true);
    setError('');
    const { accessToken } = await getActiveUserAuth();
    if (!accessToken) { setBusy(false); setError('Sign in first, then connect GitHub.'); return; }
    try {
      const res = await fetch('/api/v1/github-app/connect', { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } });
      const data = (await res.json()) as { url?: string; linkUrl?: string | null; error?: string };
      const target = mode === 'link' ? data.linkUrl || data.url : data.url;
      if (target) { window.location.href = target; return; }
      setError(data.error || 'Could not start the GitHub connection.');
    } catch {
      setError('Could not reach Zelsis. Check your connection and try again.');
    }
    setBusy(false);
  };

  if (!GITHUB_APP_ENABLED) return null;

  return (
    <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-3.5 flex flex-col gap-2.5 text-xs">
      <div className="flex items-center justify-between gap-2">
        <span className="font-semibold text-[#EDEDED]">Private repository? Connect GitHub (recommended)</span>
        {repos && repos.length > 0 && (
          <button type="button" onClick={() => void load()} className="text-[#A1A1AA] hover:text-white" aria-label="Refresh repository list">
            <RefreshCw size={12} />
          </button>
        )}
      </div>
      {repos && repos.length > 0 ? (
        <>
          <label htmlFor="github-connected-repo" className="text-[#A1A1AA]">Pick a repository you shared with Zelsis:</label>
          <select
            id="github-connected-repo"
            defaultValue=""
            onChange={(e) => e.target.value && onPickRepo(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-[#0A0A0A] border border-white/10 text-sm text-[#EDEDED]"
          >
            <option value="" disabled>Select a repository…</option>
            {repos.map((r) => (
              <option key={r.fullName} value={r.url}>{r.fullName}{r.private ? ' (private)' : ''}</option>
            ))}
          </select>
          <button type="button" onClick={() => void connect()} className="w-fit text-[11px] text-emerald-400 hover:text-emerald-300 underline underline-offset-2">
            Add more repositories on GitHub
          </button>
        </>
      ) : (
        <>
          <p className="m-0 text-[#A1A1AA] leading-relaxed">
            Choose which repositories Zelsis may read on GitHub. Zelsis gets read-only access to those repositories only, and you can remove it any time in GitHub settings. No token to copy.
          </p>
          <button
            type="button"
            onClick={() => void connect()}
            disabled={busy}
            className="inline-flex items-center justify-center gap-2 w-fit px-3 py-1.5 rounded-lg bg-white text-black font-semibold hover:bg-zinc-200 disabled:opacity-60"
          >
            {busy ? <Loader2 size={13} className="animate-spin" /> : <GitBranch size={13} />}
            Connect GitHub
          </button>
          <button type="button" onClick={() => void connect('link')} disabled={busy} className="w-fit text-[11px] text-zinc-400 hover:text-white underline underline-offset-2">
            Already installed the Zelsis app on GitHub? Link it to this account
          </button>
        </>
      )}
      {error && <p role="alert" className="m-0 text-red-400">{error}</p>}
    </div>
  );
}
