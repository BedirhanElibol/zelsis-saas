'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import { Loader2, Ticket, Unplug } from 'lucide-react';
import { deleteJiraConnection, getJiraConnection, saveJiraConnection } from '@/app/actions/jira';
import { initialJiraState, type JiraConnectionSummary } from '@/lib/jira-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

const input = 'bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400';

/** Connects a Jira Cloud project so findings can be opened as issues. The API token is stored encrypted. */
export function JiraCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [connection, setConnection] = useState<JiraConnectionSummary | null>(null);
  const [saveState, saveAction, saving] = useActionState(saveJiraConnection, initialJiraState);
  const [deleteState, deleteAction, deleting] = useActionState(deleteJiraConnection, initialJiraState);

  const refresh = useCallback(async () => {
    const { accessToken: token } = await getActiveUserAuth();
    setAccessToken(token);
    setConnection(token ? await getJiraConnection(token) : null);
  }, []);

  useEffect(() => { void refresh(); }, [refresh, saveState, deleteState]);

  if (!accessToken) return null;
  const last = deleteState.status !== 'idle' ? deleteState : saveState;

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Ticket size={16} className="text-emerald-400" aria-hidden="true" />
        <h2 className="text-sm font-bold text-white">Jira</h2>
      </div>

      {connection ? (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <p className="text-xs text-zinc-300">
            Connected to <span className="font-mono">{connection.site.replace('https://', '')}</span> as {connection.email}. New issues go to{' '}
            <span className="font-mono">{connection.projectKey}</span> as {connection.issueType}.
          </p>
          <form action={deleteAction}>
            <input type="hidden" name="accessToken" value={accessToken} />
            <button type="submit" disabled={deleting} className="px-3 py-2 rounded-lg border border-white/10 text-xs text-zinc-300 hover:text-white flex items-center gap-1.5 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400">
              {deleting ? <Loader2 size={13} className="animate-spin" aria-hidden="true" /> : <Unplug size={13} aria-hidden="true" />}
              Disconnect
            </button>
          </form>
        </div>
      ) : (
        <>
          <p className="text-xs text-zinc-400 leading-relaxed">
            Open an issue from any finding. Create an API token at id.atlassian.com under Security, API tokens. It is checked with Jira, then stored encrypted.
          </p>
          <form action={saveAction} className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input type="hidden" name="accessToken" value={accessToken} />
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Jira site<input name="site" required placeholder="acme.atlassian.net" className={input} /></label>
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Account e-mail<input name="email" type="email" required className={input} /></label>
            <label className="flex flex-col gap-1 text-xs text-zinc-400">API token<input name="apiToken" type="password" required autoComplete="off" className={input} /></label>
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Project key<input name="projectKey" required placeholder="SEC" className={input} /></label>
            <label className="flex flex-col gap-1 text-xs text-zinc-400">Issue type<input name="issueType" defaultValue="Task" required className={input} /></label>
            <div className="flex items-end">
              <button type="submit" disabled={saving} className="w-full px-4 py-2 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 disabled:opacity-60 flex items-center justify-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300">
                {saving && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
                Connect Jira
              </button>
            </div>
          </form>
        </>
      )}

      {last.status !== 'idle' && (
        <p role="status" className={`text-xs ${last.status === 'error' ? 'text-red-400' : 'text-emerald-400'}`}>{last.message}</p>
      )}
    </section>
  );
}
