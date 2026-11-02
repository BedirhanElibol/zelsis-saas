'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import { Loader2, Unplug } from 'lucide-react';
import { deleteJiraConnection, getJiraAccess, getJiraIssueTypes, saveJiraConnection, setJiraIssueType } from '@/app/actions/jira';
import { initialJiraState, type JiraConnectionSummary, type JiraIssueTypeList } from '@/lib/jira-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

const input = 'bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400';

/** Connects a Jira Cloud project so findings can be opened as issues (paid plans). The API token is stored encrypted. */
export function JiraCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [connection, setConnection] = useState<JiraConnectionSummary | null>(null);
  const [allowed, setAllowed] = useState(false);
  const [issueTypes, setIssueTypes] = useState<JiraIssueTypeList>({ types: [] });
  const [saveState, saveAction, saving] = useActionState(saveJiraConnection, initialJiraState);
  const [typeState, typeAction, savingType] = useActionState(setJiraIssueType, initialJiraState);
  const [deleteState, deleteAction, deleting] = useActionState(deleteJiraConnection, initialJiraState);

  const refresh = useCallback(async () => {
    const { accessToken: token } = await getActiveUserAuth();
    setAccessToken(token);
    const access = token ? await getJiraAccess(token) : null;
    setConnection(access?.connection ?? null);
    setAllowed(access?.allowed ?? false);
    // Type names are in the Jira account's language (Task, Görev...), so they are read from Jira, not typed in.
    setIssueTypes(token && access?.allowed && access.connection ? await getJiraIssueTypes(token) : { types: [] });
  }, []);

  useEffect(() => { void refresh(); }, [refresh, saveState, deleteState, typeState]);

  if (!accessToken) return null;
  const last = [typeState, deleteState, saveState].find((s) => s.status !== 'idle') ?? saveState;
  const currentType = connection
    ? issueTypes.types.find((t) => t.id === connection.issueType || t.name === connection.issueType)
    : undefined;

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-bold text-white">Jira</h2>
      </div>

      {connection ? (
        <div className="flex flex-col gap-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <p className="text-xs text-zinc-300">
            Connected to <span className="font-mono">{connection.site.replace('https://', '')}</span> as {connection.email}. New issues go to{' '}
            <span className="font-mono">{connection.projectKey}</span>{currentType ? <> as {currentType.name}</> : null}.
          </p>
          <form action={deleteAction}>
            <input type="hidden" name="accessToken" value={accessToken} />
            <button type="submit" disabled={deleting} className="px-3 py-2 rounded-lg border border-white/10 text-xs text-zinc-300 hover:text-white flex items-center gap-1.5 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400">
              {deleting ? <Loader2 size={13} className="animate-spin" aria-hidden="true" /> : <Unplug size={13} aria-hidden="true" />}
              Disconnect
            </button>
          </form>
        </div>
        {issueTypes.types.length > 0 && (
          <form action={typeAction} className="flex flex-col sm:flex-row sm:items-end gap-2">
            <input type="hidden" name="accessToken" value={accessToken} />
            <label className="flex flex-col gap-1 text-xs text-zinc-400 sm:w-64">
              Create issues as
              <select key={currentType?.id ?? 'none'} name="issueTypeId" defaultValue={currentType?.id ?? issueTypes.types[0].id} className={input}>
                {issueTypes.types.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </label>
            <button type="submit" disabled={savingType} className="px-3 py-2 rounded-lg border border-white/10 text-xs text-zinc-300 hover:text-white flex items-center gap-1.5 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400">
              {savingType && <Loader2 size={13} className="animate-spin" aria-hidden="true" />}
              Save type
            </button>
          </form>
        )}
        {issueTypes.error && <p className="text-xs text-amber-400">{issueTypes.error}</p>}
        </div>
      ) : !allowed ? (
        <p className="text-xs text-zinc-400 leading-relaxed flex items-start gap-2">
          <span>
            Open a Jira issue from any finding with one click. Included in Zelsis Pro and Team.{' '}
            <a href="/#pricing" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-2">See plans</a>
          </span>
        </p>
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
            <div className="flex items-end sm:col-span-2">
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
