'use client';

import React, { useActionState, useEffect, useState } from 'react';
import { ExternalLink, Loader2, Ticket } from 'lucide-react';
import { createJiraIssue, getJiraConnection } from '@/app/actions/jira';
import { initialJiraState, type JiraConnectionSummary } from '@/lib/jira-state';
import { getActiveUserAuth } from '@/lib/supabase-client';
import type { Finding } from '@/data/schema';

/** Opens an issue for the finding in the user's connected Jira project. Hidden until Jira is connected. */
export function JiraIssueButton({ finding, cweId }: { finding: Finding; cweId?: string }) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [connection, setConnection] = useState<JiraConnectionSummary | null>(null);
  const [state, action, pending] = useActionState(createJiraIssue, initialJiraState);

  useEffect(() => {
    void (async () => {
      const { accessToken: token } = await getActiveUserAuth();
      setAccessToken(token);
      setConnection(token ? await getJiraConnection(token) : null);
    })();
  }, []);

  if (!accessToken || !connection) return null;

  return (
    <form action={action} className="flex flex-wrap items-center gap-2">
      <input type="hidden" name="accessToken" value={accessToken} />
      <input type="hidden" name="title" value={finding.title} />
      <input type="hidden" name="severity" value={finding.severity} />
      <input type="hidden" name="category" value={finding.category ?? ''} />
      <input type="hidden" name="filePath" value={finding.filePath ?? ''} />
      <input type="hidden" name="lineRange" value={finding.lineRange ?? ''} />
      <input type="hidden" name="remediationPrompt" value={finding.remediationPrompt ?? ''} />
      <input type="hidden" name="cweId" value={cweId ?? ''} />
      <button
        type="submit"
        disabled={pending || state.status === 'success'}
        className="px-3 py-1 rounded bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-300 text-xs font-bold flex items-center gap-1.5 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
      >
        {pending ? <Loader2 size={13} className="animate-spin" aria-hidden="true" /> : <Ticket size={13} aria-hidden="true" />}
        Create Jira issue in {connection.projectKey}
      </button>
      {state.status !== 'idle' && (
        <span role="status" className={`text-xs ${state.status === 'error' ? 'text-red-400' : 'text-emerald-400'}`}>
          {state.message}{' '}
          {state.issueUrl && (
            <a href={state.issueUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline underline-offset-2">
              Open <ExternalLink size={11} aria-hidden="true" />
            </a>
          )}
        </span>
      )}
    </form>
  );
}
