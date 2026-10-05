'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import { Check, Copy, KeyRound, Loader2, Trash2 } from 'lucide-react';
import { createApiKey, listApiKeys, revokeApiKey } from '@/app/actions/api-keys';
import { initialApiKeyState, type ApiKeySummary } from '@/lib/api-key-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

/** API keys for the CI release gate (x-api-key header); private repositories need one. */
export function ApiKeysCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [copied, setCopied] = useState(false);
  const [createState, createAction, creating] = useActionState(createApiKey, initialApiKeyState);
  const [revokeState, revokeAction] = useActionState(revokeApiKey, initialApiKeyState);

  const refresh = useCallback(async () => {
    const { accessToken: token } = await getActiveUserAuth();
    setAccessToken(token);
    setKeys(token ? await listApiKeys(token) : []);
  }, []);

  useEffect(() => { void refresh(); }, [refresh, createState, revokeState]);

  if (!accessToken) return null;

  const copySecret = async () => {
    if (!createState.secret) return;
    try {
      await navigator.clipboard.writeText(createState.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <KeyRound size={16} className="text-emerald-400" aria-hidden="true" />
        <h2 className="text-sm font-bold text-white">API keys for the CI release gate</h2>
      </div>
      <p className="text-xs text-zinc-400 leading-relaxed">
        Add a key as the <code className="text-zinc-200">ZELSIS_API_KEY</code> secret in your repository. The GitHub Action sends it in
        the <code className="text-zinc-200">x-api-key</code> header; private repositories cannot be gated without one.
      </p>

      <form action={createAction} className="flex flex-col sm:flex-row gap-2">
        <input type="hidden" name="accessToken" value={accessToken} />
        <label htmlFor="api-key-name" className="sr-only">Key name</label>
        <input
          id="api-key-name"
          name="name"
          required
          placeholder="Key name, e.g. GitHub Actions"
          className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
        />
        <button
          type="submit"
          disabled={creating}
          className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 disabled:opacity-60 flex items-center justify-center gap-2 focus-visible:ring-2 focus-visible:ring-emerald-300 focus-visible:outline-none"
        >
          {creating && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
          Create key
        </button>
      </form>

      {(createState.status !== 'idle' || revokeState.status !== 'idle') && (
        <p role="status" className={`text-xs ${createState.status === 'error' || revokeState.status === 'error' ? 'text-red-400' : 'text-emerald-400'}`}>
          {createState.status !== 'idle' ? createState.message : revokeState.message}
        </p>
      )}

      {createState.secret && (
        <div className="flex items-center gap-2 bg-[#0A0A0A] border border-emerald-500/30 rounded-lg px-3 py-2">
          <code className="flex-1 text-xs text-emerald-300 break-all">{createState.secret}</code>
          <button
            type="button"
            onClick={copySecret}
            className="shrink-0 p-1.5 rounded hover:bg-white/10 text-zinc-300 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
            aria-label="Copy API key"
          >
            {copied ? <Check size={14} className="text-emerald-400" aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          </button>
        </div>
      )}

      {keys.length > 0 && (
        <ul className="divide-y divide-white/5 border border-white/10 rounded-lg">
          {keys.map((k) => (
            <li key={k.id} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
              <div className="min-w-0">
                <div className="text-white font-medium truncate">{k.name}</div>
                <div className="text-zinc-500 font-mono">
                  {k.prefix}… · {k.lastUsedAt ? `last used ${new Date(k.lastUsedAt).toLocaleDateString()}` : 'never used'}
                </div>
              </div>
              <form
                action={revokeAction}
                onSubmit={(e) => { if (!window.confirm(`Revoke "${k.name}"? Pipelines using it will fail the gate.`)) e.preventDefault(); }}
              >
                <input type="hidden" name="accessToken" value={accessToken} />
                <input type="hidden" name="keyId" value={k.id} />
                <button
                  type="submit"
                  className="p-1.5 rounded text-zinc-400 hover:text-red-400 hover:bg-white/5 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                  aria-label={`Revoke key ${k.name}`}
                >
                  <Trash2 size={14} aria-hidden="true" />
                </button>
              </form>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
