'use client';

import React, { useActionState, useEffect, useState } from 'react';
import { Loader2, Sparkles } from 'lucide-react';
import { getAiVerifySettings, setAiVerify } from '@/app/actions/ai-verify';
import { initialAiVerifyState, type AiVerifySettings } from '@/lib/ai-verify-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

/** Opt-in AI double-check of blocking PR findings (Pro / Team). Off by default; no code leaves Zelsis unless it is on. */
export function AiVerifyCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [settings, setSettings] = useState<AiVerifySettings | null>(null);
  const [state, action, saving] = useActionState(setAiVerify, initialAiVerifyState);

  useEffect(() => {
    let alive = true;
    void getActiveUserAuth().then(async ({ accessToken: token }) => {
      const s = token ? await getAiVerifySettings(token) : null;
      if (alive) { setAccessToken(token); setSettings(s); }
    });
    return () => { alive = false; };
  }, [state]);

  if (!accessToken || !settings) return null;
  const canToggle = settings.available && (settings.eligible || settings.enabled);

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Sparkles size={16} className="text-emerald-400" aria-hidden="true" />
        <h2 className="text-sm font-bold text-white">AI double-check before a PR is blocked</h2>
        <span className="text-[10px] font-mono text-zinc-400 border border-white/10 rounded px-1.5 py-0.5">Pro · opt-in</span>
      </div>
      <p className="text-xs text-zinc-400 leading-relaxed">
        Scans stay rule-based. When this is on and a pull request has a critical finding, Zelsis sends the flagged file and up to two
        files it imports to Anthropic&apos;s Claude model and asks whether the code already guards against it. If it does, the finding
        stays in the report as high instead of blocking the merge. At most three findings per pull request are checked. For up to two
        blocking findings on lines the pull request added, in JavaScript and TypeScript files, the model also writes a suggested fix
        for the flagged line; Zelsis re-checks it with its own scanner and only then posts it as a GitHub suggested change that you
        review and commit yourself. Nothing is sent while this is off. Anthropic does not train on this data under its commercial terms.
      </p>
      {!settings.available && <p className="text-xs text-amber-300">Not available yet on this server.</p>}
      {settings.available && !settings.eligible && !settings.enabled && (
        <p className="text-xs text-zinc-400">Available on Pro and Team.</p>
      )}
      {canToggle && (
        <form action={action} className="flex items-center gap-3">
          <input type="hidden" name="accessToken" value={accessToken} />
          <input type="hidden" name="enabled" value={settings.enabled ? 'false' : 'true'} />
          <button
            type="submit"
            disabled={saving}
            className={`px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2 cursor-pointer disabled:opacity-60 ${settings.enabled ? 'border border-white/15 text-zinc-200 hover:bg-white/5' : 'bg-emerald-500 text-black hover:bg-emerald-400'}`}
          >
            {saving && <Loader2 size={13} className="animate-spin" aria-hidden="true" />}
            {settings.enabled ? 'Turn off' : 'Turn on'}
          </button>
          <span className="text-xs text-zinc-400">{settings.enabled ? 'On' : 'Off'}</span>
        </form>
      )}
      {state.status !== 'idle' && (
        <p role="status" className={`text-xs ${state.status === 'error' ? 'text-red-400' : 'text-emerald-400'}`}>{state.message}</p>
      )}
    </section>
  );
}
