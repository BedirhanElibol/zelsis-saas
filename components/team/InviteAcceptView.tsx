'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Building2, CheckCircle2, Loader2, LogIn, Users } from 'lucide-react';
import { AuthModal } from '@/components/auth/AuthModal';
import { acceptInvite } from '@/app/actions/organization';
import { initialOrgActionState } from '@/lib/org-action-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

export function InviteAcceptView({ token }: { token: string }) {
  const router = useRouter();
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [authOpen, setAuthOpen] = useState(false);
  const [state, formAction, pending] = useActionState(acceptInvite, initialOrgActionState);

  const loadSession = useCallback(async () => {
    const { accessToken: sessionToken } = await getActiveUserAuth();
    setAccessToken(sessionToken);
    setChecking(false);
  }, []);

  useEffect(() => {
    void loadSession();
  }, [loadSession]);

  return (
    <main className="min-h-screen bg-[#0A0A0A] flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-5 shadow-2xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center">
            <Building2 size={20} />
          </div>
          <div>
            <h1 className="text-lg font-extrabold text-white">Join a team workspace</h1>
            <p className="text-xs text-zinc-400">You were invited to a Zelsis Enterprise workspace.</p>
          </div>
        </div>

        <ul className="text-xs text-zinc-300 flex flex-col gap-1.5">
          <li className="flex items-center gap-2"><Users size={13} className="text-zinc-500" /> Pro features while you are a member</li>
          <li className="flex items-center gap-2"><Users size={13} className="text-zinc-500" /> Your team&apos;s gate policy applies to your scans</li>
          <li className="flex items-center gap-2"><Users size={13} className="text-zinc-500" /> Teammates see your saved projects&apos; score and gate status</li>
        </ul>

        {state.status === 'success' ? (
          <div className="flex flex-col gap-3">
            <div role="status" className="flex items-center gap-2 text-xs p-3 rounded-xl border bg-emerald-500/10 border-emerald-500/30 text-emerald-300">
              <CheckCircle2 size={14} /> {state.message}
            </div>
            <button type="button" onClick={() => router.push('/dashboard')} className="btn btn-primary min-h-[44px] rounded-xl text-xs font-bold">
              Go to dashboard
            </button>
          </div>
        ) : checking ? (
          <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
            <Loader2 size={14} className="animate-spin" /> Checking your session...
          </div>
        ) : !accessToken ? (
          <button type="button" onClick={() => setAuthOpen(true)} className="btn btn-primary min-h-[44px] rounded-xl text-xs font-bold flex items-center justify-center gap-2">
            <LogIn size={14} /> Sign in or create an account to join
          </button>
        ) : (
          <form action={formAction} className="flex flex-col gap-3">
            <input type="hidden" name="accessToken" value={accessToken} />
            <input type="hidden" name="token" value={token} />
            {state.status === 'error' && (
              <div role="alert" className="text-xs p-3 rounded-xl border bg-red-500/10 border-red-500/30 text-red-300">
                {state.message}
              </div>
            )}
            <button type="submit" disabled={pending} className="btn btn-primary min-h-[44px] rounded-xl text-xs font-bold flex items-center justify-center gap-2">
              {pending ? <Loader2 size={14} className="animate-spin" /> : <Users size={14} />}
              Accept invite
            </button>
          </form>
        )}
      </div>

      <AuthModal
        isOpen={authOpen}
        onClose={() => setAuthOpen(false)}
        initialMode="signup"
        onLoginSuccess={() => {
          setAuthOpen(false);
          void loadSession();
        }}
      />
    </main>
  );
}
