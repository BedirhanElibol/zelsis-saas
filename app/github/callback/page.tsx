'use client';

import React, { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { getActiveUserAuth } from '@/lib/supabase-client';

/**
 * GitHub App "Callback URL": GitHub returns here with an OAuth code after the user installs or updates the app.
 * The session lives in the browser, so the page sends the code with the user's token to link the installation.
 */
export default function GithubCallbackPage() {
  const [message, setMessage] = useState('Connecting GitHub…');

  useEffect(() => {
    const run = async () => {
      const code = new URLSearchParams(window.location.search).get('code');
      if (!code) { window.location.replace('/dashboard?nav=projects&github=error'); return; }
      const { accessToken } = await getActiveUserAuth();
      if (!accessToken) {
        setMessage('Sign in to Zelsis in this browser, then press Connect GitHub again.');
        return;
      }
      try {
        const res = await fetch('/api/v1/github-app/link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
          body: JSON.stringify({ code }),
        });
        window.location.replace(`/dashboard?nav=projects&github=${res.ok ? 'connected' : 'error'}`);
      } catch {
        window.location.replace('/dashboard?nav=projects&github=error');
      }
    };
    void run();
  }, []);

  return (
    <main className="min-h-screen bg-[#0A0A0A] flex items-center justify-center p-6">
      <div className="flex items-center gap-3 text-sm text-zinc-300">
        {message.startsWith('Connecting') && <Loader2 size={16} className="animate-spin" />}
        <span>{message}</span>
      </div>
    </main>
  );
}
