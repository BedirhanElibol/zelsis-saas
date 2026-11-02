'use client';

import React, { useEffect } from 'react';
import { RefreshCw } from 'lucide-react';
import { isChunkLoadError, handleChunkLoadRecovery, clearChunkReloadCooldown } from '@/lib/chunk-reload';

interface ErrorBoundaryProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalError({ error, reset }: ErrorBoundaryProps) {
  const isChunkError = isChunkLoadError(error);

  useEffect(() => {
    // Log exception for debugging and telemetry
    console.error('[Zelsis Global Error Boundary]:', error);

    // Auto-recover from chunk load errors caused by new deployments
    if (isChunkError && typeof window !== 'undefined') {
      const dispatched = handleChunkLoadRecovery();
      if (dispatched) {
        // Reload is executing
        return;
      }
    }
  }, [error, isChunkError]);

  const handleRetry = () => {
    if (isChunkError && typeof window !== 'undefined') {
      clearChunkReloadCooldown();
      handleChunkLoadRecovery(true);
    } else {
      reset();
    }
  };

  const handleResetCache = () => {
    if (typeof window !== 'undefined') {
      try {
        localStorage.removeItem('zelsis_user');
        localStorage.removeItem('zelsis_projects');
        localStorage.removeItem('zelsis_selected_project_id');
        localStorage.removeItem('zelsis_license_key');
        localStorage.removeItem('shipguard_user');
        localStorage.removeItem('shipguard_projects');
        localStorage.removeItem('shipguard_selected_project_id');
        localStorage.removeItem('shipguard_license_key');
        sessionStorage.clear();
        document.cookie = 'zelsis_user=; path=/; max-age=0; SameSite=Lax';
        document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
      } catch (err) {
        console.warn('[Zelsis Error] Cache reset notice:', err);
      }
      window.location.href = '/dashboard';
    }
  };

  // Dedicated elegant UI for new deployment chunk transitions
  if (isChunkError) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] text-[#F5F3EF] flex items-center justify-center p-4 sm:p-6 select-text">
        <div className="w-full max-w-lg bg-[#141414] border border-emerald-500/30 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 flex items-center justify-center shrink-0">
              <RefreshCw size={22} />
            </div>
            <div>
              <div className="text-[0.68rem] font-mono font-bold uppercase tracking-widest text-emerald-400">
                Release Gate Live Update
              </div>
              <h2 className="text-xl sm:text-2xl font-extrabold text-[#F5F3EF] mt-0.5">
                New Version Available
              </h2>
            </div>
          </div>

          <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 font-mono text-xs text-zinc-300 leading-relaxed">
            <p className="font-semibold text-white mb-1">
              A new production release of Zelsis was deployed.
            </p>
            <p className="text-[0.72rem] text-zinc-400 mt-1">
              Your audit findings, project configurations, and credentials are completely intact. Please reload to apply the latest build.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2 border-t border-white/10">
            <button
              onClick={handleRetry}
              className="btn btn-primary py-2.5 px-4 text-xs font-extrabold uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer bg-emerald-500 hover:bg-emerald-400 text-black border-emerald-400"
            >
              <span>Reload & Apply Updates</span>
            </button>

            <a
              href="/dashboard"
              className="btn btn-secondary py-2.5 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 text-[#A1A1AA] hover:text-white"
            >
              <span>Dashboard</span>
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F3EF] flex items-center justify-center p-4 sm:p-6 select-text">
      <div className="w-full max-w-xl bg-[#141414] border border-white/15 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative">
        {/* Top Status Header */}
        <div className="flex items-center gap-4">
          <div>
            <div className="text-[0.68rem] font-mono font-bold uppercase tracking-widest text-[#A1A1AA]">
              Runtime Exception &bull; Release Gate Interrupted
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-[#F5F3EF] mt-0.5">
              An unexpected error occurred
            </h1>
          </div>
        </div>

        {/* Error Details Container */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-mono font-bold uppercase text-[#A1A1AA]">
            Incident Diagnostics
          </span>
          <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 font-mono text-xs text-zinc-300 break-words leading-relaxed overflow-x-auto max-h-[12rem]">
            {process.env.NODE_ENV === 'development' ? (
              <p className="font-semibold text-red-400 mb-1">
                {error.name || 'Error'}: {error.message || 'Unknown runtime error'}
              </p>
            ) : (
              <div>
                <p className="font-semibold text-white mb-1">
                  We encountered an issue completing this operation. Your audit data and local settings are safely preserved.
                </p>
                {error?.message && (
                  <p className="text-[0.72rem] text-zinc-400 mt-1 font-mono">
                    Diagnostic: {error.message}
                  </p>
                )}
              </div>
            )}
            {error.digest && (
              <p className="text-[0.7rem] text-[#A1A1AA] mt-2 border-t border-white/10 pt-2">
                Incident Reference: <span className="text-emerald-400 font-mono">{error.digest}</span>
              </p>
            )}
          </div>
        </div>

        <p className="text-xs text-[#A1A1AA] leading-relaxed">
          The application encountered an unexpected runtime condition. You can safely retry the action or return to the main dashboard.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2 border-t border-white/10">
          <button
            onClick={handleRetry}
            onKeyDown={(e) => { if (e.key === 'Enter') handleRetry(); }}
            className="btn btn-primary py-2.5 px-4 text-xs font-extrabold uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer"
          >
            <span>Try Again</span>
          </button>

          <button
            onClick={handleResetCache}
            className="btn btn-secondary py-2.5 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 text-amber-300 border-amber-500/30 hover:bg-amber-500/10 cursor-pointer"
            title="Purge corrupted local data and reset to demo showcase"
          >
            <span>Reset Cache</span>
          </button>

          <a
            href="/dashboard"
            className="btn btn-secondary py-2.5 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            <span>Dashboard</span>
          </a>

          <a
            href="/"
            className="btn btn-secondary py-2.5 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 text-[#A1A1AA] hover:text-white"
          >
            <span>Home</span>
          </a>
        </div>
      </div>
    </div>
  );
}
