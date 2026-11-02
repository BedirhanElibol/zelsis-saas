'use client';

import React, { useEffect } from 'react';

interface GlobalErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalError({ error, reset }: GlobalErrorProps) {
  useEffect(() => {
    // Log exception safely to console or monitoring telemetry
    console.error('[Zelsis Global Root Error Boundary]:', error);
  }, [error]);

  const handleRetry = () => {
    reset();
  };

  const handleReturnHome = () => {
    if (typeof window !== 'undefined') {
      window.location.href = '/';
    }
  };

  return (
    <html lang="en" className="dark">
      <head>
        <title>Zelsis Release Gate - Application Error Encountered</title>
        <meta name="description" content="Application error boundary diagnostics and recovery console." />
        <meta property="og:title" content="Zelsis Release Gate - Application Error Encountered" />
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=5" />
      </head>
      <body className="min-h-[100dvh] bg-[#0A0A0A] text-[#EDEDED] flex items-center justify-center p-4 sm:p-6 font-sans antialiased selection:bg-white/20 selection:text-white">
        <main
          className="w-full max-w-xl bg-[#141414] border border-white/15 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
          role="alert"
          aria-live="assertive"
        >
          {/* Status Header */}
          <div className="flex items-start gap-4">
            <div className="flex flex-col gap-1">
              <div className="text-[0.68rem] font-mono font-extrabold uppercase tracking-widest text-emerald-400">
                Zelsis Security &bull; Root Recovery Active
              </div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] tracking-tight leading-snug">
                Zelsis Release Gate - Application Error Encountered
              </h1>
            </div>
          </div>

          {/* Safe Diagnostics Container (No Stack Traces Leaked) */}
          <div className="flex flex-col gap-2">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#A1A1AA]">
              Diagnostics &amp; Incident Reference
            </span>
            <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 font-mono text-xs text-zinc-300 break-words leading-relaxed flex flex-col gap-2">
              <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2">
                <span className="text-white font-bold">Error Type:</span>
                <span className="text-red-400 font-mono text-[11px] bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                  {error?.name || 'ApplicationError'}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-[#A1A1AA] text-[11px]">Message:</span>
                <p className="text-white font-medium text-xs">
                  {process.env.NODE_ENV === 'development'
                    ? error?.message || 'An unexpected runtime error was caught by the root error boundary.'
                    : 'A critical application exception was caught. Local audit data is preserved.'}
                </p>
              </div>
              {error?.digest && (
                <div className="flex items-center justify-between gap-2 pt-2 border-t border-white/10 text-[11px]">
                  <span className="text-[#A1A1AA]">Digest Signature:</span>
                  <span className="font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    {error.digest}
                  </span>
                </div>
              )}
            </div>
          </div>

          <p className="text-xs text-[#CBD5E1] leading-relaxed">
            The application experienced an unexpected runtime state. Your local audit data and security gates are preserved in storage. You can attempt an in-place session recovery or navigate back to the overview.
          </p>

          {/* Action Buttons (Strict WCAG AAA, min 44px touch targets) */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-3 border-t border-white/10">
            <button
              type="button"
              onClick={handleRetry}
              className="min-h-[44px] px-5 py-2.5 rounded-xl bg-white text-black font-extrabold text-xs hover:bg-neutral-200 transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer font-mono uppercase tracking-wider"
            >
              <span>Try Again / Recover Session</span>
            </button>

            <button
              type="button"
              onClick={handleReturnHome}
              className="min-h-[44px] px-5 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/15 text-white font-bold text-xs transition-all flex items-center justify-center gap-2 cursor-pointer font-mono"
            >
              <span>Return to Safe Overview</span>
            </button>
          </div>
        </main>
      </body>
    </html>
  );
}
