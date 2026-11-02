'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { WifiOff, X, CheckCircle2 } from 'lucide-react';
import { useOnlineStatus } from '@/hooks/useOnlineStatus';

export const OfflineBanner: React.FC = () => {
  const isOnline = useOnlineStatus();
  const [wasOffline, setWasOffline] = useState(false);
  const [showRestoredNotice, setShowRestoredNotice] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);
  const [isChecking, setIsChecking] = useState(false);

  useEffect(() => {
    if (!isOnline) {
      setWasOffline(true);
      setIsDismissed(false); // Re-open when network is lost again
    } else if (wasOffline) {
      // Just transitioned from offline to online
      setShowRestoredNotice(true);
      const timer = setTimeout(() => {
        setShowRestoredNotice(false);
        setWasOffline(false);
      }, 3500);
      return () => clearTimeout(timer);
    }
  }, [isOnline, wasOffline]);

  const handleManualCheck = async () => {
    setIsChecking(true);
    try {
      // Probe connectivity with head request or no-cache fetch
      await fetch('/api/v1/badge?status=PASSED', { method: 'HEAD', cache: 'no-store' });
    } catch {
      // Silently catch probe failure
    } finally {
      setTimeout(() => setIsChecking(false), 600);
    }
  };

  return (
    <AnimatePresence>
      {!isOnline && !isDismissed && (
        <motion.div
          key="offline-banner"
          initial={{ y: -60, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -60, opacity: 0 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          role="status"
          aria-live="polite"
          className="fixed top-0 inset-x-0 z-[100] bg-[#1a1207]/95 border-b border-amber-500/40 text-amber-200 backdrop-blur-md px-4 py-2.5 shadow-2xl"
        >
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 flex-wrap sm:flex-nowrap">
            {/* Left status badge & message */}
            <div className="flex items-center gap-3 min-w-0">
              <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 shrink-0">
                <WifiOff size={16} />
                <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-amber-500 rounded-full animate-ping" />
                <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-amber-500 rounded-full" />
              </div>
              <div className="text-xs">
                <span className="font-extrabold text-white tracking-wide mr-1.5 uppercase text-[0.7rem] bg-amber-500/20 px-1.5 py-0.5 rounded border border-amber-500/30">
                  Offline Mode
                </span>
                <span className="text-amber-100/90 font-medium">
                  Network connection lost. Cached audits and local reports remain fully accessible.
                </span>
              </div>
            </div>

            {/* Right action buttons (min 44x44px touch targets) */}
            <div className="flex items-center gap-2 ml-auto shrink-0">
              <button
                type="button"
                onClick={handleManualCheck}
                disabled={isChecking}
                aria-label="Check internet connection"
                className="min-w-[44px] min-h-[44px] px-3.5 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 text-xs font-bold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
              >
                <span className="hidden sm:inline">
                  {isChecking ? 'Checking...' : 'Check Connection'}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setIsDismissed(true)}
                aria-label="Dismiss offline banner"
                className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-amber-300 hover:text-white transition-colors"
              >
                <X size={18} />
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {showRestoredNotice && (
        <motion.div
          key="online-restored-banner"
          initial={{ y: -60, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -60, opacity: 0 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          role="status"
          aria-live="polite"
          className="fixed top-0 inset-x-0 z-[100] bg-[#052317]/95 border-b border-emerald-500/40 text-emerald-200 backdrop-blur-md px-4 py-2.5 shadow-2xl"
        >
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
                <CheckCircle2 size={16} />
              </div>
              <div className="text-xs font-medium text-emerald-100">
                <span className="font-extrabold text-white tracking-wide mr-1.5 uppercase text-[0.7rem] bg-emerald-500/20 px-1.5 py-0.5 rounded border border-emerald-500/30">
                  Connected
                </span>
                Internet connection restored. Live cloud scans and webhooks are active.
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowRestoredNotice(false)}
              aria-label="Dismiss connection restored banner"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-emerald-300 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
