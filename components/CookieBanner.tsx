'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Cookie, X } from 'lucide-react';
import { updateConsentMode } from '@/components/analytics/AnalyticsScripts';

export function reopenConsent() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('zelsis:reopenConsent'));
  }
}

export function cookiePreferences(): string {
  if (typeof window === 'undefined') return 'default';
  return localStorage.getItem('zelsis_cookie_consent') || 'default';
}

export const CookieBanner: React.FC = () => {
  const [showBanner, setShowBanner] = useState(false);

  useEffect(() => {
    const consent = localStorage.getItem('zelsis_cookie_consent') || localStorage.getItem('shipguard_cookie_consent');
    if (!consent) {
      setShowBanner(true);
    } else if (consent === 'accepted') {
      updateConsentMode(true);
    }

    const handleReopen = () => {
      setShowBanner(true);
    };

    window.addEventListener('zelsis:reopenConsent', handleReopen);
    return () => window.removeEventListener('zelsis:reopenConsent', handleReopen);
  }, []);

  const handleAccept = () => {
    localStorage.setItem('zelsis_cookie_consent', 'accepted');
    localStorage.removeItem('shipguard_cookie_consent');
    updateConsentMode(true);
    setShowBanner(false);
  };

  const handleDecline = () => {
    localStorage.setItem('zelsis_cookie_consent', 'declined');
    localStorage.removeItem('shipguard_cookie_consent');
    updateConsentMode(false);
    setShowBanner(false);
  };

  if (!showBanner) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-6 sm:max-w-md z-50 transition-all duration-300">
      <div className="bg-[#141414] border border-white/10 p-4 sm:p-5 rounded-2xl shadow-2xl flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-white shrink-0">
              <Cookie size={16} />
            </div>
            <div className="text-xs font-bold text-[#FAFAFA]">
              Cookie Preferences &amp; Privacy
            </div>
          </div>
          <button
            onClick={handleDecline}
            className="text-[#94A3B8] hover:text-[#FAFAFA] transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-white/20"
            aria-label="Close cookie consent banner"
          >
            <X size={14} />
          </button>
        </div>

        <p className="text-xs text-[#94A3B8] leading-relaxed">
          We use strictly essential cookies for secure authentication and active security scan state. No invasive third-party tracking or advertising cookies are utilized. Read our{' '}
          <Link href="/cookies" className="text-white hover:underline underline-offset-2">
            Cookie Policy
          </Link>{' '}
          and{' '}
          <Link href="/privacy" className="text-white hover:underline underline-offset-2">
            Privacy Policy
          </Link>.
        </p>

        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={handleAccept}
            className="flex-1 px-3.5 py-1.5 rounded-lg text-xs font-bold text-[#0A0A0A] bg-white hover:bg-neutral-200 transition-colors shadow-sm cursor-pointer"
          >
            Accept Essential Cookies
          </button>
          <button
            onClick={handleDecline}
            className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-[#A1A1AA] hover:text-white bg-[#141414] hover:bg-white/10 border border-white/10 transition-colors cursor-pointer"
          >
            Decline
          </button>
        </div>
      </div>
    </div>
  );
};
