'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, Lock } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import type { UserProfile } from '@/components/auth/AuthModal';

interface CheckoutShellProps {
  user: UserProfile | null;
  onOpenAuth: (mode: 'signin' | 'signup') => void;
  children: React.ReactNode;
}

/** Minimal frame for the payment page: no dashboard chrome, no demo project. */
export function CheckoutShell({ user, onOpenAuth, children }: CheckoutShellProps) {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] flex flex-col">
      <header className="h-16 px-4 sm:px-6 border-b border-white/10 flex items-center justify-between gap-3">
        <div className="flex items-center gap-4 min-w-0">
          <Link href="/" aria-label="Zelsis home" className="shrink-0">
            <ZelsisLogo size="sm" />
          </Link>
          <Link
            href="/#pricing"
            className="hidden sm:inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-white transition-colors min-h-11"
          >
            <ArrowLeft size={15} />
            Back to pricing
          </Link>
        </div>
        <div className="flex items-center gap-3 min-w-0">
          <span className="hidden sm:inline-flex items-center gap-1.5 text-xs text-zinc-400">
            <Lock size={13} />
            Payments by Polar
          </span>
          {user?.isLoggedIn ? (
            <span className="text-sm text-zinc-300 truncate max-w-[180px]" title={user.email}>
              {user.email}
            </span>
          ) : (
            <button
              type="button"
              onClick={() => onOpenAuth('signin')}
              className="min-h-11 px-3 rounded-lg text-sm font-semibold text-white hover:bg-white/10 transition-colors"
            >
              Sign in
            </button>
          )}
        </div>
      </header>
      <div className="flex-1">{children}</div>
    </div>
  );
}
