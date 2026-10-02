'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Mail, Lock, User, Code, ArrowRight, CheckCircle2, KeyRound, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { supabaseSignIn, supabaseSignUp, supabaseResetPassword, supabaseSignInWithOAuth, isSupabaseConfigured } from '@/lib/supabase';
import { isPwnedPassword } from '@/lib/pwned-password';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import { useDialogFocus } from '@/hooks/useDialogFocus';

export interface UserProfile {
  name: string;
  email: string;
  avatarUrl?: string;
  tier: 'Free' | 'Pro' | 'Enterprise';
  isLoggedIn: boolean;
  emailVerified?: boolean;
  expiresAt?: string;
  billingCycle?: 'monthly' | 'annual';
  status?: 'active' | 'past_due' | 'canceled' | 'trialing';
  gracePeriodUntil?: string;
  lastVerifiedAt?: number;
}

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: UserProfile) => void;
  initialMode?: 'signin' | 'signup';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onLoginSuccess,
  initialMode = 'signin'
}) => {
  const [mode, setMode] = useState<'signin' | 'signup' | 'forgot'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [loadingTarget, setLoadingTarget] = useState<'github' | 'google' | 'email' | null>(null);

  React.useEffect(() => {
    if (isOpen) {
      setMode(initialMode);
      setEmail('');
      setPassword('');
      setName('');
      setError('');
      setSuccessMsg('');
      setLoadingTarget(null);
    }
  }, [initialMode, isOpen]);

  React.useEffect(() => {
    const handleReset = () => setLoadingTarget(null);
    window.addEventListener('pageshow', handleReset);
    window.addEventListener('focus', handleReset);
    const handleVis = () => {
      if (document.visibilityState === 'visible') {
        setLoadingTarget(null);
      }
    };
    document.addEventListener('visibilitychange', handleVis);

    return () => {
      window.removeEventListener('pageshow', handleReset);
      window.removeEventListener('focus', handleReset);
      document.removeEventListener('visibilitychange', handleVis);
    };
  }, []);

  const dialogRef = React.useRef<HTMLDivElement>(null);
  useDialogFocus(dialogRef, isOpen, onClose);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!email.includes('@')) {
      setError('Please enter a valid email address.');
      return;
    }

    if (mode === 'forgot') {
      setLoadingTarget('email');
      const { success, message } = await supabaseResetPassword(email.trim());
      setLoadingTarget(null);
      if (success) {
        setSuccessMsg(message);
      } else {
        setError(message);
      }
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }



    if (mode === 'signup' && !name.trim()) {
      setError('Please enter your full name.');
      return;
    }

    if (mode === 'signup' && password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setLoadingTarget('email');

    if (mode === 'signup' && (await isPwnedPassword(password))) {
      setLoadingTarget(null);
      setError('This password has appeared in a known data breach. Please choose a different one.');
      return;
    }

    if (mode === 'signin') {
      const { user, error: signError } = await supabaseSignIn(email.trim(), password);
      setLoadingTarget(null);
      if (signError) {
        setError(signError);
      } else if (user) {
        onLoginSuccess(user);
        onClose();
      }
    } else if (mode === 'signup') {
      const { user, error: signUpErr, requiresVerification } = await supabaseSignUp(email.trim(), password, name.trim());
      setLoadingTarget(null);
      if (signUpErr) {
        setError(signUpErr);
      } else if (user) {
        if (requiresVerification) {
          setSuccessMsg(`Account created! We've sent a verification link to ${email}. Please check your inbox.`);
        }
        onLoginSuccess(user);
        if (!requiresVerification) {
          onClose();
        }
      }
    }
  };

  const handleInitiateOAuth = async (provider: 'github' | 'google') => {
    setError('');
    setSuccessMsg('');
    setLoadingTarget(provider);

    // Auto-unlock safety timer: resets button state if redirect is cancelled or delayed
    const safetyTimer = setTimeout(() => {
      setLoadingTarget(null);
    }, 4500);

    try {
      if (provider === 'google') {
        const { url, error: oauthError } = await supabaseSignInWithOAuth(provider);
        if (url) {
          window.location.href = url;
          return;
        }
        // Google OAuth not available - show friendly error
        clearTimeout(safetyTimer);
        setLoadingTarget(null);
        const displayError = oauthError && !oauthError.toLowerCase().includes('not configured')
          ? oauthError
          : 'Google authentication is currently unavailable. Please sign in with GitHub or email.';
        setError(displayError);
        return;
      }

      const { url, error: oauthError } = await supabaseSignInWithOAuth(provider);
      if (url) {
        window.location.href = url;
        return;
      }
      clearTimeout(safetyTimer);
      setLoadingTarget(null);
      const displayError = oauthError && !oauthError.toLowerCase().includes('not configured')
        ? oauthError
        : `${provider === 'github' ? 'GitHub' : 'Google'} authentication could not be initiated. Please try again or use email.`;
      setError(displayError);
    } catch (err: any) {
      clearTimeout(safetyTimer);
      setLoadingTarget(null);

      setError(err?.message || 'Authentication error occurred. Please try again.');
    }
  };

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-3 sm:p-4 min-h-[100dvh]"
        onClick={(e) => {
          if (e.target === e.currentTarget) {
            onClose();
          }
        }}
      >
        <motion.div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="auth-modal-title"
          tabIndex={-1}
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="w-full max-w-md max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
        >
          {/* Close Button */}
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
          >
            <X size={18} />
          </button>

          {/* Header & Logo */}
          <div className="flex flex-col items-center text-center gap-2">
            <div className="mb-1">
              <ZelsisLogo size="lg" showWordmark={false} />
            </div>
            <h2 id="auth-modal-title" className="text-xl font-extrabold text-[#EDEDED]">
              {mode === 'signin'
                ? 'Welcome Back to Zelsis'
                : mode === 'signup'
                ? 'Create Your Zelsis Account'
                : 'Reset Your Password'}
            </h2>
            <p className="text-xs text-[#A1A1AA] max-w-xs">
              {mode === 'signin'
                ? 'Sign in to access your saved security scans and custom rule gates.'
                : mode === 'signup'
                ? 'Start securing your Next.js and LLM applications with automated pre-flight gates.'
                : 'Enter your email address and we will dispatch a secure password reset link.'}
            </p>
          </div>

          {/* Mode Switcher Tabs */}
          {mode !== 'forgot' && (
            <div className="grid grid-cols-2 p-1 bg-[#0A0A0A] rounded-xl border border-white/10 text-xs font-bold font-mono">
              <button
                type="button"
                onClick={() => { setMode('signin'); setError(''); setSuccessMsg(''); }}
                className={`py-2 rounded-lg transition-all ${
                  mode === 'signin'
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setMode('signup'); setError(''); setSuccessMsg(''); }}
                className={`py-2 rounded-lg transition-all ${
                  mode === 'signup'
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Sign Up
              </button>
            </div>
          )}

          {/* Direct OAuth Providers */}
          {mode !== 'forgot' && (
            <>
              <div className="flex flex-col gap-2.5">
                <button
                  type="button"
                  onClick={() => handleInitiateOAuth('github')}
                  disabled={loadingTarget !== null}
                  className="flex items-center justify-center gap-3 w-full py-3 px-4 rounded-xl bg-[#24292F] hover:bg-[#1f2328] border border-white/15 text-xs font-bold text-white transition-all shadow-md disabled:opacity-50 cursor-pointer min-h-[48px]"
                >
                  <Code size={18} className="shrink-0" />
                  <span>{loadingTarget === 'github' ? 'Connecting to GitHub...' : 'Continue with GitHub'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleInitiateOAuth('google')}
                  disabled={loadingTarget !== null}
                  className="flex items-center justify-center gap-3 w-full py-3 px-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-bold text-white transition-all shadow-md disabled:opacity-50 cursor-pointer min-h-[48px]"
                >
                  <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                    <path
                      fill="#4285F4"
                      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                    />
                  </svg>
                  <span>{loadingTarget === 'google' ? 'Connecting to Google...' : 'Continue with Google'}</span>
                </button>


              </div>

              <div className="flex items-center gap-3 my-1">
                <div className="flex-1 h-[1px] bg-white/10" />
                <span className="text-[0.65rem] text-[#A1A1AA] uppercase tracking-wider font-mono font-bold">OR CONTINUE WITH EMAIL</span>
                <div className="flex-1 h-[1px] bg-white/10" />
              </div>
            </>
          )}

          {/* Form Inputs */}
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            {error && (
              <div role="alert" className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 p-2.5 rounded-lg text-center font-medium flex items-center justify-center gap-2">
                <AlertCircle size={14} className="shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div role="status" className="text-xs text-white bg-white/5 border border-white/10 p-2.5 rounded-lg text-center font-medium flex items-center justify-center gap-2">
                <CheckCircle2 size={14} className="shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            {mode === 'signup' && (
              <div className="flex flex-col gap-1">
                <label htmlFor="auth-fullname-input" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Full Name</label>
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                  <User size={15} className="text-[#A1A1AA]" />
                  <input
                    id="auth-fullname-input"
                    autoComplete="name"
                    name="fullName"
                    aria-label="Full Name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Alex Morgan"
                    className="bg-transparent text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/70 w-full"
                  />
                </div>
              </div>
            )}

            <div className="flex flex-col gap-1">
              <label htmlFor="auth-email-input" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Email Address</label>
              <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                <Mail size={15} className="text-[#A1A1AA]" />
                <input
                  id="auth-email-input"
                  autoComplete="email"
                  name="email"
                  aria-label="Email Address"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="bg-transparent text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/70 w-full"
                />
              </div>
            </div>

            {mode !== 'forgot' && (
              <div className="flex flex-col gap-1">
                <div className="flex items-center justify-between">
                  <label htmlFor="auth-password-input" className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Password</label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => { setMode('forgot'); setError(''); setSuccessMsg(''); }}
                      className="text-[0.65rem] text-white hover:underline font-semibold"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                  <Lock size={15} className="text-[#A1A1AA]" />
                  <input
                    id="auth-password-input"
                    autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                    name="password"
                    aria-label="Password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="bg-transparent text-xs text-[#EDEDED] outline-none focus-visible:ring-1 focus-visible:ring-white/70 w-full"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="text-[#A1A1AA] hover:text-white transition-colors p-1"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loadingTarget !== null}
              className="mt-2 btn btn-primary py-3 text-xs uppercase tracking-wider font-extrabold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50"
            >
              <span>
                {loadingTarget === 'email'
                  ? 'Processing...'
                  : mode === 'signin'
                  ? 'Sign In'
                  : mode === 'signup'
                  ? 'Create Account'
                  : 'Send Reset Link'}
              </span>
              <ArrowRight size={14} />
            </button>
          </form>

          {/* Footer Back link for forgot mode */}
          {mode === 'forgot' ? (
            <button
              onClick={() => { setMode('signin'); setError(''); setSuccessMsg(''); }}
              className="text-center text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
            >
              ← Back to Sign In
            </button>
          ) : (
            <div className="text-center text-xs text-zinc-400">
              By signing in, you agree to Zelsis{' '}
              <a href="/terms" target="_blank" rel="noopener noreferrer" className="underline hover:text-white transition-colors">Terms of Service</a>
              {' '}&amp;{' '}
              <a href="/privacy" target="_blank" rel="noopener noreferrer" className="underline hover:text-white transition-colors">Privacy Policy</a>.
            </div>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
