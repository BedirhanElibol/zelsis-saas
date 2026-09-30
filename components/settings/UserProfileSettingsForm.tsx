'use client';

import React, { useState, useEffect } from 'react';
import { UserAvatar } from '@/components/ui/UserAvatar';
import { Check, Save, AlertCircle } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';

export interface UserProfileSettingsFormProps {
  user?: UserProfile | null;
  onUpdateUser?: (updatedUser: UserProfile) => void;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
}

export const UserProfileSettingsForm: React.FC<UserProfileSettingsFormProps> = ({
  user,
  onUpdateUser,
  onOpenAuth,
}) => {
  const isAuthenticated = Boolean(user && user.isLoggedIn);
  const isGuest = !isAuthenticated;

  const [profileName, setProfileName] = useState(user?.name || '');
  const [profileEmail, setProfileEmail] = useState(user?.email || '');
  const [profileAvatarUrl, setProfileAvatarUrl] = useState(user?.avatarUrl || '');
  const [profileSaved, setProfileSaved] = useState(false);

  useEffect(() => {
    if (user && user.isLoggedIn) {
      setProfileName(user.name || '');
      setProfileEmail(user.email || '');
      setProfileAvatarUrl(user.avatarUrl || '');
    } else {
      setProfileName('');
      setProfileEmail('');
      setProfileAvatarUrl('');
    }
  }, [user]);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (isGuest || !user) return;
    const updatedUser: UserProfile = {
      ...user,
      name: profileName.trim() || user.name || 'User',
      email: profileEmail.trim() || user.email || '',
      avatarUrl: profileAvatarUrl.trim() || undefined,
      tier: user.tier || 'Free',
      isLoggedIn: true,
      emailVerified: user.emailVerified ?? true,
      expiresAt: user.expiresAt,
      status: user.status,
      gracePeriodUntil: user.gracePeriodUntil,
      billingCycle: user.billingCycle,
      lastVerifiedAt: user.lastVerifiedAt || Date.now(),
    };
    if (onUpdateUser) {
      onUpdateUser(updatedUser);
    }
    try {
      localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
      localStorage.removeItem('shipguard_user');
    } catch (err) {
      console.warn('[Zelsis Profile] Failed to persist user in storage:', err);
    }
    setProfileSaved(true);
    setTimeout(() => setProfileSaved(false), 2500);
  };

  return (
    <form onSubmit={handleSaveProfile} className="bg-[#0A0A0A] border border-white/10 rounded-xl p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between pb-3 border-b border-white/10">
        <span className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">Profile Details &amp; Avatar</span>
        {profileSaved && (
          <span className="text-xs font-mono font-bold text-white flex items-center gap-1">
            <Check size={13} /> Saved
          </span>
        )}
      </div>

      {!isAuthenticated && (
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-amber-300 text-xs">
          <div className="flex items-center gap-2.5">
            <AlertCircle size={16} className="shrink-0" />
            <span>Sign in to customize and link your profile. Profile settings are read-only in guest mode.</span>
          </div>
          {onOpenAuth && (
            <button
              type="button"
              onClick={() => onOpenAuth('signin')}
              className="min-h-[44px] px-3.5 py-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 text-xs font-bold font-mono transition-colors shrink-0 cursor-pointer flex items-center justify-center gap-1.5 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
            >
              <span>Sign In / Register</span>
            </button>
          )}
        </div>
      )}

      <div className="flex items-center gap-4">
        <UserAvatar
          src={profileAvatarUrl}
          name={profileName || (isAuthenticated ? 'Unnamed Developer' : 'Guest')}
          size={56}
          className="w-14 h-14 border-2 border-white/20 shadow-md"
        />
        <div className="min-w-0 flex-1">
          <div className="text-xs font-bold text-white truncate">{profileName || (isAuthenticated ? 'Unnamed Developer' : 'Guest Developer')}</div>
          <div className="text-[11px] text-[#A1A1AA] truncate">{profileEmail || (isAuthenticated ? 'email@example.com' : 'Not signed in')}</div>
          <div className="mt-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-white/10 border border-white/20 text-white">
              {user?.tier && user.tier !== 'Free' ? `${user.tier} Plan` : isAuthenticated ? 'Free Plan' : 'Guest Mode'}
            </span>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="settings-profile-display-name" className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
          <span>Display Name</span>
          {!isAuthenticated && <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize</span>}
        </label>
        <input
          id="settings-profile-display-name"
          name="profileName"
          aria-label="Display Name"
          type="text"
          disabled={!isAuthenticated}
          readOnly={!isAuthenticated}
          value={profileName}
          onChange={(e) => setProfileName(e.target.value)}
          placeholder={!isAuthenticated ? 'Sign in to customize and link your profile.' : 'e.g. Alex Morgan'}
          className={`w-full border rounded-xl px-3.5 py-2 text-xs font-mono transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none ${
            !isAuthenticated ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed' : 'bg-[#141414] border-white/10 text-white focus:border-white/30'
          }`}
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="settings-profile-email" className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
          <span>Email Address</span>
          {!isAuthenticated && <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize</span>}
        </label>
        <input
          id="settings-profile-email"
          name="profileEmail"
          aria-label="Email Address"
          type="email"
          disabled={!isAuthenticated}
          readOnly={!isAuthenticated}
          value={profileEmail}
          onChange={(e) => setProfileEmail(e.target.value)}
          placeholder={!isAuthenticated ? 'Sign in to customize and link your profile.' : 'e.g. alex@example.com'}
          className={`w-full border rounded-xl px-3.5 py-2 text-xs font-mono transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none ${
            !isAuthenticated ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed' : 'bg-[#141414] border-white/10 text-white focus:border-white/30'
          }`}
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="settings-profile-avatar-url" className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
          <span>Avatar Image URL (GitHub or Custom URL)</span>
          {!isAuthenticated && <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize</span>}
        </label>
        <div className="flex gap-2">
          <input
            id="settings-profile-avatar-url"
            name="profileAvatarUrl"
            aria-label="Avatar Image URL"
            type="text"
            disabled={!isAuthenticated}
            readOnly={!isAuthenticated}
            value={profileAvatarUrl}
            onChange={(e) => setProfileAvatarUrl(e.target.value)}
            placeholder={!isAuthenticated ? 'Sign in to customize and link your profile.' : 'https://github.com/username.png'}
            className={`flex-1 border rounded-xl px-3.5 py-2 text-xs font-mono transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none ${
              !isAuthenticated ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed' : 'bg-[#141414] border-white/10 text-white focus:border-white/30'
            }`}
          />
          <button
            type="button"
            disabled={!isAuthenticated}
            onClick={() => {
              if (!isAuthenticated) return;
              const handle = (profileName || '').trim().replace(/\s+/g, '') || 'github';
              setProfileAvatarUrl(`https://github.com/${handle}.png`);
            }}
            className={`px-3 py-2 border rounded-xl text-[11px] font-mono transition-colors whitespace-nowrap focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none ${
              !isAuthenticated ? 'bg-white/5 border-white/5 text-[#71717A] cursor-not-allowed' : 'bg-white/5 hover:bg-white/10 border-white/10 text-[#A1A1AA] hover:text-white cursor-pointer'
            }`}
            title={!isAuthenticated ? 'Sign in to customize avatar' : 'Use GitHub avatar'}
          >
            GitHub
          </button>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 mt-2 pt-1 border-t border-white/5">
        <span className="text-[10px] text-[#71717A] font-mono text-center sm:text-left">
          By saving profile changes, you agree to our{' '}
          <a href="/privacy" target="_blank" rel="noopener noreferrer" className="underline hover:text-white transition-colors">
            Privacy Policy
          </a>{' '}
          and{' '}
          <a href="/terms" target="_blank" rel="noopener noreferrer" className="underline hover:text-white transition-colors">
            Terms of Service
          </a>.
        </span>
        <button
          type="submit"
          disabled={!isAuthenticated}
          className={`min-h-[44px] px-4 py-2 rounded-xl font-bold text-xs flex items-center justify-center gap-2 shadow-md self-end sm:self-auto shrink-0 transition-all focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none ${
            !isAuthenticated ? 'bg-white/5 border border-white/10 text-[#71717A] cursor-not-allowed' : 'bg-white text-black hover:bg-neutral-200 cursor-pointer'
          }`}
        >
          {profileSaved ? <Check size={14} /> : <Save size={14} />}
          <span>{!isAuthenticated ? 'Sign In to Save Profile' : profileSaved ? 'Profile Saved' : 'Save Profile'}</span>
        </button>
      </div>
    </form>
  );
};
