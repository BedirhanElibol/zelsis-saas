'use client';

import React, { useState, useEffect } from 'react';
import { Settings } from 'lucide-react';
import { Project } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { SubscriptionCard } from '@/components/settings/SubscriptionCard';
import { TeamWorkspaceCard } from '@/components/settings/TeamWorkspaceCard';
import { RepoConfigCard } from '@/components/settings/RepoConfigCard';
import { DangerZoneCard } from '@/components/settings/DangerZoneCard';

interface ProjectSettingsViewProps {
  project: Project;
  onSaveSettings?: (updatedFields: Partial<Project>) => void;
  onDeleteAccount?: () => void;
  user?: UserProfile | null;
  onUpdateUser?: (updatedUser: UserProfile) => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
}

export const ProjectSettingsView: React.FC<ProjectSettingsViewProps> = ({
  project,
  onSaveSettings,
  onDeleteAccount,
  user,
  onUpdateUser,
  onOpenCheckout,
  onOpenAuth,
}) => {
  const [repoUrl, setRepoUrl] = useState(project.repoUrl);
  const [patToken, setPatToken] = useState(() => {
    if (typeof window !== 'undefined') {
      return sessionStorage.getItem('zelsis_github_token') || '';
    }
    return '';
  });
  const [showPatToken, setShowPatToken] = useState(false);
  const [saved, setSaved] = useState(false);

  // Synchronize form fields when selected project changes
  useEffect(() => {
    setRepoUrl(project.repoUrl || '');
    if (typeof window !== 'undefined') {
      const sessionToken = sessionStorage.getItem('zelsis_github_token');
      if (sessionToken) {
        setPatToken(sessionToken);
      }
    }
  }, [project.id, project.repoUrl]);

  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    if (typeof window !== 'undefined') {
      if (patToken.trim()) {
        sessionStorage.setItem('zelsis_github_token', patToken.trim());
      } else {
        sessionStorage.removeItem('zelsis_github_token');
        localStorage.removeItem('zelsis_github_token');
        localStorage.removeItem('github_token');
      }
    }
    if (onSaveSettings) {
      // F-08 Remediation: Never persist plaintext PAT in project database or project records
      onSaveSettings({
        repoUrl,
      });
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="flex flex-col gap-8 pb-12">
      {/* Header */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
            <Settings size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-[#EDEDED]">
              Project Configuration &amp; Release Settings
            </h1>
            <p className="text-xs text-[#A1A1AA] mt-0.5">
              Manage target repository URLs, GitHub Personal Access Tokens, and CI/CD clearance policies
            </p>
          </div>
        </div>
      </div>

      {/* Membership & Subscription Management */}
      <SubscriptionCard
        user={user}
        onUpdateUser={onUpdateUser}
        onOpenCheckout={onOpenCheckout}
        onOpenAuth={onOpenAuth}
      />

      {/* Enterprise team workspace: members, invites, org policy, report branding */}
      <TeamWorkspaceCard user={user} onOpenCheckout={onOpenCheckout} />

      {/* Target Repo & GitHub PAT Configuration */}
      <RepoConfigCard
        repoUrl={repoUrl}
        setRepoUrl={setRepoUrl}
        patToken={patToken}
        setPatToken={setPatToken}
        showPatToken={showPatToken}
        setShowPatToken={setShowPatToken}
        saved={saved}
        onSaveSettings={handleSaveSettings}
      />

      {/* Danger Zone: GDPR Erasure & Local Cache Wipe */}
      <DangerZoneCard
        project={project}
        user={user}
        onDeleteAccount={onDeleteAccount}
      />
    </div>
  );
};
