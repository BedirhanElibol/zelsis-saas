'use client';

import React from 'react';
import { Finding, PlanUsageQuota } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { FindingDetailModal } from './FindingDetailModal';

export interface RemediationDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve: (id: string) => void;
  onMarkFalsePositive?: (id: string) => void;
  onIgnoreRule?: (ruleId: number) => void;
  /** The finding's rule is muted in this project: the button offers to unmute it. */
  ruleMuted?: boolean;
  user?: UserProfile | null;
  quota?: PlanUsageQuota;
  onRecordAiPrompt?: () => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  finding,
  onClose,
  onToggleResolve,
  onMarkFalsePositive,
  onIgnoreRule,
  ruleMuted,
  user,
  quota,
  onRecordAiPrompt,
  onOpenCheckout,
}) => {
  return (
    <FindingDetailModal
      isOpen={finding !== null}
      finding={finding}
      onClose={onClose}
      onToggleResolve={onToggleResolve}
      onMarkFalsePositive={onMarkFalsePositive}
      onIgnoreRule={onIgnoreRule}
      ruleMuted={ruleMuted}
      user={user}
      quota={quota}
      onRecordAiPrompt={onRecordAiPrompt}
      onOpenCheckout={onOpenCheckout}
    />
  );
};
