'use client';

import React from 'react';
import dynamic from 'next/dynamic';
import { Project, UserTier } from '@/data/schema';
import { AuditCompareModal } from './AuditCompareModal';
import { NotificationSettingsModal } from './NotificationSettingsModal';
import { RuleConfiguratorModal } from './RuleConfiguratorModal';

// Bundles the full rule catalogs (~3 MB): load only when the knowledge base is opened
const RuleKnowledgeBaseModal = dynamic(() => import('./RuleKnowledgeBaseModal').then((m) => m.RuleKnowledgeBaseModal), { ssr: false });
import { DeploymentManifestModal } from './DeploymentManifestModal';
import { BadgeGeneratorModal } from './BadgeGeneratorModal';
import { ShareReportModal } from './ShareReportModal';
import { CiCdIntegrationModal } from './CiCdIntegrationModal';

export type ActiveModalType =
  | 'compare'
  | 'notif'
  | 'rules'
  | 'kb'
  | 'manifest'
  | 'badge'
  | 'share'
  | 'cicd'
  | null;

export interface DashboardModalsProps {
  project: Project;
  activeModal: ActiveModalType;
  onClose: () => void;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const DashboardModals: React.FC<DashboardModalsProps> = ({
  project,
  activeModal,
  onClose,
  userTier,
  onOpenCheckout,
}) => {
  if (!activeModal) return null;

  return (
    <>
      <AuditCompareModal
        isOpen={activeModal === 'compare'}
        onClose={onClose}
        project={project}
      />

      <NotificationSettingsModal
        isOpen={activeModal === 'notif'}
        onClose={onClose}
        projectName={project.name}
        repoUrl={project.repoUrl}
      />

      <RuleConfiguratorModal
        isOpen={activeModal === 'rules'}
        onClose={onClose}
        projectName={project.name}
        userTier={userTier}
        onOpenCheckout={onOpenCheckout}
      />

      <RuleKnowledgeBaseModal
        isOpen={activeModal === 'kb'}
        onClose={onClose}
      />

      <DeploymentManifestModal
        isOpen={activeModal === 'manifest'}
        onClose={onClose}
        projectName={project.name}
        userTier={userTier}
        onOpenCheckout={onOpenCheckout}
      />

      <BadgeGeneratorModal
        isOpen={activeModal === 'badge'}
        onClose={onClose}
        project={project}
      />

      <ShareReportModal
        isOpen={activeModal === 'share'}
        onClose={onClose}
        project={project}
      />

      <CiCdIntegrationModal
        isOpen={activeModal === 'cicd'}
        onClose={onClose}
        project={project}
        userTier={userTier}
        onOpenCheckout={onOpenCheckout}
      />
    </>
  );
};
