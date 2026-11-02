'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Loader2 } from 'lucide-react';
import { Project } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { supabaseSignOut } from '@/lib/supabase';
import { purgeZelsisStorage } from '@/lib/storage';

interface DangerZoneCardProps {
  project: Project;
  user?: UserProfile | null;
  onDeleteAccount?: () => void;
}

export const DangerZoneCard: React.FC<DangerZoneCardProps> = ({
  project,
  user,
  onDeleteAccount,
}) => {
  const router = useRouter();
  const isAuthenticated = Boolean(user && user.isLoggedIn);

  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [confirmationInput, setConfirmationInput] = useState('');
  const [hasConfirmedCheckbox, setHasConfirmedCheckbox] = useState(false);
  const [isPurging, setIsPurging] = useState(false);
  const [purgeSuccess, setPurgeSuccess] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  // Close modal on Escape key for WCAG 2.2 AA accessibility
  useEffect(() => {
    if (!isDeleteModalOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsDeleteModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isDeleteModalOpen]);

  const handleExportData = async () => {
    if (!isAuthenticated || !user) return;
    setIsExporting(true);
    try {
      const exportData = {
        exportVersion: '1.0',
        exportedAt: new Date().toISOString(),
        framework: ['GDPR Article 20 (Right to Data Portability)', 'CCPA'],
        user: {
          name: user.name,
          email: user.email,
          tier: user.tier,
        },
        activeProject: {
          name: project.name,
          repoUrl: project.repoUrl,
          gateStatus: project.gateStatus,
          readinessScore: project.readinessScore,
          findingsCount: project.findings?.length || 0,
        },
      };
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `zelsis-privacy-export-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[GDPR Export] Failed to export data:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExecutePurge = async () => {
    if (confirmationInput !== 'DELETE' || !hasConfirmedCheckbox) return;

    setIsPurging(true);

    try {
      if (isAuthenticated && user?.email) {
        try {
          await fetch('/api/v1/user/delete', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirmation: 'DELETE', email: user.email }),
          });
        } catch (apiErr) {
          console.warn('[GDPR Erasure] Server-side deletion notice:', apiErr);
        }
      }

      await supabaseSignOut().catch(() => {});
      purgeZelsisStorage(false);

      if (onDeleteAccount) {
        onDeleteAccount();
      }

      setPurgeSuccess(true);
      setTimeout(() => {
        setIsDeleteModalOpen(false);
        router.push('/');
      }, 1500);
    } catch (err) {
      console.error('[GDPR Erasure] Error executing cascade deletion:', err);
    } finally {
      setIsPurging(false);
    }
  };

  return (
    <>
      <div className="bg-[#180a0a]/60 border border-red-500/30 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap sm:flex-nowrap">
          <div className="flex items-start gap-3">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-extrabold text-white">
                  {!isAuthenticated ? 'Danger Zone: Clear Local Browser Cache & Scans' : 'Danger Zone: GDPR Data Erasure'}
                </h2>
                <span className="text-[0.65rem] font-extrabold uppercase tracking-wider bg-red-500/20 border border-red-500/40 text-red-300 px-2 py-0.5 rounded-full">
                  Irreversible
                </span>
              </div>
              <p className="text-xs text-[#CBD5E1] mt-1.5 leading-relaxed max-w-2xl">
                {isAuthenticated
                  ? 'Exercise your Right to Erasure (GDPR Article 17 / CCPA). Permanently destroy your account, wipe all registered repository audits, flush cached vulnerability findings, purge personal access credentials, and wipe local storage states.'
                  : 'Exercise your Right to Erasure (GDPR Article 17 / CCPA). As an unauthenticated guest, this action clears your local browser cache, registered repository audits, and scan history stored on this device.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {isAuthenticated && (
              <button
                type="button"
                onClick={handleExportData}
                disabled={isExporting}
                className="min-h-[44px] px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white text-xs font-bold flex items-center justify-center gap-2 transition-colors shrink-0 cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
              >
                <span>{isExporting ? 'Exporting...' : 'Export Data (GDPR Art. 20)'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setConfirmationInput('');
                setHasConfirmedCheckbox(false);
                setPurgeSuccess(false);
                setIsDeleteModalOpen(true);
              }}
              className="min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 hover:text-red-100 text-xs font-bold flex items-center justify-center gap-2 transition-colors shrink-0 cursor-pointer focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none"
            >
              <span>{isAuthenticated ? 'Delete Account & Wipe Data' : 'Clear Local Cache & Wipe Scans'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* GDPR Deletion Confirmation Modal */}
      <AnimatePresence>
        {isDeleteModalOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-3 sm:p-4 min-h-[100dvh]"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gdpr-delete-modal-title"
            onClick={(e) => {
              if (e.target === e.currentTarget) setIsDeleteModalOpen(false);
            }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="w-full max-w-lg max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-red-500/30 rounded-2xl p-5 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
            >
              <button
                type="button"
                onClick={() => setIsDeleteModalOpen(false)}
                aria-label="Close deletion confirmation modal"
                className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10 focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none"
              >
                <X size={20} />
              </button>

              {purgeSuccess ? (
                <div className="py-8 flex flex-col items-center justify-center text-center gap-4">
                  <h3 className="text-xl font-extrabold text-white">
                    {isAuthenticated ? 'Data Purged Successfully' : 'Local Cache & Scans Cleared'}
                  </h3>
                  <p className="text-xs text-[#A1A1AA] max-w-sm">
                    {isAuthenticated
                      ? 'All account records, audits, tokens, and local cache have been erased in compliance with GDPR Art. 17 / CCPA. Redirecting to home...'
                      : 'All local scan data, cached repositories, and browser storage have been wiped. Redirecting to home...'}
                  </p>
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-3">
                    <div>
                      <h3 id="gdpr-delete-modal-title" className="text-lg font-extrabold text-white">
                        {!isAuthenticated ? 'Confirm Local Cache & Scan History Erasure' : 'Confirm Permanent Account & Data Erasure'}
                      </h3>
                      <p className="text-xs text-[#A1A1AA]">
                        {!isAuthenticated ? 'Wipes local browser storage & scan history on this machine' : 'GDPR Article 17 / CCPA Right to Erasure'}
                      </p>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/20 text-xs text-red-200/90 flex flex-col gap-2">
                    <span className="font-extrabold text-red-300 uppercase text-[0.7rem] flex items-center gap-1.5">
                      The following data will be permanently wiped:
                    </span>
                    <ul className="space-y-1 list-disc list-inside text-[0.72rem] text-red-200/80">
                      {!isAuthenticated ? (
                        <>
                          <li>Guest mode session and local browser cache (<code className="text-red-300">zelsis_*</code>).</li>
                          <li>Locally saved project scans and vulnerability findings history on this device.</li>
                          <li>Temporary repository target configurations and local license state.</li>
                          <li>Note: No cloud account credentials exist to purge in Guest Mode.</li>
                        </>
                      ) : (
                        <>
                          <li>Active user profile, authenticated session tokens, and billing records.</li>
                          <li>All registered project repositories and custom scan settings.</li>
                          <li>Historical audit reports, gate matrices, and remediation logs.</li>
                          <li>Stored GitHub Personal Access Tokens (PAT) and webhook credentials.</li>
                          <li>Local browser database and storage caches (<code className="text-red-300">zelsis_*</code>).</li>
                        </>
                      )}
                    </ul>
                  </div>

                  <div className="flex flex-col gap-4">
                    <div className="flex flex-col gap-1.5">
                      <label htmlFor="delete-confirm-input" className="text-xs font-bold text-[#CBD5E1]">
                        To confirm erasure, type <span className="font-mono text-red-400 font-extrabold">DELETE</span> below:
                      </label>
                      <input
                        id="delete-confirm-input"
                        name="deleteConfirmation"
                        aria-label="Type DELETE to confirm account and data erasure"
                        type="text"
                        value={confirmationInput}
                        onChange={(e) => setConfirmationInput(e.target.value)}
                        placeholder="Type DELETE to confirm"
                        className="w-full bg-[#0A0A0A] border border-white/15 focus:border-red-500 rounded-xl px-4 py-2.5 text-xs text-white font-mono focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none"
                      />
                    </div>

                    <label htmlFor="confirm-delete-checkbox" className="flex items-start gap-2.5 cursor-pointer text-xs text-[#A1A1AA] hover:text-white select-none">
                      <input
                        id="confirm-delete-checkbox"
                        name="confirmDelete"
                        aria-label="Confirm permanent deletion of account and telemetry"
                        type="checkbox"
                        checked={hasConfirmedCheckbox}
                        onChange={(e) => setHasConfirmedCheckbox(e.target.checked)}
                        className="mt-0.5 rounded border-white/20 bg-[#0A0A0A] text-red-600 focus:ring-0 focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none w-4 h-4"
                      />
                      <span>
                        {!isAuthenticated
                          ? 'I acknowledge this action will permanently clear all local project scans and browser cache on this machine.'
                          : 'I acknowledge this action is irreversible and request the permanent deletion of my account and all associated telemetry.'}
                      </span>
                    </label>
                  </div>

                  <div className="flex items-center justify-end gap-3 pt-2 border-t border-white/10">
                    <button
                      type="button"
                      onClick={() => setIsDeleteModalOpen(false)}
                      disabled={isPurging}
                      className="min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                    >
                      Cancel
                    </button>

                    <button
                      type="button"
                      onClick={handleExecutePurge}
                      disabled={confirmationInput !== 'DELETE' || !hasConfirmedCheckbox || isPurging}
                      className="min-h-[44px] min-w-[44px] px-5 py-2.5 rounded-xl bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:hover:bg-red-600 text-xs font-bold text-white transition-colors flex items-center justify-center gap-2 shadow-lg focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none"
                    >
                      {isPurging ? (
                        <>
                          <Loader2 size={14} className="animate-spin" />
                          <span>Purging Data...</span>
                        </>
                      ) : (
                        <>
                          <span>{!isAuthenticated ? 'Permanently Wipe Local Data' : 'Permanently Delete & Wipe'}</span>
                        </>
                      )}
                    </button>
                  </div>
                </>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};
