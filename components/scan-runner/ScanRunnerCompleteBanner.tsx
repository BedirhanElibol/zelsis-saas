import React from 'react';
import { CheckCircle2, Lock, Key } from 'lucide-react';
import { ScanResult } from '@/lib/scanner-engine';
import { Project } from '@/data/schema';
import { canAccessLocalAudit } from '@/lib/env-config';
import { safeLower } from '@/lib/safe-utils';
import { priceLabel } from '@/data/pricing-plans';

interface ScanRunnerCompleteBannerProps {
  isFinished: boolean;
  scanResult: ScanResult | null;
  project: Project;
  queuedFilesCount: number;
  countdownSeconds: number;
  scanFailureReason: string | null;
  onViewReport: () => void;
  onReturnToDashboard: () => void;
  onConfigureSettings: () => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  setIsPrivateTokenModalOpen: (val: boolean) => void;
}

export const ScanRunnerCompleteBanner: React.FC<ScanRunnerCompleteBannerProps> = ({
  isFinished,
  scanResult,
  project,
  queuedFilesCount,
  countdownSeconds,
  scanFailureReason,
  onViewReport,
  onReturnToDashboard,
  onConfigureSettings,
  onOpenCheckout,
  setIsPrivateTokenModalOpen,
}) => {
  if (!isFinished) return null;

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4 shadow-2xl animate-fade-in">
      {scanResult ? (
        <>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
              <CheckCircle2 size={24} className="text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-extrabold text-white uppercase tracking-wider">
                  AST CLEARANCE SCAN COMPLETE
                </span>
                <span className={`px-2 py-0.5 rounded text-[0.65rem] font-bold ${
                  scanResult.gateStatus === 'FAILED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-white/5 text-white border border-white/10'
                }`}>
                  GATE: {scanResult.gateStatus}
                </span>
                <span className="text-[0.65rem] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded font-mono">
                  Auto-opening report in {countdownSeconds}s...
                </span>
              </div>
              <p className="text-sm font-bold text-[#EDEDED] mt-0.5">
                Audited {queuedFilesCount} files · Found {scanResult.findings.length} security &amp; UX issues (Readiness Score: {scanResult.score}/100)
              </p>
            </div>
          </div>

          <button
            className="btn btn-primary px-8 py-4 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all"
            onClick={onViewReport}
          >
            <CheckCircle2 size={18} />
            <span>View Full Audit Report ({scanResult.findings.length} Issues)</span>
          </button>
        </>
      ) : (
        <>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center shrink-0">
              <span className="text-red-400 font-bold text-lg font-mono">!</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-extrabold text-red-400 uppercase tracking-wider">
                  AUDIT RESTRICTED
                </span>
              </div>
              <p className="text-sm font-bold text-[#EDEDED] mt-0.5">
                {scanFailureReason || ((project?.repoUrl === 'local' || safeLower(project?.repoUrl) === 'local') && !canAccessLocalAudit()
                  ? 'Local workspace self-audit is available only in local development.'
                  : 'Audit execution was stopped before completion.')}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {(!scanFailureReason?.includes('rate limit') &&
              !scanFailureReason?.includes('GitHub anonymous') &&
              (scanFailureReason?.includes('Pro feature') || scanFailureReason?.includes('Monthly Free Scan Limit') || scanFailureReason?.includes('Upgrade to Zelsis Pro'))) && (
              <button
                onClick={() => onOpenCheckout?.('Pro')}
                className="btn btn-primary px-5 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-black transition-all font-mono cursor-pointer"
              >
                <Lock size={14} />
                <span>Upgrade to Pro ({priceLabel('Pro')})</span>
              </button>
            )}

            {(scanFailureReason?.includes('Private') || scanFailureReason?.includes('token') || scanFailureReason?.includes('Token') || scanFailureReason?.includes('PAT') || scanFailureReason?.includes('rate limit')) &&
              !scanFailureReason?.includes('not found') &&
              !scanFailureReason?.includes('404') && (
              <button
                onClick={() => setIsPrivateTokenModalOpen(true)}
                className="btn btn-primary px-5 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all font-mono cursor-pointer"
              >
                <Key size={14} />
                <span>{scanFailureReason?.includes('rate limit') ? 'Add Free GitHub Token (5,000 req/hr)' : 'Enter GitHub Token'}</span>
              </button>
            )}

            {scanFailureReason?.includes('Settings') && (
              <a
                href="/dashboard?nav=settings"
                className="btn btn-secondary px-5 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 transition-all font-mono"
                onClick={onConfigureSettings}
              >
                <span>Configure in Settings</span>
              </a>
            )}

            <button
              className="btn btn-secondary px-6 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 border border-white/10 hover:bg-white/10 text-white transition-all font-mono"
              onClick={onReturnToDashboard}
            >
              <span>Return to Dashboard</span>
            </button>
          </div>
        </>
      )}
    </div>
  );
};
