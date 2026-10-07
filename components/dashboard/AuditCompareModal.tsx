'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ArrowRight, CheckCircle2, AlertTriangle, ShieldCheck, Layers } from 'lucide-react';
import { Project, ScanHistoryItem } from '@/data/schema';

interface AuditCompareModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
}

export const AuditCompareModal: React.FC<AuditCompareModalProps> = ({
  isOpen,
  onClose,
  project
}) => {
  // Keyboard Escape listener for Accessibility (WCAG 2.2 AA)
  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // history[0] is the latest scan; compare it with the one before. With a single scan there is nothing to compare,
  // and the modal says so instead of inventing a baseline.
  const history = (project as any).scanHistory as ScanHistoryItem[] | undefined;
  const pastScanItem = history && history.length > 1 ? history[1] : null;

  if (!pastScanItem) {
    return (
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-compare-title"
      >
        <div className="w-full max-w-md bg-[#141414] border border-white/10 rounded-2xl p-6 flex flex-col gap-4 shadow-2xl">
          <h2 id="audit-compare-title" className="text-lg font-extrabold text-white">Nothing to compare yet</h2>
          <p className="text-sm text-[#A1A1AA]">
            {project.name} has one scan so far. Run the audit again after you fix something and this view will show what changed.
          </p>
          <button onClick={onClose} className="self-end min-h-[44px] px-4 rounded-xl bg-white/5 hover:bg-white/10 text-sm text-white">
            Close
          </button>
        </div>
      </div>
    );
  }

  const previousScan = {
    date: pastScanItem.date,
    score: pastScanItem.score,
    gateStatus: pastScanItem.gateStatus,
    criticals: pastScanItem.criticalCount,
    highs: pastScanItem.highCount,
    openFindings: pastScanItem.criticalCount + pastScanItem.highCount + pastScanItem.mediumCount,
    isBaseline: false,
    label: 'PREVIOUS AUDIT'
  };

  const currentScan = {
    date: project.lastScanAt || 'Current Live Audit',
    score: project.readinessScore,
    gateStatus: project.gateStatus,
    criticals: project.criticalCount,
    highs: project.highCount,
    openFindings: project.findings.length
  };

  const scoreDelta = currentScan.score - previousScan.score;

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-compare-title"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-3xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Layers size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-white">
                  Audit History Side-by-Side Comparison
                </h2>
                <p className="text-xs text-[#A1A1AA]">
                  Comparing baseline pre-fix scan against current live production release audit for {project.name}
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close comparison"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={20} />
            </button>
          </div>

          {/* Comparison Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Previous Scan */}
            <div className="bg-[#0A0A0A] p-5 rounded-xl border border-white/10 flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#A1A1AA]">{previousScan.label}</span>
                <span className="text-[0.65rem] text-[#94A3B8]">{previousScan.date}</span>
              </div>
              
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-extrabold ${previousScan.gateStatus === 'PASSED' ? 'text-white' : 'text-red-500'}`}>
                  {previousScan.score}
                </span>
                <span className="text-xs text-[#94A3B8]">/ 100</span>
              </div>

              <div className="flex flex-col gap-1.5 text-xs text-[#94A3B8]">
                <div className="flex items-center justify-between">
                  <span>Critical Vulnerabilities</span>
                  <span className="text-red-400 font-bold">{previousScan.criticals}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>High Risks</span>
                  <span className="text-[#A1A1AA] font-bold">{previousScan.highs}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Total Open Rules</span>
                  <span className="font-bold text-[#EDEDED]">{previousScan.openFindings}</span>
                </div>
              </div>

              <div className="mt-2 pt-3 border-t border-white/10 text-[0.68rem] font-bold text-center">
                Gate: <span className={previousScan.gateStatus === 'PASSED' ? 'text-white' : 'text-red-400'}>{previousScan.gateStatus}</span>
              </div>
            </div>

            {/* Current Scan */}
            <div className="bg-[#0A0A0A] p-5 rounded-xl border border-white/20 flex flex-col gap-4 relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-1 bg-white" />
              
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-white">CURRENT AUDIT</span>
                <span className="text-[0.65rem] text-[#94A3B8]">{currentScan.date}</span>
              </div>
              
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-extrabold ${currentScan.gateStatus === 'PASSED' ? 'text-white' : 'text-red-500'}`}>
                  {currentScan.score}
                </span>
                <span className="text-xs text-[#94A3B8]">/ 100</span>
                
                <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded ${
                  scoreDelta > 0 
                    ? 'bg-white/5 text-white border border-white/10'
                    : scoreDelta < 0
                      ? 'bg-red-500/10 text-red-400 border border-red-500/25'
                      : 'bg-white/10 text-[#A1A1AA]'
                }`}>
                  {scoreDelta > 0 ? '+' : ''}{scoreDelta} pts
                </span>
              </div>

              <div className="flex flex-col gap-1.5 text-xs text-[#A1A1AA]">
                <div className="flex items-center justify-between">
                  <span>Critical Vulnerabilities</span>
                  <span className="text-red-400 font-bold">{currentScan.criticals}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>High Risks</span>
                  <span className="text-[#A1A1AA] font-bold">{currentScan.highs}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Total Open Rules</span>
                  <span className="font-bold text-[#EDEDED]">{currentScan.openFindings}</span>
                </div>
              </div>

              <div className="mt-2 pt-3 border-t border-white/10 text-[0.68rem] font-bold text-center">
                Gate: <span className={currentScan.gateStatus === 'PASSED' ? 'text-white' : 'text-red-400'}>{currentScan.gateStatus}</span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-white/5 border border-white/10 text-xs text-white flex items-center justify-center gap-2">
            <ShieldCheck size={14} className="text-white" />
            <span>Audit delta tracked automatically. Delta logs retained for 90 days.</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
