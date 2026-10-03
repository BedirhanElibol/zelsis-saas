'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Layers, Download, CheckCircle2, Lock } from 'lucide-react';
import { Finding, UserTier } from '@/data/schema';
import { isBulkPatchAllowed } from '@/lib/quota-manager';

interface BulkFixModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: Finding[];
  projectName: string;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const BulkFixModal: React.FC<BulkFixModalProps> = ({
  isOpen,
  onClose,
  findings,
  projectName,
  userTier,
  onOpenCheckout,
}) => {
  const canDownload = isBulkPatchAllowed(userTier);
  const openFindings = findings.filter((f) => f.status === 'OPEN');
  const [selectedIds, setSelectedIds] = useState<string[]>(openFindings.map((f) => f.id));

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const handleDownloadCombinedPatch = () => {
    const selectedFindings = openFindings.filter((f) => selectedIds.includes(f.id));

    let patchContent = `# Zelsis 3.0 Automated Multi-File Security & UI Remediations
# Project: ${projectName}
# Generated: ${new Date().toISOString()}
# Total Remediations: ${selectedFindings.length}
# ======================================================================

`;

    selectedFindings.forEach((f) => {
      if (f.diffPatch && f.diffPatch.includes('---') && f.diffPatch.includes('+++')) {
        patchContent += f.diffPatch.trim() + '\n\n';
      } else {
        const rangeMatch = (f.lineRange || '').match(/(\d+)(?:-(\d+))?/);
        const startLine = rangeMatch ? parseInt(rangeMatch[1], 10) : 1;
        const endLine = rangeMatch && rangeMatch[2] ? parseInt(rangeMatch[2], 10) : startLine;
        const lineCount = Math.max(1, endLine - startLine + 1);

        const snippetLines = (f.snippet || '').split('\n');
        const removedLines = snippetLines.map((l) => `-${l}`).join('\n');
        const addedComment = `+// REMEDIATION [${f.severity} - ${f.title}]: ${(f.remediationPrompt || 'Remediation').replace(/\r?\n/g, ' ')}`;

        patchContent += `--- a/${f.filePath}
+++ b/${f.filePath}
@@ -${startLine},${lineCount} +${startLine},${lineCount} @@
${removedLines}
${addedComment}

`;
      }
    });

    const blob = new Blob([patchContent], { type: 'text/x-patch' });
    const url = URL.createObjectURL(blob);
    const safeProjectName = (projectName || 'project').toLowerCase().replace(/\s+/g, '-');
    const a = document.createElement('a');
    a.href = url;
    a.download = `zelsis-remediation-patch-${safeProjectName}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Layers size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Bulk Unified Git Patch Generator
                </h2>
                <p className="text-xs text-[#A1A1AA]">
                  Select open findings to combine into a single multi-file .patch file for IDE execution
                </p>
              </div>
            </div>

            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>

          {/* Checklist */}
          <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
            {openFindings.map((finding) => (
              <div
                key={finding.id}
                className="bg-[#0A0A0A] p-3.5 rounded-xl border border-white/10 flex items-center justify-between gap-3 hover:border-white/10 transition-all"
              >
                <div className="flex items-center gap-3">
                  <input
                    id={`bulk-fix-checkbox-${finding.id}`}
                    name={`bulkFixFinding_${finding.id}`}
                    aria-label={`Select finding ${finding.title} for bulk remediation patch`}
                    type="checkbox"
                    checked={selectedIds.includes(finding.id)}
                    onChange={() => toggleSelect(finding.id)}
                    className="w-4 h-4 rounded accent-white cursor-pointer"
                  />
                  <div>
                    <div className="text-xs font-mono font-bold text-[#EDEDED]">
                      {finding.title}
                    </div>
                    <div className="text-[0.68rem] text-white font-mono mt-0.5">
                      {finding.filePath} ({finding.lineRange})
                    </div>
                  </div>
                </div>

                <span
                  className={`text-[0.65rem] font-extrabold uppercase px-2 py-0.5 rounded ${
                    finding.severity === 'CRITICAL'
                      ? 'bg-red-500/20 text-red-400'
                      : finding.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-white/5 text-white'
                  }`}
                >
                  {finding.severity}
                </span>
              </div>
            ))}
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <div className="text-xs text-[#A1A1AA] font-mono">
              {selectedIds.length} of {openFindings.length} Selected
            </div>

            <div className="flex items-center gap-2">
              <button className="btn btn-secondary text-xs px-4 py-2" onClick={onClose}>
                Cancel
              </button>
              {canDownload ? (
                <button
                  className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm"
                  disabled={selectedIds.length === 0}
                  onClick={handleDownloadCombinedPatch}
                >
                  <Download size={14} />
                  <span>Download Multi-File .patch</span>
                </button>
              ) : (
                <button
                  className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-amber-500 text-black hover:bg-amber-400 transition-all shadow-sm"
                  onClick={() => onOpenCheckout?.('Pro')}
                >
                  <Lock size={14} />
                  <span>Pro — Unlock Bulk Patch</span>
                </button>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
