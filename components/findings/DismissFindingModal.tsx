'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldX, Loader2, Copy } from 'lucide-react';
import { Finding } from '@/data/schema';
import { dismissFinding } from '@/actions/dismiss-finding';
import { getActiveUserAuth } from '@/lib/supabase-client';

interface DismissFindingModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: Finding | null;
  projectId: string;
  onDismissed: () => void;
}

export const DismissFindingModal: React.FC<DismissFindingModalProps> = ({
  isOpen,
  onClose,
  finding,
  projectId,
  onDismissed,
}) => {
  const [reason, setReason] = useState<'false_positive' | 'accepted_risk' | 'test_code'>('false_positive');
  const [note, setNote] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isSubmitting) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, isSubmitting]);

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      setReason('false_positive');
      setNote('');
      setError(null);
    }
  }, [isOpen]);

  if (!isOpen || !finding) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      const auth = await getActiveUserAuth();
      if (!auth.accessToken) {
        setError('You must be signed in to dismiss findings.');
        setIsSubmitting(false);
        return;
      }

      const formData = new FormData();
      formData.append('accessToken', auth.accessToken);
      formData.append('projectId', projectId);
      formData.append('ruleId', finding.ruleId.toString());
      formData.append('filePath', finding.filePath);
      formData.append('reason', reason);
      if (note.trim()) {
        formData.append('note', note.trim());
      }

      const result = await dismissFinding({ status: 'idle', message: '' }, formData);

      if (result.status === 'error') {
        setError(result.message);
      } else {
        onDismissed();
        onClose();
      }
    } catch (err) {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCopyZelsisIgnore = () => {
    const ignoreLine = `${finding.ruleId} ${finding.filePath}`;
    navigator.clipboard.writeText(ignoreLine);
  };

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
        onClick={(e) => {
          if (e.target === e.currentTarget && !isSubmitting) onClose();
        }}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-lg bg-[#141414] border border-white/10 rounded-2xl p-6 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <ShieldX size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Dismiss Finding
                </h2>
                <p className="text-xs text-[#A1A1AA] font-mono mt-0.5 truncate max-w-[280px]">
                  {finding.title}
                </p>
              </div>
            </div>

            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              disabled={isSubmitting}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors disabled:opacity-50"
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
                {error}
              </div>
            )}

            <div className="flex flex-col gap-2">
              <label htmlFor="reason" className="text-sm font-bold text-[#EDEDED]">
                Reason for Dismissal
              </label>
              <select
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value as any)}
                className="bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-white/30 transition-colors"
                disabled={isSubmitting}
              >
                <option value="false_positive">False Positive (Scanner Error)</option>
                <option value="accepted_risk">Accepted Risk (Won't Fix)</option>
                <option value="test_code">Test Code / Non-Production</option>
              </select>
            </div>

            <div className="flex flex-col gap-2">
              <label htmlFor="note" className="text-sm font-bold text-[#EDEDED]">
                Additional Note <span className="text-[#A1A1AA] font-normal">(Optional)</span>
              </label>
              <textarea
                id="note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Briefly explain why this is being dismissed..."
                className="bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-white/30 transition-colors min-h-[80px] resize-y"
                disabled={isSubmitting}
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-white/10">
              <button
                type="button"
                onClick={handleCopyZelsisIgnore}
                className="text-xs text-[#A1A1AA] hover:text-white flex items-center gap-1.5 transition-colors font-mono"
                title="Copy line for .zelsisignore file"
              >
                <Copy size={12} />
                <span>Copy .zelsisignore line</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-secondary text-xs px-4 py-2"
                  onClick={onClose}
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-white text-black hover:bg-gray-200 transition-all shadow-sm disabled:opacity-70"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 size={14} className="animate-spin" />
                      <span>Dismissing...</span>
                    </>
                  ) : (
                    <span>Dismiss Finding</span>
                  )}
                </button>
              </div>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
