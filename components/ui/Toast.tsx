'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'info';

export interface ToastMessage {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  duration?: number;
}

interface ToastItemProps {
  toast: ToastMessage;
  onDismiss: (id: string) => void;
}

export const ToastItem: React.FC<ToastItemProps> = ({ toast, onDismiss }) => {
  const getIcon = () => {
    switch (toast.type) {
      case 'success':
        return <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />;
      case 'error':
        return <AlertCircle size={16} className="text-red-400 shrink-0" />;
      case 'info':
      default:
        return <Info size={16} className="text-sky-400 shrink-0" />;
    }
  };

  const getBorderColor = () => {
    switch (toast.type) {
      case 'success':
        return 'border-emerald-500/30';
      case 'error':
        return 'border-red-500/30';
      case 'info':
      default:
        return 'border-sky-500/30';
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9, y: 10 }}
      transition={{ duration: 0.2 }}
      role={toast.type === 'error' ? 'alert' : 'status'}
      aria-live="polite"
      className={`max-w-sm w-full bg-[#141414] ${getBorderColor()} shadow-2xl rounded-xl p-4 flex items-start gap-3 relative pointer-events-auto border`}
    >
      <div className="mt-0.5">{getIcon()}</div>
      <div className="flex-1 min-w-0 pr-2">
        {toast.title && (
          <h4 className="text-xs font-extrabold text-[#EDEDED] leading-tight mb-0.5 font-mono">
            {toast.title}
          </h4>
        )}
        <p className="text-xs text-[#A1A1AA] leading-relaxed break-words">
          {toast.message}
        </p>
      </div>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(toast.id)}
        className="text-[#71717A] hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors shrink-0"
      >
        <X size={14} />
      </button>
    </motion.div>
  );
};

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div
      aria-label="Notifications"
      className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none px-4 sm:px-0"
    >
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  );
};

export interface ClipboardToastBadgeProps {
  isVisible: boolean;
  message?: string;
  badge?: string;
  onDismiss?: () => void;
}

export const ClipboardToastBadge: React.FC<ClipboardToastBadgeProps> = ({
  isVisible,
  message = 'AI prompt copied to clipboard',
  badge = '[COPIED]',
  onDismiss,
}) => {
  if (!isVisible) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-5 right-5 z-50 flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl bg-[#0A0A0A] border border-white/20 text-white shadow-2xl shadow-black/80 backdrop-blur-md pointer-events-auto transition-all duration-150 animate-in fade-in slide-in-from-bottom-2"
    >
      <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono font-bold text-[10px] tracking-wider border border-emerald-500/30">
        {badge}
      </span>
      <span className="text-xs font-mono text-zinc-200">
        {message}
      </span>
      {onDismiss && (
        <button
          type="button"
          aria-label="Dismiss toast"
          onClick={onDismiss}
          className="text-zinc-400 hover:text-white ml-1 p-0.5 rounded transition-colors cursor-pointer"
        >
          <X size={12} />
        </button>
      )}
    </div>
  );
};

export function useClipboardToast(durationMs = 2500) {
  const [state, setState] = React.useState({
    isVisible: false,
    message: 'AI prompt copied to clipboard',
    badge: '[COPIED]',
  });
  const timerRef = React.useRef<NodeJS.Timeout | null>(null);

  const showToast = React.useCallback(
    (message = 'AI prompt copied to clipboard', badge = '[COPIED]') => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
      setState({ isVisible: true, message, badge });
      timerRef.current = setTimeout(() => {
        setState((prev) => ({ ...prev, isVisible: false }));
      }, durationMs);
    },
    [durationMs]
  );

  const hideToast = React.useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    setState((prev) => ({ ...prev, isVisible: false }));
  }, []);

  React.useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  return {
    isVisible: state.isVisible,
    message: state.message,
    badge: state.badge,
    showToast,
    hideToast,
  };
}

