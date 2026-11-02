'use client';

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { logger } from '@/lib/logger';
import { safeString } from '@/lib/safe-utils';
import { isChunkLoadError, handleChunkLoadRecovery, clearChunkReloadCooldown } from '@/lib/chunk-reload';

interface Props {
  componentName: string;
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
  resetKeys?: any[];
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ComponentErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    logger.error(`[ComponentErrorBoundary] Caught error in ${this.props.componentName}:`, {
      message: safeString(error?.message),
      stack: safeString(errorInfo?.componentStack)
    });

    // Auto-recover if this was triggered by a stale deployment chunk 404
    if (isChunkLoadError(error)) {
      console.warn(`[ComponentErrorBoundary] Detected chunk error in ${this.props.componentName}, attempting auto-reload...`);
      handleChunkLoadRecovery();
    }
  }

  public componentDidUpdate(prevProps: Props): void {
    if (this.state.hasError && this.props.resetKeys) {
      const hasChanged = this.props.resetKeys.some(
        (key, idx) => key !== (prevProps.resetKeys ? prevProps.resetKeys[idx] : undefined)
      );
      if (hasChanged) {
        this.resetError();
      }
    }
  }

  public resetError = (): void => {
    if (isChunkLoadError(this.state.error)) {
      clearChunkReloadCooldown();
      handleChunkLoadRecovery(true);
      return;
    }
    this.props.onReset?.();
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  public render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const isChunk = isChunkLoadError(this.state.error);

      if (isChunk) {
        return (
          <div className="w-full bg-[#141414] border border-emerald-500/30 rounded-xl p-5 sm:p-6 text-[#EDEDED] flex flex-col gap-4 font-mono shadow-xl">
            <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5 text-emerald-400 text-xs font-bold uppercase tracking-wider">
                <span>{this.props.componentName} Update Available</span>
              </div>
              <button
                onClick={this.resetError}
                className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-xs text-emerald-300 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>Reload to Update</span>
              </button>
            </div>
            <p className="text-xs text-[#A1A1AA] leading-relaxed">
              A newer release of this module is live in production. Reload to apply the updated release without losing your local audit state.
            </p>
          </div>
        );
      }

      return (
        <div className="w-full bg-[#141414] border border-red-500/20 rounded-xl p-5 sm:p-6 text-[#EDEDED] flex flex-col gap-4 font-mono shadow-xl">
          <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2.5 text-red-400 text-xs font-bold uppercase tracking-wider">
              <span>{this.props.componentName} Temporarily Unavailable</span>
            </div>
            <button
              onClick={this.resetError}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs text-white flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>Retry Component</span>
            </button>
          </div>
          <p className="text-xs text-[#A1A1AA] leading-relaxed">
            An isolated exception occurred while rendering this module. Sibling components and your active release gate session remain unaffected.
          </p>
          {process.env.NODE_ENV !== 'production' && this.state.error && (
            <div className="bg-[#0A0A0A] p-3 rounded-lg border border-white/5 text-[11px] text-red-300 overflow-x-auto whitespace-pre-wrap">
              {safeString(this.state.error.message)}
            </div>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}
