'use client';

import React, { useState, useEffect } from 'react';
import { ShieldCheck, ArrowRight } from 'lucide-react';

interface StickyMobileCTAProps {
  onOpenAudit: () => void;
}

export const StickyMobileCTA: React.FC<StickyMobileCTAProps> = ({ onOpenAudit }) => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 300) {
        setIsVisible(true);
      } else {
        setIsVisible(false);
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 z-40 lg:hidden transition-all duration-300 transform translate-y-0">
      <div className="bg-[#141414]/95 backdrop-blur-md border border-white/10 p-3 rounded-xl shadow-2xl flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 text-white flex items-center justify-center shrink-0 shadow-sm">
            <ShieldCheck size={16} />
          </div>
          <div className="truncate">
            <div className="text-xs font-extrabold text-[#FAFAFA] truncate">
              Zelsis Pre-Flight
            </div>
            <div className="text-[10px] text-[#94A3B8] font-mono truncate">
              Instant Security Clearance
            </div>
          </div>
        </div>

        <button
          onClick={onOpenAudit}
          className="btn btn-primary flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider shrink-0 bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm"
        >
          <span>Run Audit</span>
          <ArrowRight size={13} />
        </button>
      </div>
    </div>
  );
};
