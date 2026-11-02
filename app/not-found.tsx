import React from 'react';
import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F3EF] flex flex-col items-center justify-center p-4 sm:p-8">
      {/* Breadcrumb Header */}
      <nav aria-label="Breadcrumb" className="mb-6 flex items-center gap-2 text-xs font-mono text-[#A1A1AA]">
        <Link href="/" className="hover:text-white transition-colors flex items-center gap-1">
          <span>Zelsis</span>
        </Link>
        <Link href="/dashboard" className="hover:text-white transition-colors">
          Dashboard
        </Link>
        <span className="text-white font-bold">404 (Not Found)</span>
      </nav>

      <div className="w-full max-w-lg glass-card bg-[#141414] border border-white/15 rounded-2xl p-8 sm:p-10 flex flex-col items-center text-center gap-6 shadow-2xl">
        {/* Monochromatic Status Pill */}
        <div className="px-3 py-1 rounded-md bg-white/10 border border-white/20 text-xs font-mono font-bold uppercase tracking-wider text-white">
          HTTP 404 &bull; Route Missing
        </div>

        {/* 404 Hero Number */}
        <div className="flex flex-col items-center">
          <span className="text-6xl sm:text-7xl font-mono font-black tracking-tight text-white select-none">
            404
          </span>
          <h1 className="text-xl sm:text-2xl font-extrabold text-[#F5F3EF] mt-2">
            Page Not Found
          </h1>
          <p className="text-xs sm:text-sm text-[#A1A1AA] max-w-sm mt-2 leading-relaxed">
            The requested URL or audit route could not be found in the current deployment namespace. It may have moved or been decommissioned.
          </p>
        </div>

        {/* Quick Links Matrix */}
        <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
          <Link
            href="/dashboard"
            className="btn btn-primary py-3 px-4 text-xs font-extrabold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            <span>Go to Dashboard</span>
          </Link>

          <Link
            href="/"
            className="btn btn-secondary py-3 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            <span>Return to Landing</span>
          </Link>
        </div>

        {/* Secondary Helpful Links */}
        <div className="w-full border-t border-white/10 pt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-[#A1A1AA] gap-2">
          <div className="flex items-center gap-1.5 text-white/80 font-mono text-[0.7rem]">
            <span>Zelsis Gate System Online</span>
          </div>

          <Link
            href="/checkout"
            className="inline-flex items-center gap-1 text-[0.72rem] font-bold text-white hover:underline"
          >
            <span>Pricing &amp; Plans</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
