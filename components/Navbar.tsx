'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ArrowUpRight } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';
import { UserProfile } from '@/components/auth/AuthModal';

interface NavbarProps {
  onToggleDashboard?: () => void;
  showDashboard?: boolean;
  user?: UserProfile | null;
}

export const Navbar: React.FC<NavbarProps> = ({ onToggleDashboard, showDashboard, user }) => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(user || null);

  useEffect(() => {
    if (user !== undefined) {
      setCurrentUser(user);
      return;
    }

    const loadUser = () => {
      try {
        let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!savedUserStr && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            savedUserStr = decodeURIComponent(match[3]);
          }
        }
        if (savedUserStr) {
          const parsed = JSON.parse(savedUserStr);
          if (parsed && parsed.isLoggedIn) {
            setCurrentUser(parsed);
            return;
          }
        }
        setCurrentUser(null);
      } catch {
        setCurrentUser(null);
      }
    };

    loadUser();
    window.addEventListener('storage', loadUser);
    return () => window.removeEventListener('storage', loadUser);
  }, [user]);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (!mobileMenuOpen) return;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.overflow = 'hidden';
    if (scrollbarWidth > 0) {
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileMenuOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = 'unset';
      document.body.style.paddingRight = '';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [mobileMenuOpen]);

  // On the landing page the hero already has the scan box; elsewhere fall back to the dashboard
  const focusHeroScan = () => {
    const input = document.getElementById('hero-repo-input');
    if (input) {
      input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      (input as HTMLInputElement).focus({ preventScroll: true });
    } else {
      window.location.href = '/dashboard';
    }
  };

  const navLinks = [
    { label: 'How it works', href: '#workflow' },
    { label: 'Features', href: '#features' },
    { label: 'Benchmark', href: '#benchmark' },
    { label: 'Pricing', href: '#pricing' },
    { label: 'FAQ', href: '#faq' },
  ];

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-[#0A0A0A]/90 backdrop-blur-md border-b border-white/10 py-4'
            : 'bg-transparent py-5'
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          {/* Logo */}
          <a href="/" className="flex items-center group" aria-label="Zelsis Home">
            <ZelsisLogo size="md" />
          </a>

          {/* Desktop Nav Links */}
          <nav className="hidden md:flex items-center gap-7">
            {navLinks.length === 0 ? (
              <span className="text-xs text-[#A1A1AA]">No navigation items</span>
            ) : (
              navLinks.map((link) => (
                <a
                  key={link.label}
                  href={link.href}
                  className="relative text-xs font-semibold text-[#A1A1AA] hover:text-white tracking-wider transition-colors py-1 group"
                >
                  {link.label}
                  <span className="absolute bottom-0 left-0 w-full h-[1.5px] bg-white scale-x-0 group-hover:scale-x-100 transition-transform origin-left duration-200" />
                </a>
              ))
            )}
          </nav>

          {/* Action Buttons */}
          <div className="hidden md:flex items-center gap-3">
            {currentUser && currentUser.isLoggedIn ? (
              <>
                <a
                  href="/dashboard?view=settings"
                  className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono text-[#A1A1AA] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all"
                  title={currentUser.email}
                >
                  <span className="max-w-[120px] truncate">{currentUser.name || currentUser.email.split('@')[0]}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider bg-white/10 text-white border border-white/20">
                    {currentUser.tier || 'Pro'}
                  </span>
                </a>

                <button
                  onClick={() => { window.location.href = '/dashboard'; }}
                  className="px-3.5 py-1.5 rounded-md text-xs font-bold tracking-wider uppercase bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-1 shadow-sm cursor-pointer"
                >
                  <span>Dashboard</span>
                  <ArrowUpRight size={13} />
                </button>
              </>
            ) : (
              <>
                <a
                  href="/dashboard?auth=signin"
                  className="px-3.5 py-1.5 rounded-md text-xs font-semibold tracking-wider uppercase text-[#EDEDED] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all"
                >
                  Sign In
                </a>

                <button
                  onClick={focusHeroScan}
                  className="px-3.5 py-1.5 rounded-md text-xs font-bold tracking-wider uppercase bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-1 shadow-sm cursor-pointer"
                >
                  <span>Scan Repo</span>
                  <ArrowUpRight size={13} />
                </button>
              </>
            )}
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="md:hidden min-w-[44px] min-h-[44px] flex items-center justify-center p-2 text-[#94A3B8] hover:text-white transition-colors rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-white/20"
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </header>

      {/* Mobile Menu Overlay */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed inset-0 z-40 bg-[#0A0A0A] flex flex-col justify-center px-8 py-20 md:hidden"
            onClick={(e) => { if (e.target === e.currentTarget) setMobileMenuOpen(false); }}
          >
            <nav className="flex flex-col gap-6">
              {navLinks.map((link, idx) => (
                <motion.a
                  key={link.label}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  className="text-3xl font-extrabold text-[#F5F3EF] hover:text-white tracking-wider transition-colors"
                >
                  {link.label}
                </motion.a>
              ))}
            </nav>

            <div className="mt-12 flex flex-col gap-4">
              {currentUser && currentUser.isLoggedIn ? (
                <>
                  <div className="flex items-center justify-between px-4 py-3 rounded-lg bg-white/5 border border-white/10 text-xs font-mono text-[#A1A1AA]">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-medium truncate max-w-[180px]">
                        {currentUser.name || currentUser.email}
                      </span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-white font-bold uppercase">
                      {currentUser.tier || 'Pro'}
                    </span>
                  </div>

                  <button
                    onClick={() => {
                      setMobileMenuOpen(false);
                      window.location.href = '/dashboard';
                    }}
                    className="btn btn-primary w-full uppercase tracking-widest text-xs py-3 flex items-center justify-center gap-2"
                  >
                    <span>OPEN DASHBOARD</span>
                    <ArrowUpRight size={14} />
                  </button>
                </>
              ) : (
                <>
                  <a
                    href="/dashboard?auth=signin"
                    onClick={() => setMobileMenuOpen(false)}
                    className="btn btn-secondary w-full uppercase tracking-widest text-xs py-3 text-center"
                  >
                    Sign In / Register
                  </a>

                  <button
                    onClick={() => {
                      setMobileMenuOpen(false);
                      focusHeroScan();
                    }}
                    className="btn btn-primary w-full uppercase tracking-widest text-xs py-3 flex items-center justify-center gap-2"
                  >
                    <span>SCAN REPOSITORY</span>
                    <ArrowUpRight size={14} />
                  </button>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};
