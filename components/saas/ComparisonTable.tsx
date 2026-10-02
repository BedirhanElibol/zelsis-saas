'use client';

import React, { useState, useEffect } from 'react';
import { Check, X, Shield, ArrowRight, Lock, ExternalLink, Zap } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';
import { formatCount, RULE_COUNTS } from '@/lib/rule-status';
import { ENTERPRISE_SEAT_LIMIT, PLAN_PRICES, priceLabel, SUPPORT_TERMS, ZELSIS_PRICING_PLANS } from '@/data/pricing-plans';
import { contactMailto } from '@/lib/contact';

interface ComparisonItem {
  name: string;
  description: string;
  free: string | boolean;
  pro: string | boolean;
  enterprise: string | boolean;
}

interface ComparisonCategory {
  title: string;
  items: ComparisonItem[];
}

const planFor = (id: string) => ZELSIS_PRICING_PLANS.find((p) => p.id === id)!;
const MOBILE_PLANS = [
  { tier: 'Free' as const, plan: planFor('free') },
  { tier: 'Pro' as const, plan: planFor('zelsis-core') },
  { tier: 'Enterprise' as const, plan: planFor('vibecare') },
];

export const ComparisonTable: React.FC = () => {
  const router = useRouter();

  const POLAR_PRO_URL = 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC';
  const POLAR_ENTERPRISE_URL = 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od';

  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>('signup');
  const [pendingPlan, setPendingPlan] = useState<'Pro' | 'Enterprise' | null>(null);

  useEffect(() => {
    const loadUser = () => {
      try {
        let saved = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!saved && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            saved = decodeURIComponent(match[3]);
          }
        }
        if (saved) {
          const parsed = JSON.parse(saved);
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
  }, []);

  const handleSelectPlan = (plan: 'Pro' | 'Enterprise') => {
    if (!currentUser || !currentUser.isLoggedIn) {
      setPendingPlan(plan);
      setAuthInitialMode('signup');
      setIsAuthModalOpen(true);
      return;
    }

    const currentTier = currentUser.tier || 'Free';
    if (plan === 'Pro') {
      if (currentTier === 'Pro' || currentTier === 'Enterprise') {
        window.open('https://polar.sh/purchases', '_blank');
        return;
      }
      router.push('/checkout?plan=zelsis-core');
    } else if (plan === 'Enterprise') {
      if (currentTier === 'Enterprise') {
        window.open('https://polar.sh/purchases', '_blank');
        return;
      }
      router.push('/checkout?plan=vibecare');
    }
  };

  const handleModalAuthSuccess = (authedUser: UserProfile) => {
    setCurrentUser(authedUser);
    setIsAuthModalOpen(false);
    if (pendingPlan === 'Enterprise') {
      router.push('/checkout?plan=vibecare');
    } else if (pendingPlan === 'Pro') {
      router.push('/checkout?plan=zelsis-core');
    }
    setPendingPlan(null);
  };

  const categories: ComparisonCategory[] = [
    {
      title: 'Audit Capacity & Concurrency',
      items: [
        {
          name: 'Monthly Live Scans',
          description: 'Maximum pre-flight audits performed per monthly billing cycle',
          free: '3 Scans / month (Strict Cap)',
          pro: 'Unlimited Scans (fair-use rate limits)',
          enterprise: 'Unlimited Scans (fair-use rate limits)'
        },
        {
          name: 'Repository Scope & Privacy',
          description: 'Supported repository types and permission boundary',
          free: '1 Public Repository only',
          pro: 'Unlimited Public & Private Repos',
          enterprise: 'Unlimited Public & Private Repos'
        },
      ]
    },
    {
      title: 'Security & Inspection Depth',
      items: [
        {
          name: 'Static & Pattern-Based Rule Inventory',
          description: 'Coverage of security vulnerabilities, misconfigurations, and anti-patterns',
          free: `All ${formatCount(RULE_COUNTS.gating)} active rules`,
          pro: `All ${formatCount(RULE_COUNTS.gating)} active rules`,
          enterprise: `All ${formatCount(RULE_COUNTS.gating)} active rules`
        },
        {
          name: 'Known Vulnerable Dependencies',
          description: 'Exact lockfile versions checked against OSV.dev (npm, PyPI, Go, RubyGems, Packagist, crates.io, Maven)',
          free: 'Included on every plan',
          pro: 'Included on every plan',
          enterprise: 'Included on every plan'
        },
        {
          name: 'Secret & API Key Leak Detection',
          description: 'Scanning engine for hardcoded tokens, AWS keys, and private credentials',
          free: 'Same secret rules on every plan',
          pro: 'Same secret rules on every plan',
          enterprise: 'Same secret rules on every plan'
        },
        {
          name: 'Repository Size Scalability',
          description: 'Analysis support for large multi-package and monorepo codebases',
          free: 'Same engine on every plan',
          pro: 'Same engine on every plan',
          enterprise: 'Same engine on every plan'
        },
        {
          name: 'Source Code Retention',
          description: 'Repositories are scanned in memory; only findings are saved',
          free: 'Source not stored; findings keep short snippets',
          pro: 'Source not stored; findings keep short snippets',
          enterprise: 'Source not stored; findings keep short snippets'
        }
      ]
    },
    {
      title: 'AI Remediation & Surgical Diffs',
      items: [
        {
          name: 'Surgical Unified Git Diffs',
          description: 'Visual before/after line-by-line code replacement for every detected flaw',
          free: 'Line Numbers only (No Diffs)',
          pro: 'Interactive Unified Git Diffs',
          enterprise: 'Interactive Unified Git Diffs'
        },
        {
          name: 'Context-Engineered AI Prompts',
          description: 'Tailored prompts with CVE context for any AI coding assistant',
          free: '1 Lifetime Trial Prompt',
          pro: 'Unlimited 1-Click Fix Prompts',
          enterprise: 'Unlimited 1-Click Fix Prompts'
        },
      ]
    },
    {
      title: 'CI/CD & Production Gates',
      items: [
        {
          name: 'CI Release Gate',
          description: 'HTTP gate API that fails the CI job when the gate fails (GitHub Actions, GitLab CI or any runner)',
          free: 'Dashboard scans only',
          pro: 'Gate API + generated CI workflows',
          enterprise: 'Gate API + generated CI workflows'
        },
        {
          name: 'Policy-as-Code (.zelsisrc.json)',
          description: 'Ignore rules or paths, turn off pillars, choose smart / strict / advisory gating with a minimum score',
          free: 'Included',
          pro: 'Included',
          enterprise: 'Included'
        }
      ]
    },
    {
      title: 'Executive Compliance & Reports',
      items: [
        {
          name: 'PDF Readiness Report',
          description: 'Downloadable PDF of the gate result, score and findings for stakeholders',
          free: false,
          pro: 'PDF Report Export',
          enterprise: 'PDF Report Export'
        },
        {
          name: 'Issue Tracker Export',
          description: 'Direct export to team tracking systems (Jira, Linear, GitHub Issues)',
          free: 'Manual Markdown Copy',
          pro: '1-Click Jira & Linear Markdown',
          enterprise: '1-Click Jira & Linear Markdown'
        },
        {
          name: 'Audit History Retention',
          description: 'Time window for historical telemetry, scan logs, and trend analytics',
          free: '7 Days Retention',
          pro: '90 Days Historical Telemetry',
          enterprise: 'Unlimited Audit History & Compliance Logs'
        }
      ]
    },
    {
      title: 'Operational SLA & Support',
      items: [
        {
          name: 'Technical Support Channel',
          description: 'Direct engineering support and issue escalation channel',
          free: SUPPORT_TERMS.Free,
          pro: SUPPORT_TERMS.Pro,
          enterprise: SUPPORT_TERMS.Enterprise
        },
        {
          name: 'Team Workspace & Roles',
          description: 'Shared workspace with invite links and owner / admin / member roles; every member gets Pro',
          free: false,
          pro: false,
          enterprise: `${ENTERPRISE_SEAT_LIMIT} seats included`
        },
        {
          name: 'Organization Gate Policy',
          description: 'One .zelsisrc policy (strategy, minimum score, ignored rules and paths) enforced on all member scans and the CI gate',
          free: false,
          pro: false,
          enterprise: 'Included'
        },
        {
          name: 'White-label SOC 2 Report',
          description: 'PDF report with your company name and logo, findings mapped to SOC 2 Trust Services Criteria',
          free: false,
          pro: false,
          enterprise: 'Included'
        }
      ]
    }
  ];

  const renderCellContent = (val: string | boolean) => {
    if (typeof val === 'boolean') {
      return val ? (
        <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-white/10 text-white">
          <Check size={12} className="stroke-[2.5]" />
          <span className="sr-only">Included</span>
        </span>
      ) : (
        <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-white/5 text-zinc-400">
          <X size={12} className="stroke-[2]" />
          <span className="sr-only">Not included</span>
        </span>
      );
    }

    const isLocked = val.toLowerCase().includes('locked') || val.toLowerCase().includes('not available') || val.toLowerCase().includes('strict cap');

    return (
      <span className={`text-xs font-mono font-medium leading-tight ${isLocked ? 'text-zinc-400' : 'text-zinc-200'}`}>
        {val}
      </span>
    );
  };

  const currentTier = currentUser?.tier || 'Free';
  const isLoggedIn = Boolean(currentUser?.isLoggedIn);

  return (
    <section id="pricing" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10 font-sans relative">
      <div id="comparison" className="absolute -top-24 left-0 pointer-events-none" />

      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center text-xs font-mono uppercase tracking-widest text-zinc-400 bg-white/5 px-3 py-1 rounded-full border border-white/10 self-center">
            <span>Pricing</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight [text-wrap:balance]">
            Start free, upgrade when you ship
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed">
            Every plan runs the same rules. Paid plans remove the limits, unlock private repositories and the CI gate, and add team features.
          </p>
        </div>

        {/* Mobile: stacked plan cards (the matrix needs ~760px) */}
        <div className="md:hidden flex flex-col gap-4">
          {MOBILE_PLANS.map(({ tier, plan }) => {
            const isCurrent = isLoggedIn && currentTier === tier;
            return (
              <div
                key={plan.id}
                className={`rounded-2xl border p-5 flex flex-col gap-4 bg-[#121216] ${plan.isPopular ? 'border-white/30' : 'border-white/10'}`}
              >
                <div className="flex items-baseline justify-between gap-3">
                  <h3 className="text-lg font-bold text-white">{tier}</h3>
                  <div className="text-2xl font-extrabold text-white font-mono">
                    ${plan.priceMonthly}
                    <span className="text-sm font-normal text-zinc-400"> / month</span>
                  </div>
                </div>
                <p className="text-sm text-zinc-400">{plan.description}</p>
                <ul className="flex flex-col gap-2">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-2 text-sm text-zinc-200">
                      <Check size={16} className="text-white shrink-0 mt-0.5" aria-hidden="true" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
                {isCurrent ? (
                  <div className="min-h-11 flex items-center justify-center rounded-lg border border-white/15 text-sm text-zinc-300">
                    Current plan
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => (tier === 'Free' ? router.push('/dashboard') : handleSelectPlan(tier))}
                    className={`min-h-11 rounded-lg text-sm font-semibold transition-colors ${
                      plan.isPopular ? 'bg-white text-black hover:bg-neutral-200' : 'bg-white/10 text-white border border-white/20 hover:bg-white/15'
                    }`}
                  >
                    {tier === 'Free' ? 'Start free' : `Get ${tier}`}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {/* Matrix Container */}
        <div className="hidden md:block rounded-2xl border border-white/15 bg-[#121216] overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[760px]">
              <caption className="sr-only">Feature comparison of the Free, Pro and Enterprise plans</caption>
              <thead>
                <tr className="border-b border-white/15 bg-[#0E0E12]">
                  <th className="p-5 sm:p-6 text-xs font-mono uppercase tracking-wider text-zinc-400 w-[34%] align-bottom">
                    <span className="text-white font-bold block text-sm">Feature / Requirement</span>
                    <span className="text-zinc-400 text-[11px] font-normal lowercase tracking-normal">feature breakdown &amp; boundaries</span>
                  </th>

                  {/* Free Plan Header */}
                  <th className="p-5 sm:p-6 text-xs font-mono tracking-wider text-zinc-300 w-[22%] align-bottom border-l border-white/10">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-zinc-400 uppercase tracking-widest">Free</span>
                        {isLoggedIn && currentTier === 'Free' && (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-zinc-500/10 text-zinc-300 px-2 py-0.5 rounded border border-zinc-500/20">
                            Active
                          </span>
                        )}
                      </div>
                      <div className="text-2xl font-extrabold text-white font-mono">$0</div>
                      <span className="text-[11px] text-zinc-400 font-sans">For hobbyists and testing public repositories</span>

                      {isLoggedIn && currentTier === 'Free' ? (
                        <button
                          type="button"
                          onClick={() => router.push('/dashboard')}
                          className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 border border-white/20 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                        >
                          <span>Current Plan</span>
                        </button>
                      ) : isLoggedIn && (currentTier === 'Pro' || currentTier === 'Enterprise') ? (
                        <div className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white/5 border border-white/10 text-zinc-400 text-sm font-semibold">
                          Included Baseline
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => router.push('/dashboard')}
                          className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 hover:bg-white/15 border border-white/15 text-white text-sm font-semibold transition-colors cursor-pointer"
                        >
                          Start free
                        </button>
                      )}
                    </div>
                  </th>

                  {/* Pro Plan Header */}
                  <th className="p-5 sm:p-6 text-xs font-mono tracking-wider text-white w-[22%] align-bottom bg-white/[0.03] border-x border-white/20 relative">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-extrabold text-white uppercase tracking-widest">Pro</span>
                        {isLoggedIn && currentTier === 'Pro' ? (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-white/10 text-white px-2 py-0.5 rounded border border-white/20 flex items-center gap-1">
                            <span>Active Plan</span>
                          </span>
                        ) : isLoggedIn && currentTier === 'Enterprise' ? (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-white/10 text-zinc-300 px-2 py-0.5 rounded border border-white/15">
                            Included
                          </span>
                        ) : (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-white/10 text-zinc-300 px-2 py-0.5 rounded border border-white/20">
                            Recommended
                          </span>
                        )}
                      </div>
                      <div className="text-2xl font-extrabold text-white font-mono">
                        ${PLAN_PRICES.Pro} <span className="text-xs text-zinc-400 font-normal">/ month</span>
                      </div>
                      <span className="text-[11px] text-zinc-400 font-sans">For professional developers and shipping teams</span>

                      {isLoggedIn && currentTier === 'Pro' ? (
                        <div className="flex flex-col gap-1 mt-2">
                          <a
                            href="https://polar.sh/purchases"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 hover:bg-white/15 border border-white/20 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 shadow cursor-pointer"
                          >
                            <span>Manage at Polar</span>
                            <ExternalLink size={12} />
                          </a>
                          <span className="text-[10px] text-zinc-400">Active subscription</span>
                        </div>
                      ) : isLoggedIn && currentTier === 'Enterprise' ? (
                        <div className="flex flex-col gap-1 mt-2">
                          <div className="w-full min-h-11 px-3 rounded-lg font-sans bg-white/5 border border-white/10 text-zinc-400 text-sm font-semibold">
                            Included in Enterprise
                          </div>
                          <span className="text-[10px] text-zinc-400">All Pro features active</span>
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleSelectPlan('Pro')}
                          className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white hover:bg-zinc-200 text-black text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 shadow cursor-pointer"
                        >
                          <span>Get Pro</span>
                          <ArrowRight size={13} />
                        </button>
                      )}
                    </div>
                  </th>

                  {/* Enterprise Plan Header */}
                  <th className="p-5 sm:p-6 text-xs font-mono tracking-wider text-zinc-300 w-[22%] align-bottom border-l border-white/10">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-zinc-400 uppercase tracking-widest">Enterprise</span>
                        {isLoggedIn && currentTier === 'Enterprise' ? (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-white/10 text-white px-2 py-0.5 rounded border border-white/20 flex items-center gap-1">
                            <span>Active Plan</span>
                          </span>
                        ) : isLoggedIn && currentTier === 'Pro' ? (
                          <span className="text-[11px] font-bold uppercase tracking-wider bg-white/10 text-zinc-300 px-2 py-0.5 rounded border border-white/20">
                            Upgrade
                          </span>
                        ) : null}
                      </div>
                      <div className="text-2xl font-extrabold text-white font-mono">
                        ${PLAN_PRICES.Enterprise} <span className="text-xs text-zinc-400 font-normal">/ month</span>
                      </div>
                      <span className="text-[11px] text-zinc-400 font-sans">For teams: shared workspace, org policy &amp; SOC 2 reports</span>

                      {isLoggedIn && currentTier === 'Enterprise' ? (
                        <div className="flex flex-col gap-1 mt-2">
                          <a
                            href="https://polar.sh/purchases"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 hover:bg-white/15 border border-white/20 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 shadow cursor-pointer"
                          >
                            <span>Manage at Polar</span>
                            <ExternalLink size={12} />
                          </a>
                          <span className="text-[10px] text-zinc-400">Enterprise plan active</span>
                        </div>
                      ) : isLoggedIn && currentTier === 'Pro' ? (
                        <button
                          type="button"
                          onClick={() => handleSelectPlan('Enterprise')}
                          className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 hover:bg-white/15 border border-white/20 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 shadow cursor-pointer"
                        >
                          <span>Upgrade to Enterprise</span>
                          <ArrowRight size={13} />
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleSelectPlan('Enterprise')}
                          className="mt-2 w-full min-h-11 px-3 rounded-lg font-sans bg-white/10 hover:bg-white/15 border border-white/20 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                        >
                          <span>Get Enterprise</span>
                          <ArrowRight size={13} />
                        </button>
                      )}
                    </div>
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5 text-xs sm:text-sm">
                {categories.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center bg-[#0A0A0A] text-xs text-zinc-400 font-mono">
                      No comparison categories available.
                    </td>
                  </tr>
                ) : (
                  categories.map((category, catIdx) => (
                    <React.Fragment key={catIdx}>
                      {/* Category Divider Header */}
                      <tr className="bg-[#0A0A0E] border-y border-white/10">
                        <td colSpan={4} className="px-5 sm:px-6 py-3 text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-300">
                          {category.title}
                        </td>
                      </tr>

                      {/* Category Items */}
                      {category.items.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="p-4 text-xs font-mono text-zinc-400">
                            No criteria defined for this category.
                          </td>
                        </tr>
                      ) : (
                        category.items.map((item, itemIdx) => (
                          <tr key={itemIdx} className="hover:bg-white/[0.02] transition-colors">
                            <th scope="row" className="p-4 sm:p-5 font-normal text-left">
                              <div className="font-bold text-white mb-0.5 text-xs sm:text-sm">{item.name}</div>
                              <div className="text-xs text-zinc-400 font-sans leading-snug">{item.description}</div>
                            </th>

                            {/* Free Value */}
                            <td className="p-4 sm:p-5 border-l border-white/10">
                              {renderCellContent(item.free)}
                            </td>

                            {/* Pro Value */}
                            <td className="p-4 sm:p-5 bg-white/[0.02] border-x border-white/10 text-zinc-200">
                              {renderCellContent(item.pro)}
                            </td>

                            {/* Enterprise Value */}
                            <td className="p-4 sm:p-5 border-l border-white/10">
                              {renderCellContent(item.enterprise)}
                            </td>
                          </tr>
                        ))
                      )}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Bottom Bar CTA */}
          <div className="p-6 bg-[#0E0E12] border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-xs font-mono text-zinc-400 text-center sm:text-left">
              <span>Looking for custom on-premise deployments or custom procurement?</span>
              <strong className="text-white block sm:inline sm:ml-1">Instant digital delivery on all plans.</strong>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => router.push('/dashboard')}
                className="px-4 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-wider bg-white/10 hover:bg-white/15 text-white transition-all cursor-pointer"
              >
                Launch Console
              </button>

              {isLoggedIn && currentTier === 'Enterprise' ? (
                <a
                  href="https://polar.sh/purchases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-5 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-wider bg-white/10 hover:bg-white/15 border border-white/20 text-white transition-all flex items-center gap-2 cursor-pointer"
                >
                  <span>Manage Enterprise Plan</span>
                  <ExternalLink size={13} />
                </a>
              ) : isLoggedIn && currentTier === 'Pro' ? (
                <button
                  type="button"
                  onClick={() => handleSelectPlan('Enterprise')}
                  className="px-5 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-2 shadow cursor-pointer"
                >
                  <span>Upgrade to Enterprise ({priceLabel('Enterprise')})</span>
                  <ArrowRight size={14} />
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => handleSelectPlan('Pro')}
                  className="px-5 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-2 shadow cursor-pointer"
                >
                  <span>Upgrade to Pro ({priceLabel('Pro')})</span>
                  <ArrowRight size={14} />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Custom Enterprise Inquiries Banner */}
        <div className="p-4 sm:p-6 rounded-xl border border-white/10 bg-[#0E0E12] flex flex-col sm:flex-row items-center justify-between gap-4 text-center sm:text-left">
          <div>
            <h3 className="text-sm font-bold text-white mb-1">Looking for custom security requirements or bespoke invoicing?</h3>
            <p className="text-xs text-zinc-400">We offer custom organization onboarding, volume team pricing, and security questionnaire assistance.</p>
          </div>
          <a
            href={contactMailto('Enterprise inquiry')}
            className="px-4 min-h-11 inline-flex items-center rounded-lg text-sm font-semibold bg-white/10 hover:bg-white/15 border border-white/20 text-white transition-all shrink-0 cursor-pointer"
          >
            Contact us
          </a>
        </div>
      </div>

      {/* Auth Modal for Unauthenticated Checkout Actions */}
      <AuthModal
        isOpen={isAuthModalOpen && !currentUser?.isLoggedIn}
        onClose={() => {
          setIsAuthModalOpen(false);
          setPendingPlan(null);
        }}
        initialMode={authInitialMode}
        onLoginSuccess={handleModalAuthSuccess}
      />
    </section>
  );
};

