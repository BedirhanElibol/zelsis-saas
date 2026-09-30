'use client';

import React, { useState } from 'react';
import { Finding, InfraRule } from '@/data/schema';
import { INFRA_RULES_CATALOG } from '@/data/mockData';
import { Database, Search, Filter, Copy, CheckCircle2, AlertTriangle, ShieldCheck, AlertOctagon, Terminal, Server, Code } from 'lucide-react';

interface InfraAuditViewProps {
  findings: Finding[];
  onInspectFinding: (f: Finding) => void;
}

export const InfraAuditView: React.FC<InfraAuditViewProps> = ({
  findings,
  onInspectFinding,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | number | null>(null);

  const categories = [
    'ALL',
    'Database Security',
    'Container Security',
    'Secrets & Cloud',
    'API & Network',
    'Infra Hardening',
    'Next.js Security',
  ];

  const filteredRules = INFRA_RULES_CATALOG.filter((rule) => {
    const safeSearch = (searchTerm || '').toLowerCase();
    const matchesSearch =
      (rule.title || '').toLowerCase().includes(safeSearch) ||
      (rule.description || '').toLowerCase().includes(safeSearch) ||
      (rule.code || '').toLowerCase().includes(safeSearch) ||
      (rule.targetStack || '').toLowerCase().includes(safeSearch) ||
      (rule.category || '').toLowerCase().includes(safeSearch);
    const matchesCat = selectedCategory === 'ALL' || rule.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  const copyPrompt = (rule: InfraRule) => {
    navigator.clipboard.writeText(rule.remediationPrompt);
    setCopiedId(rule.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const infraFindings = findings.filter((f) => f.type === 'INFRA_DATABASE' && f.status === 'OPEN');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header Info */}
      <div className="bg-[#141414] border border-cyan-500/20 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Database size={24} className="text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] m-0">
                Zelsis Infrastructure, Cloud &amp; Universal Database Gate
              </h1>
              <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest">
                Postgres · MySQL · MongoDB · Redis · SQLite · Docker · Cloud Gate
              </span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            Architectural release gate verifying universal multi-database isolation (Postgres RLS, MySQL, MongoDB sanitization, Redis cache safety, SQLite boundaries), container privileges, exposed secrets, and API mutations.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="px-4 py-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-bold flex items-center gap-2">
            <Server size={16} />
            <span>Infra Gate: ENFORCED</span>
          </div>
          {infraFindings.length > 0 && (
            <div className="px-3.5 py-2 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono font-bold">
              {infraFindings.length} Open Issue{infraFindings.length > 1 ? 's' : ''}
            </div>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex gap-4 flex-wrap items-center">
        <div className="flex items-center gap-2.5 bg-[#141414] px-4 py-2.5 rounded-xl border border-white/10 flex-1 min-w-[280px]">
          <Search size={16} className="text-[#A1A1AA]" />
          <input
            id="infra-rules-search-input"
            name="infraRulesSearch"
            aria-label="Search infrastructure rules"
            type="text"
            placeholder="Search rules, stacks (PostgreSQL, MySQL, MongoDB, Redis, SQLite, Docker), or categories..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none outline-none focus-visible:ring-1 focus-visible:ring-white/20 text-[#EDEDED] w-full text-xs font-mono placeholder:text-zinc-400 rounded"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter size={16} className="text-[#A1A1AA]" />
          <select
            id="infra-category-select"
            name="infraCategory"
            aria-label="Filter infrastructure rules by category"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#141414] text-[#EDEDED] px-3.5 py-2.5 rounded-xl border border-white/10 text-xs font-mono font-bold cursor-pointer outline-none focus-visible:ring-1 focus-visible:ring-white/20"
          >
            {categories.map((c) => (
              <option key={c} value={c} className="bg-[#141414]">
                {c === 'ALL' ? 'All Infra Categories' : c}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rules Catalog Grid */}
      {filteredRules.length === 0 ? (
        <div className="bg-[#141414] border border-white/10 rounded-xl p-10 text-center text-[#A1A1AA] text-xs font-mono">
          No infrastructure rules match your search or filter.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredRules.map((rule) => {
          const matchingFindings = findings.filter(
            (f) => (f.ruleId === rule.id || (typeof rule.id === 'number' && f.ruleId === rule.id - 3000)) && f.status === 'OPEN'
          );
          const hasOpenViolation = matchingFindings.length > 0;

          return (
            <div
              key={rule.id}
              className={`bg-[#141414] border rounded-xl p-5 flex flex-col justify-between transition-all ${
                hasOpenViolation
                  ? 'border-rose-500/40 bg-rose-950/10'
                  : 'border-white/10 hover:border-cyan-500/30'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                      {rule.code}
                    </span>
                    <span className="text-[11px] font-mono text-zinc-400 bg-white/5 px-2 py-0.5 rounded">
                      {rule.targetStack}
                    </span>
                  </div>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      rule.riskLevel === 'CRITICAL'
                        ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        : rule.riskLevel === 'HIGH'
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                    }`}
                  >
                    {rule.riskLevel}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-[#EDEDED] mb-2">{rule.title}</h3>
                <p className="text-xs text-[#A1A1AA] leading-relaxed mb-4">{rule.description}</p>

                <div className="bg-black/30 border border-white/5 rounded-lg p-3 mb-4">
                  <span className="text-[10px] font-mono font-bold text-[#EDEDED] uppercase tracking-wider block mb-1">
                    Verification Control
                  </span>
                  <p className="text-xs text-zinc-400 font-mono leading-relaxed m-0">
                    {rule.verificationControl}
                  </p>
                </div>

                {rule.sampleDiff && (
                  <div className="bg-black/50 border border-white/5 rounded-lg p-2.5 mb-4 overflow-x-auto font-mono text-[11px]">
                    <span className="text-[10px] text-zinc-400 block mb-1">Standard Patch Preview:</span>
                    <pre className="text-emerald-400 m-0 leading-tight">{rule.sampleDiff}</pre>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between gap-3 pt-3 border-t border-white/5">
                {hasOpenViolation ? (
                  <button
                    onClick={() => onInspectFinding(matchingFindings[0])}
                    className="text-xs font-mono font-bold text-rose-400 hover:text-rose-300 flex items-center gap-1.5 transition-colors"
                  >
                    <AlertTriangle size={14} />
                    <span>Inspect {matchingFindings.length} Violation(s)</span>
                  </button>
                ) : (
                  <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                    <ShieldCheck size={14} />
                    <span>Control Satisfied</span>
                  </div>
                )}

                <button
                  onClick={() => copyPrompt(rule)}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-[#EDEDED] text-xs font-mono transition-colors flex items-center gap-1.5"
                  title="Copy AI Remediation Directive"
                >
                  {copiedId === rule.id ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      <span className="text-emerald-400 font-bold">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy size={13} className="text-zinc-400" />
                      <span>Copy Fix</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
        </div>
      )}
    </div>
  );
};
