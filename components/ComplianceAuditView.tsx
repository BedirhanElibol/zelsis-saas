'use client';

import React, { useState } from 'react';
import { Finding, ComplianceRule } from '@/data/schema';
import { COMPLIANCE_RULES_CATALOG } from '@/data/mockData';
import { Scale, Search, Filter, Copy, CheckCircle2, AlertTriangle, ShieldCheck, AlertOctagon } from 'lucide-react';

interface ComplianceAuditViewProps {
  findings: Finding[];
  onInspectFinding: (f: Finding) => void;
}

export const ComplianceAuditView: React.FC<ComplianceAuditViewProps> = ({
  findings,
  onInspectFinding,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | number | null>(null);

  const categories = [
    'ALL',
    'Transparency & Notice',
    'Consent & Tracking',
    'Data Collection & Forms',
    'Privacy by Design',
    'Payment Card Security',
  ];

  const filteredRules = COMPLIANCE_RULES_CATALOG.filter((rule) => {
    const safeSearch = (searchTerm || '').toLowerCase();
    const matchesSearch =
      (rule.title || '').toLowerCase().includes(safeSearch) ||
      (rule.description || '').toLowerCase().includes(safeSearch) ||
      (rule.code || '').toLowerCase().includes(safeSearch) ||
      (rule.legalFramework || '').toLowerCase().includes(safeSearch) ||
      (rule.penaltyExposure || '').toLowerCase().includes(safeSearch);
    const matchesCat = selectedCategory === 'ALL' || rule.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  const copyPrompt = (rule: ComplianceRule) => {
    navigator.clipboard.writeText(rule.remediationPrompt);
    setCopiedId(rule.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header Info */}
      <div className="bg-[#141414] border border-amber-500/20 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
              <Scale size={24} className="text-amber-400" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] m-0">
                Zelsis Legal, Privacy &amp; Regulatory Pre-Flight Gate
              </h1>
              <span className="text-[11px] font-mono font-bold text-amber-400 uppercase tracking-widest">
                GDPR · CCPA · ePrivacy Directive · FTC Act · PCI-DSS v4.0
              </span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            Statutory release gate enforcing global privacy regulations, cookie consent parity, transparent notices, PII isolation, and payment security controls prior to production deployment.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="px-4 py-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono font-bold flex items-center gap-2">
            <AlertOctagon size={16} />
            <span>Active Release Gate: ENFORCED</span>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex gap-4 flex-wrap items-center">
        <div className="flex items-center gap-2.5 bg-[#141414] px-4 py-2.5 rounded-xl border border-white/10 flex-1 min-w-[280px]">
          <Search size={16} className="text-[#A1A1AA]" />
          <input
            id="compliance-search-input"
            name="complianceSearch"
            aria-label="Search compliance rules or legal frameworks"
            type="text"
            placeholder="Search rules, legal frameworks (GDPR, CCPA), or penalties..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none outline-none focus-visible:ring-1 focus-visible:ring-white/20 text-[#EDEDED] w-full text-xs font-mono placeholder:text-zinc-400 rounded"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter size={16} className="text-[#A1A1AA]" />
          <select
            id="compliance-category-select"
            name="complianceCategory"
            aria-label="Filter compliance framework by category"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#141414] text-[#EDEDED] px-3.5 py-2.5 rounded-xl border border-white/10 text-xs font-mono font-bold cursor-pointer outline-none focus-visible:ring-1 focus-visible:ring-white/20"
          >
            {categories.map((cat) => (
              <option key={cat} value={cat} className="bg-[#141414]">
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rules Catalog Grid */}
      <div className="flex flex-col gap-4">
        {filteredRules.length === 0 ? (
          <div className="bg-[#141414] border border-white/10 rounded-xl p-10 text-center text-[#A1A1AA] text-xs">
            No compliance rules match your active filter or search criteria.
          </div>
        ) : (
          filteredRules.map((rule) => {
            const matchingFinding = findings.find(
              (f) => f.ruleId === rule.id && f.status === 'OPEN'
            );

            return (
              <div
                key={rule.id}
                className="bg-[#141414] border rounded-xl p-5 sm:p-6 transition-all"
                style={{
                  borderColor: matchingFinding
                    ? 'rgba(239, 68, 68, 0.4)'
                    : 'rgba(255, 255, 255, 0.08)',
                  background: matchingFinding ? 'rgba(239, 68, 68, 0.03)' : '#141414',
                }}
              >
                <div className="flex items-start justify-between flex-wrap gap-4 mb-3">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span
                      className={`badge ${
                        rule.riskLevel === 'CRITICAL'
                          ? 'badge-critical'
                          : rule.riskLevel === 'HIGH'
                          ? 'badge-high'
                          : 'badge-medium'
                      }`}
                    >
                      {rule.code} : {rule.riskLevel}
                    </span>
                    <span className="text-[0.75rem] text-[#EDEDED] font-semibold bg-white/5 border border-white/10 px-2.5 py-0.5 rounded font-mono">
                      {rule.category}
                    </span>
                    <span className="text-[0.75rem] text-amber-400 font-mono font-bold bg-amber-500/10 border border-amber-500/30 px-2.5 py-0.5 rounded flex items-center gap-1.5">
                      <ShieldCheck size={12} />
                      <span>{rule.legalFramework}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-2.5">
                    {matchingFinding ? (
                      <button
                        className="btn btn-primary btn-sm flex items-center gap-1.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs"
                        onClick={() => onInspectFinding(matchingFinding)}
                      >
                        <AlertTriangle size={14} />
                        <span>Fix Violation</span>
                      </button>
                    ) : (
                      <span className="badge badge-passed flex items-center gap-1">
                        <span className="text-emerald-400">·</span>
                        <span>Compliant</span>
                      </span>
                    )}

                    <button
                      className="btn btn-secondary btn-sm flex items-center gap-1.5 text-xs font-mono font-bold"
                      onClick={() => copyPrompt(rule)}
                    >
                      {copiedId === rule.id ? (
                        <CheckCircle2 size={14} className="text-emerald-400" />
                      ) : (
                        <Copy size={14} />
                      )}
                      <span>{copiedId === rule.id ? 'Copied Prompt!' : 'Copy Fix Prompt'}</span>
                    </button>
                  </div>
                </div>

                <h3 className="text-base sm:text-lg font-extrabold text-[#F8FAFC] m-0 mb-1.5">
                  {rule.title}
                </h3>
                <p className="text-xs sm:text-sm text-[#CBD5E1] m-0 mb-3 leading-relaxed">
                  {rule.description}
                </p>

                {/* Statutory Penalty Banner */}
                <div className="bg-rose-500/10 border border-rose-500/20 px-3.5 py-2 rounded-lg text-xs text-rose-400 font-mono mb-3 flex items-center gap-2">
                  <AlertOctagon size={14} className="shrink-0" />
                  <span>
                    <strong className="text-rose-300">Statutory Penalty Exposure:</strong>{' '}
                    {rule.penaltyExposure}
                  </span>
                </div>

                {/* Verification Control */}
                <div className="bg-black/30 p-3 sm:p-4 rounded-lg border border-white/5 text-xs text-[#A1A1AA] leading-relaxed">
                  <strong className="text-[#F8FAFC]">Verification Control:</strong>{' '}
                  {rule.verificationControl}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
