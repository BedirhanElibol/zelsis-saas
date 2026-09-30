'use client';

import React, { useState } from 'react';
import { Finding, SecurityRule } from '@/data/schema';
import { SECURITY_RULES_CATALOG } from '@/data/mockData';
import { ShieldCheck, Search, Filter, Copy, CheckCircle2, AlertTriangle } from 'lucide-react';

interface SecurityAuditViewProps {
  findings: Finding[];
  onInspectFinding: (f: Finding) => void;
}

export const SecurityAuditView: React.FC<SecurityAuditViewProps> = ({
  findings,
  onInspectFinding
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | number | null>(null);

  const categories = ['ALL', 'Secret Isolation', 'Authentication', 'Database', 'Network & CORS', 'Input & Files', 'Error & Logging', 'Supply Chain', 'Compliance & Cost'];

  const filteredRules = SECURITY_RULES_CATALOG.filter(rule => {
    const safeSearch = (searchTerm || '').toLowerCase();
    const matchesSearch = (rule.title || '').toLowerCase().includes(safeSearch) ||
                          (rule.description || '').toLowerCase().includes(safeSearch) ||
                          (rule.code || '').toLowerCase().includes(safeSearch);
    const matchesCat = selectedCategory === 'ALL' || rule.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  const copyPrompt = (rule: SecurityRule) => {
    navigator.clipboard.writeText(rule.claudePrompt);
    setCopiedId(rule.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header Info */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldCheck size={26} color="#10B981" />
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#EDEDED', margin: 0 }}>
            Zelsis Security Pre-flight Taxonomy
          </h1>
        </div>
        <p style={{ fontSize: '0.875rem', color: '#A1A1AA', marginTop: '6px', maxWidth: '800px' }}>
          Complete pre-flight checks covering secret leaks, database RLS, server-side authorization, CORS, password hashing, and LLM cost protection.
        </p>
      </div>

      {/* Filter Bar */}
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', background: 'var(--bg-surface)', padding: '10px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.08)', flex: 1, minWidth: '280px' }}>
          <Search size={16} color="#A1A1AA" />
          <input
            id="security-rules-search-input"
            name="securityRulesSearch"
            aria-label="Search security rules or OWASP tags"
            type="text"
            placeholder="Search security rules or OWASP tags..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="focus-visible:ring-1 focus-visible:ring-white/20 rounded"
            style={{ background: 'transparent', border: 'none', outline: 'none', color: '#EDEDED', width: '100%', fontSize: '0.85rem' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={16} color="#A1A1AA" />
          <select
            id="security-category-select"
            name="securityCategory"
            aria-label="Filter security rules by category"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="focus-visible:ring-1 focus-visible:ring-white/20 outline-none"
            style={{ background: 'var(--bg-surface)', color: '#EDEDED', padding: '10px 14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.08)', fontSize: '0.85rem', cursor: 'pointer' }}
          >
            {categories.map(cat => (
              <option key={cat} value={cat} style={{ background: "#141414" }}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rules Catalog Grid */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {filteredRules.length === 0 ? (
          <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '40px', textAlign: 'center', color: '#A1A1AA', fontSize: '0.875rem' }}>
            No security rules match your current filter or search criteria.
          </div>
        ) : (
          filteredRules.map(rule => {
            const matchingFinding = findings.find(f => f.ruleId === rule.id && f.status === 'OPEN');

            return (
              <div
                key={rule.id}
                className="bg-[#141414] border border-white/10 rounded-xl"
                style={{
                  padding: '20px 24px',
                  borderColor: matchingFinding ? 'rgba(239, 68, 68, 0.4)' : 'rgba(255, 255, 255, 0.08)',
                  background: matchingFinding ? 'rgba(239, 68, 68, 0.03)' : 'var(--bg-surface)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span className={`badge ${rule.riskLevel === 'CRITICAL' ? 'badge-critical' : rule.riskLevel === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                      {rule.code} : {rule.riskLevel}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#EDEDED', fontWeight: 600, background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                      {rule.owaspTag}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {matchingFinding ? (
                      <button className="btn btn-primary btn-sm" style={{ background: '#EF4444' }} onClick={() => onInspectFinding(matchingFinding)}>
                        <AlertTriangle size={14} />
                        <span>Fix Open Violation</span>
                      </button>
                    ) : (
                      <span className="badge badge-passed">
                        <span className="text-emerald-400">·</span>
                        <span>Compliant</span>
                      </span>
                    )}

                    <button className="btn btn-secondary btn-sm" onClick={() => copyPrompt(rule)}>
                      {copiedId === rule.id ? <CheckCircle2 size={14} color="#10B981" /> : <Copy size={14} />}
                      <span>{copiedId === rule.id ? 'Copied Prompt!' : 'Copy Fix Prompt'}</span>
                    </button>
                  </div>
                </div>

                <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#F8FAFC', margin: '0 0 6px 0' }}>
                  {rule.title}
                </h3>
                <p style={{ fontSize: '0.875rem', color: '#CBD5E1', margin: '0 0 14px 0' }}>
                  {rule.description}
                </p>

                <div style={{ background: 'rgba(0, 0, 0, 0.25)', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)', fontSize: '0.8rem', color: '#A1A1AA' }}>
                  <strong style={{ color: '#F8FAFC' }}>Verification Control:</strong> {rule.verificationControl}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
