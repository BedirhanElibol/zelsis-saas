'use client';

import React, { useState } from 'react';
import { UiRule } from '@/data/schema';
import { UI_RULES_CATALOG, VIBEPOLISH_30_CATALOG, AI_CLICHE_25_CATALOG } from '@/data/mockData';
import { Palette, Copy, CheckCircle2, Search, Filter } from 'lucide-react';

/** Named catalogs, resolved here so callers do not import (and bundle) the catalog data themselves. */
const CATALOGS = {
  polish: () => VIBEPOLISH_30_CATALOG,
  cliche: () => AI_CLICHE_25_CATALOG,
  all: () => UI_RULES_CATALOG,
} as const;

interface VibePolishViewProps {
  rules?: UiRule[];
  catalog?: keyof typeof CATALOGS;
  title?: string;
  description?: string;
}

export const VibePolishView: React.FC<VibePolishViewProps> = ({
  catalog = 'all',
  rules = CATALOGS[catalog](),
  title = "VibePolish 200 AI Master Anti-Patterns & Slop Matrix",
  description = "Automated audit matrix covering AI product failure modes: UI/UX slop, hallucinated imports, prompt bloat, agent reasoning deadlocks, RAG triad failures, and unhandled streaming cancellations."
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCat, setSelectedCat] = useState('ALL');
  const [copiedNegativePrompt, setCopiedNegativePrompt] = useState(false);

  const categories = ['ALL', ...Array.from(new Set(rules.map(r => r.category)))];

  const filteredRules = rules.filter(rule => {
    const safeSearch = (searchTerm || '').toLowerCase();
    const matchesSearch = (rule.title || '').toLowerCase().includes(safeSearch) ||
                          (rule.clichePattern || '').toLowerCase().includes(safeSearch) ||
                          (rule.code || '').toLowerCase().includes(safeSearch);
    const matchesCat = selectedCat === 'ALL' || rule.category === selectedCat;
    return matchesSearch && matchesCat;
  });

  const negativePromptText = `[MANDATORY NEGATIVE UI PROMPT FOR AI GENERATION]
ABSOLUTELY DO NOT USE THE FOLLOWING CLICHÉS: Forced Apple-style bento box grids, generic inline 3-card feature grids, ambient neon glow/gradient clutter, Lucide sparkle icons on every button, 'Not X, but Y' slogan formulas, fake user testimonials, green checkmark icons on every row, over-rounded 999px pill buttons, decorative fake terminal mockups, Inter/Geist font defaults without brand identity, and jittery bouncing hover arrows. Use crisp typography, organic functional layouts, subtle 1px borders, and desaturated, purposeful color palettes.`;

  const copyNegativePrompt = () => {
    navigator.clipboard.writeText(negativePromptText);
    setCopiedNegativePrompt(true);
    setTimeout(() => setCopiedNegativePrompt(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '24px 32px', background: "#141414", borderColor: 'rgba(16, 185, 129, 0.25)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Palette size={24} color="#10B981" />
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#EDEDED', margin: 0 }}>
              {title}
            </h1>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#A1A1AA', marginTop: '6px', maxWidth: '750px' }}>
            {description}
          </p>
        </div>

        <button className="btn btn-primary px-5 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm" onClick={copyNegativePrompt}>
          {copiedNegativePrompt ? <CheckCircle2 size={16} /> : <Copy size={16} />}
          <span>{copiedNegativePrompt ? 'Negative Prompt Copied!' : 'Copy Negative UI Prompt'}</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', background: 'var(--bg-surface)', padding: '10px 16px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.08)', flex: 1, minWidth: '280px' }}>
          <Search size={16} color="#A1A1AA" />
          <input
            id="vibepolish-search-input"
            name="vibePolishSearch"
            aria-label="Search 200 AI anti-patterns, clichés or rules"
            type="text"
            placeholder="Search 200 AI anti-patterns, clichés or rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="focus-visible:ring-1 focus-visible:ring-white/20 rounded"
            style={{ background: 'transparent', border: 'none', outline: 'none', color: '#F8FAFC', width: '100%', fontSize: '0.85rem' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={16} color="#A1A1AA" />
          <select
            id="vibepolish-category-select"
            name="vibePolishCategory"
            aria-label="Filter AI anti-patterns by category"
            value={selectedCat}
            onChange={(e) => setSelectedCat(e.target.value)}
            className="focus-visible:ring-1 focus-visible:ring-white/20 outline-none"
            style={{ background: 'var(--bg-surface)', color: '#F8FAFC', padding: '10px 14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.08)', fontSize: '0.85rem', cursor: 'pointer' }}
          >
            {categories.map(cat => (
              <option key={cat} value={cat} style={{ background: "#141414" }}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rules Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '20px' }}>
        {filteredRules.length === 0 ? (
          <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '40px', gridColumn: '1 / -1', textAlign: 'center', color: '#A1A1AA', fontSize: '0.875rem' }}>
            No VibePolish UI rules match your current search or category filter.
          </div>
        ) : (
          filteredRules.map(rule => (
            <div key={rule.id} className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <span className="badge badge-high" style={{ fontSize: '0.7rem' }}>
                    {rule.code}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#A1A1AA', fontWeight: 600 }}>
                    {rule.category}
                  </span>
                </div>

                <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#F8FAFC', margin: '0 0 10px 0' }}>
                  {rule.title}
                </h3>

                <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '10px 12px', borderRadius: '8px', marginBottom: '10px' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 800, color: '#EF4444', textTransform: 'uppercase', marginBottom: '2px', letterSpacing: '0.05em' }}>
                    AI Anti-Pattern:
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#FCA5A5' }}>
                    "{rule.clichePattern}"
                  </div>
                </div>

                <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '10px 12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 800, color: '#10B981', textTransform: 'uppercase', marginBottom: '2px', letterSpacing: '0.05em' }}>
                    Zelsis Resolution:
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#6EE7B7' }}>
                    {rule.zelsisSolution || (rule as any).shipguardSolution}
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
