'use client';

import React, { useState, useMemo } from 'react';
import { Search, ShieldAlert, CheckCircle2, AlertTriangle, Info, SlidersHorizontal } from 'lucide-react';

export interface CatalogRule {
  ruleId: number;
  code: string;
  title: string;
  severity: string;
  preciseLocation?: boolean;
  tested?: boolean;
  maturity: 'verified' | 'unproven' | 'experimental';
}

interface RuleSearchClientProps {
  rules: CatalogRule[];
}

export function RuleSearchClient({ rules }: RuleSearchClientProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [maturityFilter, setMaturityFilter] = useState<string>('ALL');

  const filteredRules = useMemo(() => {
    const term = searchTerm.toLowerCase().trim();
    return rules.filter((r) => {
      // Severity filter
      if (severityFilter !== 'ALL' && r.severity.toUpperCase() !== severityFilter) {
        return false;
      }
      // Maturity filter
      if (maturityFilter !== 'ALL' && r.maturity !== maturityFilter) {
        return false;
      }
      // Search term filter
      if (!term) return true;
      return (
        r.code.toLowerCase().includes(term) ||
        r.title.toLowerCase().includes(term) ||
        r.maturity.toLowerCase().includes(term) ||
        r.severity.toLowerCase().includes(term) ||
        String(r.ruleId).includes(term)
      );
    });
  }, [rules, searchTerm, severityFilter, maturityFilter]);

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
            <ShieldAlert size={12} /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
            <ShieldAlert size={12} /> HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle size={12} /> MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Info size={12} /> LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">
            {sev}
          </span>
        );
    }
  };

  const getMaturityBadge = (maturity: 'verified' | 'unproven' | 'experimental') => {
    switch (maturity) {
      case 'verified':
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 whitespace-nowrap"
            title="Tested and benchmarked: eligible to gate releases"
          >
            <CheckCircle2 size={10} /> Verified Gate
          </span>
        );
      case 'experimental':
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 whitespace-nowrap"
            title="Experimental: reported as advisory finding, does not fail release gate"
          >
            <AlertTriangle size={10} /> Experimental
          </span>
        );
      case 'unproven':
      default:
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/5 text-zinc-400 border border-white/10 whitespace-nowrap"
            title="Standard rule: standard coverage"
          >
            <Info size={10} /> Standard
          </span>
        );
    }
  };

  return (
    <div className="space-y-5">
      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" size={16} />
          <input
            type="text"
            placeholder="Search by code (e.g. SEC-03, RULE-1), title, or keywords..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#0A0A0A] border border-white/10 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono transition-colors"
          />
        </div>

        {/* Severity dropdown / toggle */}
        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#0A0A0A] border border-white/10 rounded-lg px-2.5 py-2 text-xs text-zinc-300 font-mono focus:outline-none focus:border-emerald-500"
            aria-label="Filter by Severity"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={maturityFilter}
            onChange={(e) => setMaturityFilter(e.target.value)}
            className="bg-[#0A0A0A] border border-white/10 rounded-lg px-2.5 py-2 text-xs text-zinc-300 font-mono focus:outline-none focus:border-emerald-500"
            aria-label="Filter by Maturity"
          >
            <option value="ALL">All Maturity</option>
            <option value="verified">Verified Gate</option>
            <option value="experimental">Experimental</option>
            <option value="unproven">Standard</option>
          </select>
        </div>
      </div>

      {/* Rules count info */}
      <div className="flex items-center justify-between text-xs text-zinc-400 font-mono">
        <span>Showing {filteredRules.length} of {rules.length} rules</span>
        {(searchTerm || severityFilter !== 'ALL' || maturityFilter !== 'ALL') && (
          <button
            onClick={() => {
              setSearchTerm('');
              setSeverityFilter('ALL');
              setMaturityFilter('ALL');
            }}
            className="text-emerald-400 hover:underline cursor-pointer"
          >
            Reset filters
          </button>
        )}
      </div>

      {/* Rules Table */}
      <div className="bg-[#0A0A0A] border border-white/10 rounded-lg overflow-hidden shadow-inner">
        <div className="max-h-[640px] overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/60 border-b border-white/10 sticky top-0 z-10 font-mono text-zinc-300">
              <tr>
                <th className="px-4 py-3 w-32">Rule Code</th>
                <th className="px-4 py-3">Description / Title</th>
                <th className="px-4 py-3 w-28">Severity</th>
                <th className="px-4 py-3 w-36 text-center">Benchmark Maturity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredRules.map((rule) => (
                <tr key={rule.ruleId} className="hover:bg-white/5 transition-colors">
                  <td className="px-4 py-3 font-mono text-emerald-400 font-semibold whitespace-nowrap align-top">
                    {rule.code}
                  </td>
                  <td className="px-4 py-3 text-zinc-200 align-top">
                    <div className="font-medium">{rule.title}</div>
                    <div className="flex items-center gap-2 mt-1">
                      {rule.preciseLocation && (
                        <span className="text-[10px] text-zinc-400 font-mono bg-white/5 px-1.5 py-0.2 rounded">
                          line-precise
                        </span>
                      )}
                      {rule.tested && (
                        <span className="text-[10px] text-zinc-400 font-mono bg-white/5 px-1.5 py-0.2 rounded">
                          fixture-tested
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap align-top">
                    {getSeverityBadge(rule.severity)}
                  </td>
                  <td className="px-4 py-3 text-center whitespace-nowrap align-top">
                    {getMaturityBadge(rule.maturity)}
                  </td>
                </tr>
              ))}
              {filteredRules.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-12 text-center text-zinc-500 font-mono">
                    No rules found matching &quot;{searchTerm}&quot;
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
