'use client';

import React, { useState, useMemo } from 'react';
import { Search, ShieldAlert, CheckCircle2, AlertTriangle, Info } from 'lucide-react';

interface Rule {
  ruleId: number;
  code: string;
  title: string;
  severity: string;
  preciseLocation?: boolean;
  tested?: boolean;
}

interface RuleSearchClientProps {
  rules: Rule[];
}

export function RuleSearchClient({ rules }: RuleSearchClientProps) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredRules = useMemo(() => {
    if (!searchTerm) return rules;
    const lower = searchTerm.toLowerCase();
    return rules.filter(
      r => r.code.toLowerCase().includes(lower) || r.title.toLowerCase().includes(lower)
    );
  }, [rules, searchTerm]);

  const getSeverityIcon = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL': return <ShieldAlert size={14} className="text-red-500" />;
      case 'HIGH': return <ShieldAlert size={14} className="text-orange-500" />;
      case 'MEDIUM': return <AlertTriangle size={14} className="text-amber-500" />;
      case 'LOW': return <Info size={14} className="text-blue-500" />;
      default: return <Info size={14} className="text-zinc-500" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" size={18} />
        <input
          type="text"
          placeholder="Search by rule code or title..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="w-full bg-[#141414] border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
        />
      </div>

      <div className="bg-zinc-900 border border-white/10 rounded-lg overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-black/50 border-b border-white/10 sticky top-0 z-10">
              <tr>
                <th className="px-4 py-3 font-mono text-zinc-300">Code</th>
                <th className="px-4 py-3 font-mono text-zinc-300">Title</th>
                <th className="px-4 py-3 font-mono text-zinc-300 w-24">Severity</th>
                <th className="px-4 py-3 font-mono text-zinc-300 w-32 text-center">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredRules.map(rule => (
                <tr key={rule.ruleId} className="hover:bg-white/5 transition-colors">
                  <td className="px-4 py-3 font-mono text-emerald-400 whitespace-nowrap">{rule.code}</td>
                  <td className="px-4 py-3 text-zinc-300">{rule.title}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {getSeverityIcon(rule.severity)}
                      <span className="text-xs uppercase font-medium">{rule.severity}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-col items-center gap-1 text-[10px]">
                      {rule.preciseLocation && (
                        <span className="flex items-center gap-1 text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                          <CheckCircle2 size={10} /> Precise
                        </span>
                      )}
                      {rule.tested && (
                        <span className="flex items-center gap-1 text-blue-500 bg-blue-500/10 px-2 py-0.5 rounded-full">
                          <CheckCircle2 size={10} /> Tested
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filteredRules.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-zinc-500">
                    No rules found matching "{searchTerm}"
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
