import React from 'react';
import { RuleSearchClient, CatalogRule } from './RuleSearchClient';
import rulesData from '@/data/rule-inventory.generated.json';
import { ruleMaturity } from '@/lib/scanner/rule-maturity';
import { List } from 'lucide-react';

export const metadata = {
  title: 'Rule Catalog | Zelsis Docs',
  description: 'Audited inventory of security, Next.js, infrastructure, and accessibility SAST rules.',
};

export default function RulesPage() {
  const rawRules = (rulesData as { rules?: Array<Record<string, unknown>> }).rules || [];
  
  const rules: CatalogRule[] = rawRules.map((r) => ({
    ruleId: Number(r.ruleId),
    code: String(r.code),
    title: String(r.title),
    severity: String(r.severity),
    preciseLocation: Boolean(r.preciseLocation),
    tested: Boolean(r.tested),
    maturity: ruleMaturity(Number(r.ruleId)),
  }));

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs uppercase tracking-wider mb-2">
          <List size={14} />
          <span>Rule Inventory</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Static Analysis Rule Catalog</h1>
        <p className="text-zinc-400 mt-2 text-base">
          Explore the complete inventory of {rules.length} static analysis rules with severity classifications,
          line-targeting precision, and empirical benchmark maturity levels.
        </p>
      </div>

      <div className="border-t border-white/10 pt-6">
        <RuleSearchClient rules={rules} />
      </div>
    </div>
  );
}
