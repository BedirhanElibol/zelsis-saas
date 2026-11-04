'use client';

import React, { useEffect, useState } from 'react';
import { RuleSearchClient, type CatalogRule } from '@/app/docs/rules/RuleSearchClient';

/**
 * The rules the scanner actually runs, the same inventory as /docs/rules. The inventory is a large JSON file,
 * so it loads when this view opens instead of shipping with the dashboard.
 */
export function RuleCatalogView() {
  const [rules, setRules] = useState<CatalogRule[] | null>(null);

  useEffect(() => {
    let alive = true;
    Promise.all([import('@/data/rule-inventory.generated.json'), import('@/lib/scanner/rule-maturity')]).then(([inventory, { ruleMaturity }]) => {
      const raw = (inventory.default as { rules?: Array<Record<string, unknown>> }).rules || [];
      if (!alive) return;
      setRules(raw.map((r) => ({
        ruleId: Number(r.ruleId),
        code: String(r.code),
        title: String(r.title),
        severity: String(r.severity),
        preciseLocation: Boolean(r.preciseLocation),
        tested: Boolean(r.tested),
        maturity: ruleMaturity(Number(r.ruleId)),
      })));
    });
    return () => { alive = false; };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Rule Catalog</h1>
        <p className="text-zinc-400 mt-2 text-sm">
          Every rule Zelsis runs on your code, with its severity and confidence. Verified rules decide the release gate;
          the others only make suggestions.
        </p>
      </div>
      {rules ? <RuleSearchClient rules={rules} /> : <p className="text-zinc-500 text-sm">Loading rules…</p>}
    </div>
  );
}
