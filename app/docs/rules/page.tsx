import React from 'react';
import { RuleSearchClient } from './RuleSearchClient';
import rulesData from '@/data/rule-inventory.generated.json';

export const metadata = { title: 'Rule Catalog - Zelsis Docs' };

export default function RulesPage() {
  const rules = (rulesData as any).rules || [];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Rule Catalog</h1>
      <p className="text-zinc-400">
        Browse the complete inventory of static analysis rules, security checks, and UI quality validations performed by Zelsis.
      </p>
      
      <div className="mt-8">
        <RuleSearchClient rules={rules} />
      </div>
    </div>
  );
}
