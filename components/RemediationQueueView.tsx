'use client';

import React, { useState } from 'react';
import { Project, Finding } from '@/data/schema';
import { UserTier } from '@/data/schema';
import { hasFixPromptAccess } from '@/lib/subscription-utils';
import { suggestionFindings, verifiedFindings } from '@/lib/finding-counts';

interface RemediationQueueViewProps {
  projects: Project[];
  onInspectFinding: (f: Finding) => void;
  onToggleResolveFinding: (id: string) => void;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const RemediationQueueView: React.FC<RemediationQueueViewProps> = ({
  projects,
  onInspectFinding,
  onToggleResolveFinding,
  userTier = 'Free',
  onOpenCheckout
}) => {
  const [copiedBatch, setCopiedBatch] = useState(false);

  const allFindings = projects.flatMap(p => p.findings.map(f => ({ ...f, projectName: p.name })));
  // The selected project's verified findings, the same list the findings table shows by default
  const openFindings = verifiedFindings(allFindings).map((f) => ({ ...f, projectName: (f as typeof allFindings[number]).projectName }));
  const suggestionCount = suggestionFindings(allFindings).length;
  const resolvedFindings = allFindings.filter(f => f.status === 'RESOLVED');

  const batchPromptText = `Act as Senior Lead Architect. Here are the ${openFindings.length} open security & release blocker tasks in this project. Refactor code to solve all items:

${openFindings.map((f, idx) => `Task ${idx + 1}: [${f.severity}] ${f.title} (${f.projectName} -> ${f.filePath})
Remediation: ${f.remediationPrompt}`).join('\n\n')}`;

  const copyBatchPrompt = () => {
    if (!hasFixPromptAccess(userTier)) {
      onOpenCheckout?.('Pro');
      return;
    }
    navigator.clipboard.writeText(batchPromptText);
    setCopiedBatch(true);
    setTimeout(() => setCopiedBatch(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#EDEDED', margin: 0 }}>
              Remediation Action Queue
            </h1>
          </div>
          <p style={{ fontSize: '0.875rem', color: '#A1A1AA', marginTop: '6px', maxWidth: '700px' }}>
            Prioritized remediation queue linking findings directly to copyable AI fix prompts and acceptance criteria.
          </p>
        </div>

        {openFindings.length > 0 && (
          userTier === 'Free' ? (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs text-zinc-400">
                <span className="font-mono">Batch Export — Pro Only</span>
              </div>
              {onOpenCheckout && (
                <button
                  className="text-xs px-3 py-2 rounded-xl bg-white text-black font-bold hover:bg-neutral-200 transition-colors"
                  onClick={() => onOpenCheckout('Pro')}
                >
                  Upgrade
                </button>
              )}
            </div>
          ) : (
            <button className="btn btn-primary" onClick={copyBatchPrompt}>
              <span>{copiedBatch ? 'Batch Prompts Copied!' : 'Export All Batch Fix Prompts'}</span>
            </button>
          )
        )}
      </div>

      {/* Open Items */}
      <div>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#EDEDED', margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>Open Findings ({openFindings.length})</span>
          {suggestionCount > 0 && (
            <span style={{ fontSize: '0.75rem', fontWeight: 500, color: '#71717A' }}>+ {suggestionCount} suggestions in the findings table</span>
          )}
        </h2>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {openFindings.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: '#10B981', background: 'rgba(16, 185, 129, 0.05)', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
              Remediation queue is empty. All findings resolved.
            </div>
          ) : (
            openFindings.map(item => (
              <div key={item.id} className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <span className={`badge ${item.severity === 'CRITICAL' ? 'badge-critical' : item.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                    {item.severity}
                  </span>
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#EDEDED' }}>
                      {item.title}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#A1A1AA', marginTop: '4px' }}>
                      <strong style={{ color: '#34D399' }}>{item.projectName}</strong> / <code style={{ color: '#A1A1AA' }}>{item.filePath} ({item.lineRange})</code>
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => onInspectFinding(item)}>
                    <span>Inspect Code</span>
                  </button>

                  <button className="btn btn-secondary btn-sm" style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: '#10B981' }} onClick={() => onToggleResolveFinding(item.id)}>
                    <span>Mark Resolved</span>
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Resolved Items */}
      {resolvedFindings.length > 0 && (
        <div style={{ marginTop: '20px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#64748B', margin: '0 0 12px 0' }}>
            Resolved Items ({resolvedFindings.length})
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {resolvedFindings.map(item => (
              <div key={item.id} style={{ padding: '14px 20px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '0.875rem', color: '#A1A1AA', textDecoration: 'line-through' }}>
                    {item.title} ({item.projectName})
                  </span>
                </div>
                <button className="btn btn-secondary btn-sm" style={{ fontSize: '0.7rem', padding: '4px 8px' }} onClick={() => onToggleResolveFinding(item.id)}>
                  Re-open
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
