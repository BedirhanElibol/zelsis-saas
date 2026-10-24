'use client';

import React, { useEffect, useState } from 'react';
import { Calculator } from 'lucide-react';
import type { Finding } from '@/data/schema';
import { estimateCost, formatUsd, type CostInputs } from '@/lib/cost-estimate';

const storageKey = (projectId?: string) => `zelsis:cost-inputs:${projectId || 'default'}`;

/**
 * "What could this cost?" for paid-call and data-leak findings, from numbers the user enters. Nothing is shown in
 * dollars until the user gives a price and a rate; the inputs stay in this browser.
 */
export function CostEstimatePanel({ findings, projectId }: { findings: Finding[]; projectId?: string }) {
  const [inputs, setInputs] = useState<Partial<CostInputs>>({});
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(storageKey(projectId));
      if (saved) setInputs(JSON.parse(saved));
    } catch { /* storage blocked: start empty */ }
  }, [projectId]);

  const update = (key: keyof CostInputs, raw: string) => {
    const value = raw === '' ? undefined : Number(raw);
    const next = { ...inputs, [key]: value };
    setInputs(next);
    try { localStorage.setItem(storageKey(projectId), JSON.stringify(next)); } catch { /* not saved */ }
  };

  const est = estimateCost(findings, inputs);
  if (est.paidCallFindings.length === 0 && est.dataLeakFindings.length === 0) return null;

  const field = (key: keyof CostInputs, label: string, hint: string, step: string) => (
    <label className="flex flex-col gap-1 text-[11px] text-zinc-400">
      <span>{label}</span>
      <input
        type="number" min="0" step={step} inputMode="decimal"
        value={inputs[key] ?? ''}
        onChange={(e) => update(key, e.target.value)}
        placeholder={hint}
        className="bg-[#0A0A0A] border border-white/10 rounded-md px-2 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
      />
    </label>
  );

  return (
    <div className="rounded-lg border border-white/10 bg-[#101012] px-3 py-2.5 text-xs">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 text-left text-zinc-200 cursor-pointer">
        <span className="flex items-center gap-2">
          <Calculator className="w-4 h-4 text-emerald-400" aria-hidden="true" />
          <strong className="text-white">What could this cost?</strong>
          {est.perDay !== null && <span className="text-red-300">Up to {formatUsd(est.perDay)} a day of abuse</span>}
          {est.perDay === null && est.usersAtRisk !== null && <span className="text-red-300">Records of up to {est.usersAtRisk.toLocaleString('en-US')} users</span>}
        </span>
        <span className="text-zinc-500">{open ? 'Hide' : 'Estimate with your numbers'}</span>
      </button>

      {open && (
        <div className="mt-3 flex flex-col gap-3">
          {est.paidCallFindings.length > 0 && (
            <div className="flex flex-col gap-2">
              <p className="text-zinc-400">
                {est.paidCallFindings.length === 1 ? '1 finding lets' : `${est.paidCallFindings.length} findings let`} someone trigger paid SMS or AI calls on your account.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {field('pricePerRequest', 'Cost of one request (USD)', 'e.g. 0.0079 per SMS', '0.0001')}
                {field('requestsPerMinute', 'Requests per minute that get through', 'e.g. 600', '1')}
              </div>
              {est.perHour !== null && est.perDay !== null ? (
                <p className="text-zinc-200">
                  {formatUsd(est.perHour)} per hour, {formatUsd(est.perDay)} per day of abuse.{' '}
                  <span className="text-zinc-500">Your numbers: ${inputs.pricePerRequest} per request x {inputs.requestsPerMinute} requests a minute. Provider limits and alerts can stop it sooner.</span>
                </p>
              ) : (
                <p className="text-zinc-500">Enter both numbers to see a figure. Zelsis does not know your prices or traffic, so it does not guess.</p>
              )}
            </div>
          )}
          {est.dataLeakFindings.length > 0 && (
            <div className="flex flex-col gap-2">
              <p className="text-zinc-400">
                {est.dataLeakFindings.length} finding{est.dataLeakFindings.length === 1 ? '' : 's'} can expose other users&apos; data.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {field('userCount', 'Users whose data the app stores', 'e.g. 12000', '1')}
              </div>
              {est.usersAtRisk !== null && (
                <p className="text-zinc-200">Records of up to {est.usersAtRisk.toLocaleString('en-US')} users are reachable. <span className="text-zinc-500">No dollar figure: the cost of a leak depends on what the records hold and where your users live.</span></p>
              )}
            </div>
          )}
          <p className="text-[10px] text-zinc-500">These numbers stay in this browser.</p>
        </div>
      )}
    </div>
  );
}
