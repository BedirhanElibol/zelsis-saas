'use client';

import React, { useState } from 'react';
import { Building2, Globe, Sliders, Users, CheckCircle2, Save } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';

interface EnterpriseOrgCardProps {
  user?: UserProfile | null;
}

export const EnterpriseOrgCard: React.FC<EnterpriseOrgCardProps> = ({ user }) => {
  const [orgName, setOrgName] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('zelsis_org_name') || (user?.name ? `${user.name.split(' ')[0]}'s Security Workspace` : 'Primary Workspace');
    }
    return 'Primary Workspace';
  });

  const [orgDomain, setOrgDomain] = useState(() => {
    if (typeof window !== 'undefined') {
      const emailDomain = user?.email?.includes('@') ? user.email.split('@')[1] : 'company.com';
      return localStorage.getItem('zelsis_org_domain') || `${emailDomain}, secops.${emailDomain}`;
    }
    return 'company.com';
  });

  const [orgMinScore, setOrgMinScore] = useState(85);
  const [enforceOrgGate, setEnforceOrgGate] = useState(true);
  const [orgSaved, setOrgSaved] = useState(false);

  const handleSaveOrgSettings = (e: React.FormEvent) => {
    e.preventDefault();
    if (typeof window !== 'undefined') {
      localStorage.setItem('zelsis_org_name', orgName);
      localStorage.setItem('zelsis_org_domain', orgDomain);
      localStorage.setItem('zelsis_org_min_score', String(orgMinScore));
      localStorage.setItem('zelsis_org_enforce_gate', String(enforceOrgGate));
    }
    setOrgSaved(true);
    setTimeout(() => setOrgSaved(false), 2500);
  };

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-white/20" />

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center">
            <Building2 size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base sm:text-lg font-extrabold text-white">Organization &amp; Team Workspace</h2>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider bg-white/10 border border-white/20 text-zinc-200 px-2 py-0.5 rounded-full">
                F-47 Enterprise
              </span>
            </div>
            <p className="text-xs text-[#A1A1AA] mt-0.5">
              Configure tenant boundaries, corporate SSO domains, and organization-wide release gate policies.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold border border-white/15 bg-white/5 text-zinc-300 flex items-center gap-1.5">
            <Users size={12} className="text-zinc-400" />
            <span>12 / 25 Seats Active</span>
          </span>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSaveOrgSettings} className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="flex flex-col gap-2">
          <label htmlFor="settings-org-name" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
            <Building2 size={13} className="text-zinc-400" />
            <span>Workspace / Organization Name:</span>
          </label>
          <input
            id="settings-org-name"
            name="orgName"
            aria-label="Workspace Organization Name"
            type="text"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            placeholder="Security Engineering Workspace"
            className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-[#EDEDED] font-mono focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none focus:border-white/20"
          />
        </div>

        <div className="flex flex-col gap-2">
          <label htmlFor="settings-org-domain" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
            <Globe size={13} className="text-zinc-400" />
            <span>SSO Allowed Email Domains:</span>
          </label>
          <input
            id="settings-org-domain"
            name="orgDomain"
            aria-label="SSO Allowed Email Domains"
            type="text"
            value={orgDomain}
            onChange={(e) => setOrgDomain(e.target.value)}
            placeholder="company.com, secops.company.com"
            className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-[#EDEDED] font-mono focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none focus:border-white/20"
          />
        </div>

        <div className="flex flex-col gap-2">
          <label htmlFor="settings-org-min-score" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
            <Sliders size={13} className="text-zinc-400" />
            <span>Org-Wide Minimum Gate Score:</span>
          </label>
          <div className="flex items-center gap-3">
            <input
              id="settings-org-min-score"
              name="orgMinScore"
              aria-label="Org-Wide Minimum Gate Score"
              type="range"
              min="70"
              max="100"
              step="5"
              value={orgMinScore}
              onChange={(e) => setOrgMinScore(Number(e.target.value))}
              className="flex-1 accent-white cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
            />
            <span className="text-xs font-mono font-extrabold text-white bg-white/10 px-2.5 py-1 rounded-lg border border-white/15 tabular-nums">
              {orgMinScore}/100
            </span>
          </div>
        </div>

        <div className="flex flex-col justify-end gap-2">
          <label htmlFor="settings-enforce-org-gate" className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2 cursor-pointer select-none">
            <input
              id="settings-enforce-org-gate"
              name="enforceOrgGate"
              aria-label="Enforce Organization Security Policies across all repositories"
              type="checkbox"
              checked={enforceOrgGate}
              onChange={(e) => setEnforceOrgGate(e.target.checked)}
              className="rounded border-white/20 bg-[#0A0A0A] text-white focus:ring-0 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none w-4 h-4"
            />
            <span>Enforce Organization Security Policies across all repositories</span>
          </label>
          <p className="text-[11px] text-zinc-400 font-mono">
            Blocks deployment if any sub-project fails SCA license hygiene or critical CVE gates.
          </p>
        </div>

        <div className="md:col-span-2 flex items-center justify-between pt-4 border-t border-white/10 flex-wrap gap-3">
          <span className="text-xs text-zinc-400 font-mono">
            {orgSaved ? 'Organization settings saved successfully.' : 'Applies to all connected repos & team members.'}
          </span>
          <button
            type="submit"
            disabled={orgSaved}
            className="min-h-[44px] px-5 py-2 text-xs font-bold font-mono uppercase tracking-wider rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50 cursor-pointer focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
          >
            {orgSaved ? <CheckCircle2 size={14} /> : <Save size={14} />}
            <span>{orgSaved ? 'Saved!' : 'Save Org Policy'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
