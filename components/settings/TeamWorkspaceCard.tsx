'use client';

import React, { useActionState, useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Building2,
  Check,
  Copy,
  Link2,
  Loader2,
  LogOut,
  Palette,
  ShieldCheck,
  Sliders,
  Trash2,
  UserMinus,
  Users,
} from 'lucide-react';
import type { UserProfile } from '@/components/auth/AuthModal';
import {
  createInvite,
  createOrganization,
  deleteOrganization,
  getMyWorkspace,
  leaveOrganization,
  removeMember,
  revokeInvite,
  updateMemberRole,
  updateOrgBranding,
  updateOrgPolicy,
} from '@/app/actions/organization';
import { initialOrgActionState, type OrgActionState, type WorkspaceSnapshot } from '@/lib/org-action-state';
import { getActiveUserAuth } from '@/lib/supabase-client';
import { fetchTeamProjects, type TeamProjectSummary } from '@/lib/supabase';
import { priceLabel } from '@/data/pricing-plans';

type OrgAction = (prev: OrgActionState, formData: FormData) => Promise<OrgActionState>;

interface TeamWorkspaceCardProps {
  user?: UserProfile | null;
  onOpenCheckout?: (tier: 'Pro' | 'Enterprise') => void;
}

/** A form bound to one workspace server action; reports its result and refreshes the card. */
function ActionForm({
  action,
  accessToken,
  onDone,
  children,
  className,
  confirmText,
}: {
  action: OrgAction;
  accessToken: string;
  onDone: (state: OrgActionState) => void;
  children: (pending: boolean) => React.ReactNode;
  className?: string;
  confirmText?: string;
}) {
  const [state, formAction, pending] = useActionState(action, initialOrgActionState);
  useEffect(() => {
    if (state.status !== 'idle') onDone(state);
  }, [state, onDone]);
  return (
    <form
      action={formAction}
      className={className}
      onSubmit={(e) => {
        if (confirmText && !window.confirm(confirmText)) e.preventDefault();
      }}
    >
      <input type="hidden" name="accessToken" value={accessToken} />
      {children(pending)}
    </form>
  );
}

const roleBadge: Record<string, string> = {
  owner: 'bg-white text-black',
  admin: 'bg-white/15 text-white border border-white/20',
  member: 'bg-white/5 text-zinc-300 border border-white/10',
};

export const TeamWorkspaceCard: React.FC<TeamWorkspaceCardProps> = ({ user, onOpenCheckout }) => {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [teamProjects, setTeamProjects] = useState<TeamProjectSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<OrgActionState | null>(null);
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    const { accessToken: token } = await getActiveUserAuth();
    setAccessToken(token);
    if (!token) {
      setSnapshot(null);
      setLoading(false);
      return;
    }
    const [snap, projects] = await Promise.all([getMyWorkspace(token), fetchTeamProjects()]);
    setSnapshot(snap);
    setTeamProjects(snap.org ? projects : []);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh, user?.email]);

  const handleDone = useCallback(
    (state: OrgActionState) => {
      setFeedback(state);
      if (state.inviteUrl) {
        setInviteUrl(state.inviteUrl);
        setCopied(false);
      }
      if (state.status === 'success') void refresh();
    },
    [refresh]
  );

  const copyInvite = async () => {
    if (!inviteUrl) return;
    await navigator.clipboard.writeText(inviteUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const org = snapshot?.org ?? null;
  const role = snapshot?.role ?? null;
  const canManage = role === 'owner' || role === 'admin';
  const seatsUsed = (snapshot?.members.length ?? 0) + (snapshot?.invites.length ?? 0);

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-white/20" />

      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center">
            <Building2 size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base sm:text-lg font-extrabold text-white">{org ? org.name : 'Team Workspace'}</h2>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider bg-white/10 border border-white/20 text-zinc-200 px-2 py-0.5 rounded-full">
                Enterprise
              </span>
            </div>
            <p className="text-xs text-[#A1A1AA] mt-0.5">
              Invite teammates, share project status and enforce one gate policy across every repository.
            </p>
          </div>
        </div>
        {org && snapshot && (
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold border border-white/15 bg-white/5 text-zinc-300 flex items-center gap-1.5">
            <Users size={12} className="text-zinc-400" />
            <span>
              {seatsUsed} / {snapshot.seatLimit} seats
            </span>
          </span>
        )}
      </div>

      {feedback && feedback.status !== 'idle' && (
        <div
          role="status"
          className={`text-xs font-mono p-3 rounded-xl border ${
            feedback.status === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
          <Loader2 size={14} className="animate-spin" /> Loading workspace...
        </div>
      ) : !accessToken || !snapshot ? (
        <p className="text-xs text-zinc-400">Sign in to manage your team workspace.</p>
      ) : !org ? (
        snapshot.ownTier === 'Enterprise' ? (
          <ActionForm action={createOrganization} accessToken={accessToken} onDone={handleDone} className="flex flex-col sm:flex-row gap-3">
            {(pending) => (
              <>
                <input
                  name="name"
                  required
                  minLength={2}
                  maxLength={80}
                  aria-label="Workspace name"
                  placeholder="Acme Engineering"
                  className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white focus:border-white/30 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                />
                <button type="submit" disabled={pending} className="btn btn-primary min-h-[44px] px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-2">
                  {pending ? <Loader2 size={14} className="animate-spin" /> : <Building2 size={14} />}
                  Create workspace
                </button>
              </>
            )}
          </ActionForm>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-[#0A0A0A] border border-white/10">
            <p className="text-xs text-zinc-400">
              Team workspaces come with Enterprise ({priceLabel('Enterprise')}): up to {snapshot.seatLimit} seats, and every member gets Pro.
              Got an invite link? Open it while signed in to join.
            </p>
            {onOpenCheckout && (
              <button type="button" onClick={() => onOpenCheckout('Enterprise')} className="btn btn-secondary min-h-[44px] px-4 rounded-xl text-xs font-bold shrink-0">
                View Enterprise
              </button>
            )}
          </div>
        )
      ) : (
        <>
          {!org.ownerPlanActive && (
            <div className="flex items-start gap-2 text-xs p-3 rounded-xl border bg-amber-500/10 border-amber-500/30 text-amber-300">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>The owner&apos;s Enterprise plan is not active, so members are on their own plans until it renews.</span>
            </div>
          )}

          {/* Members */}
          <section className="flex flex-col gap-2">
            <h3 className="text-xs font-mono font-bold text-[#EDEDED] uppercase tracking-wider">Members</h3>
            <ul className="flex flex-col divide-y divide-white/5 rounded-xl border border-white/10 bg-[#0A0A0A]">
              {snapshot.members.map((m) => (
                <li key={m.userId} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="text-xs text-white truncate">{m.name || m.email}</div>
                    {m.name && <div className="text-[11px] text-zinc-500 truncate">{m.email}</div>}
                  </div>
                  <div className="flex items-center gap-2">
                    {role === 'owner' && m.role !== 'owner' ? (
                      <ActionForm action={updateMemberRole} accessToken={accessToken} onDone={handleDone}>
                        {(pending) => (
                          <>
                            <input type="hidden" name="userId" value={m.userId} />
                            <select
                              name="role"
                              defaultValue={m.role}
                              disabled={pending}
                              aria-label={`Role for ${m.email}`}
                              onChange={(e) => e.currentTarget.form?.requestSubmit()}
                              className="bg-[#141414] border border-white/10 rounded-lg px-2 py-1 text-[11px] text-white font-mono"
                            >
                              <option value="member">member</option>
                              <option value="admin">admin</option>
                            </select>
                          </>
                        )}
                      </ActionForm>
                    ) : (
                      <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${roleBadge[m.role]}`}>{m.role}</span>
                    )}
                    {canManage && m.role !== 'owner' && m.email !== user?.email && (role === 'owner' || m.role === 'member') && (
                      <ActionForm action={removeMember} accessToken={accessToken} onDone={handleDone} confirmText={`Remove ${m.email} from the workspace?`}>
                        {(pending) => (
                          <>
                            <input type="hidden" name="userId" value={m.userId} />
                            <button type="submit" disabled={pending} aria-label={`Remove ${m.email}`} className="p-1.5 rounded-lg text-zinc-400 hover:text-red-300 hover:bg-white/5">
                              <UserMinus size={14} />
                            </button>
                          </>
                        )}
                      </ActionForm>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </section>

          {/* Invites */}
          {canManage && (
            <section className="flex flex-col gap-3">
              <h3 className="text-xs font-mono font-bold text-[#EDEDED] uppercase tracking-wider">Invite links</h3>
              <ActionForm action={createInvite} accessToken={accessToken} onDone={handleDone} className="flex flex-col sm:flex-row gap-2">
                {(pending) => (
                  <>
                    <select
                      name="role"
                      defaultValue="member"
                      aria-label="Invite role"
                      className="bg-[#0A0A0A] border border-white/10 rounded-xl px-3 py-2.5 text-xs text-white font-mono"
                    >
                      <option value="member">Member</option>
                      {role === 'owner' && <option value="admin">Admin</option>}
                    </select>
                    <button
                      type="submit"
                      disabled={pending || seatsUsed >= snapshot.seatLimit}
                      className="btn btn-primary min-h-[44px] px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-2"
                    >
                      {pending ? <Loader2 size={14} className="animate-spin" /> : <Link2 size={14} />}
                      Create invite link
                    </button>
                  </>
                )}
              </ActionForm>
              {inviteUrl && (
                <div className="flex items-center gap-2">
                  <input
                    readOnly
                    value={inviteUrl}
                    aria-label="Invite link"
                    className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-300"
                  />
                  <button type="button" onClick={copyInvite} className="btn btn-secondary p-2 rounded-lg" aria-label="Copy invite link">
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
              )}
              {snapshot.invites.length > 0 && (
                <ul className="flex flex-col gap-1">
                  {snapshot.invites.map((inv) => (
                    <li key={inv.id} className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                      <span>
                        Pending {inv.role} invite · expires {new Date(inv.expiresAt).toLocaleDateString()}
                      </span>
                      <ActionForm action={revokeInvite} accessToken={accessToken} onDone={handleDone}>
                        {(pending) => (
                          <>
                            <input type="hidden" name="inviteId" value={inv.id} />
                            <button type="submit" disabled={pending} className="text-zinc-400 hover:text-red-300 underline">
                              Revoke
                            </button>
                          </>
                        )}
                      </ActionForm>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}

          {/* Organization policy */}
          <section className="flex flex-col gap-2">
            <h3 className="text-xs font-mono font-bold text-[#EDEDED] uppercase tracking-wider flex items-center gap-2">
              <Sliders size={13} className="text-zinc-400" /> Organization gate policy
            </h3>
            <p className="text-[11px] text-zinc-400">
              Same format as <code>.zelsisrc.json</code>. Strategy and minimum score override each repository&apos;s file; ignored rules,
              paths and disabled gates are added to it. Applies to dashboard scans and the CI gate for every member.
            </p>
            {canManage ? (
              <ActionForm action={updateOrgPolicy} accessToken={accessToken} onDone={handleDone} className="flex flex-col gap-2">
                {(pending) => (
                  <>
                    <textarea
                      name="policy"
                      defaultValue={org.policy}
                      rows={8}
                      spellCheck={false}
                      aria-label="Organization policy JSON"
                      placeholder={'{\n  "failStrategy": "strict",\n  "minScoreThreshold": 85,\n  "ignoreRules": ["UI-201"]\n}'}
                      className="bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white font-mono focus:border-white/30 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"
                    />
                    <button type="submit" disabled={pending} className="btn btn-secondary self-start min-h-[40px] px-4 rounded-xl text-xs font-bold flex items-center gap-2">
                      {pending ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                      Save policy
                    </button>
                  </>
                )}
              </ActionForm>
            ) : (
              <pre className="bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-zinc-300 font-mono overflow-x-auto">{org.policy}</pre>
            )}
          </section>

          {/* White-label report branding */}
          {canManage && (
            <section className="flex flex-col gap-2">
              <h3 className="text-xs font-mono font-bold text-[#EDEDED] uppercase tracking-wider flex items-center gap-2">
                <Palette size={13} className="text-zinc-400" /> Report branding
              </h3>
              <p className="text-[11px] text-zinc-400">Shown on PDF audit reports and the SOC 2 control mapping export for every member.</p>
              <ActionForm action={updateOrgBranding} accessToken={accessToken} onDone={handleDone} className="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-2">
                {(pending) => (
                  <>
                    <input
                      name="brandName"
                      defaultValue={org.brandName ?? ''}
                      maxLength={80}
                      aria-label="Company name on reports"
                      placeholder="Company name"
                      className="bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white"
                    />
                    <input
                      name="brandLogoUrl"
                      defaultValue={org.brandLogoUrl ?? ''}
                      maxLength={500}
                      type="url"
                      aria-label="Logo URL (https)"
                      placeholder="https://example.com/logo.png"
                      className="bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white"
                    />
                    <button type="submit" disabled={pending} className="btn btn-secondary min-h-[40px] px-4 rounded-xl text-xs font-bold">
                      {pending ? <Loader2 size={14} className="animate-spin" /> : 'Save'}
                    </button>
                  </>
                )}
              </ActionForm>
            </section>
          )}

          {/* Team projects */}
          <section className="flex flex-col gap-2">
            <h3 className="text-xs font-mono font-bold text-[#EDEDED] uppercase tracking-wider">Teammates&apos; projects</h3>
            {teamProjects.length === 0 ? (
              <p className="text-[11px] text-zinc-500">No saved projects from teammates yet.</p>
            ) : (
              <ul className="flex flex-col divide-y divide-white/5 rounded-xl border border-white/10 bg-[#0A0A0A]">
                {teamProjects.map((p) => (
                  <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-xs">
                    <div className="min-w-0">
                      <div className="text-white truncate">{p.name}</div>
                      <div className="text-[11px] text-zinc-500 truncate">{p.ownerEmail}</div>
                    </div>
                    <div className="flex items-center gap-3 font-mono text-[11px]">
                      <span className="text-zinc-300">{p.readinessScore}/100</span>
                      <span
                        className={
                          p.gateStatus === 'FAILED' ? 'text-red-300' : p.gateStatus === 'WARNING' ? 'text-amber-300' : 'text-emerald-300'
                        }
                      >
                        {p.gateStatus}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {/* Leave / delete */}
          <div className="pt-4 border-t border-white/10 flex justify-end">
            {role === 'owner' ? (
              <ActionForm
                action={deleteOrganization}
                accessToken={accessToken}
                onDone={handleDone}
                confirmText="Delete this workspace? Members lose their Pro seat. Their own accounts and projects stay."
              >
                {(pending) => (
                  <button type="submit" disabled={pending} className="text-xs text-zinc-400 hover:text-red-300 flex items-center gap-1.5">
                    <Trash2 size={13} /> Delete workspace
                  </button>
                )}
              </ActionForm>
            ) : (
              <ActionForm action={leaveOrganization} accessToken={accessToken} onDone={handleDone} confirmText="Leave this workspace?">
                {(pending) => (
                  <button type="submit" disabled={pending} className="text-xs text-zinc-400 hover:text-red-300 flex items-center gap-1.5">
                    <LogOut size={13} /> Leave workspace
                  </button>
                )}
              </ActionForm>
            )}
          </div>
        </>
      )}

    </div>
  );
};
