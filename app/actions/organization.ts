'use server';

import crypto from 'crypto';
import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import type { z } from 'zod';
import {
  OrgAcceptInviteSchema,
  OrgBrandingSchema,
  OrgInviteRevokeSchema,
  OrgInviteSchema,
  OrgMemberActionSchema,
  OrgNameSchema,
  OrgPolicySchema,
  OrgPolicyUpdateSchema,
} from '@/lib/validations/api-schemas';
import {
  ENTERPRISE_SEAT_LIMIT,
  INVITE_TTL_DAYS,
  canManageOrg,
  getEffectivePlanTier,
  getOrgMembership,
  getOwnPlanTier,
  type OrgMembership,
  type OrgRole,
} from '@/lib/organization';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { logger } from '@/lib/logger';
import { sendWorkspaceInviteEmail } from '@/lib/email';
import type { OrgActionState, WorkspaceSnapshot } from '@/lib/org-action-state';

const fail = (message: string): OrgActionState => ({ status: 'error', message });
const ok = (message: string, extra: Partial<OrgActionState> = {}): OrgActionState => ({ status: 'success', message, ...extra });

interface ActionContext {
  admin: SupabaseClient;
  user: User;
}

/** Verifies the caller's Supabase session token and returns a service-role client. */
async function authenticate(accessToken: string): Promise<ActionContext | null> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceRoleKey) return null;
  const authClient = createClient(url, anonKey, { auth: { persistSession: false } });
  const { data, error } = await authClient.auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return { admin: createClient(url, serviceRoleKey, { auth: { persistSession: false } }), user: data.user };
}

function parseForm<S extends z.ZodTypeAny>(schema: S, formData: FormData): z.infer<S> | null {
  const raw: Record<string, unknown> = {};
  formData.forEach((value, key) => {
    if (typeof value === 'string') raw[key] = value;
  });
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

const hashToken = (token: string): string => crypto.createHash('sha256').update(token).digest('hex');

async function audit(admin: SupabaseClient, userId: string, action: string, orgId: string, metadata: Record<string, unknown> = {}) {
  try {
    await admin.from('audit_logs').insert({ user_id: userId, action, entity_type: 'organization', entity_id: orgId, metadata });
  } catch (err) {
    logger.debug('[Org] Audit log write failed:', err);
  }
}

/** Seats in use: members plus unexpired, unused invites. */
async function seatsInUse(admin: SupabaseClient, orgId: string): Promise<number> {
  const [{ count: members }, { count: invites }] = await Promise.all([
    admin.from('organization_members').select('user_id', { count: 'exact', head: true }).eq('org_id', orgId),
    admin
      .from('organization_invites')
      .select('id', { count: 'exact', head: true })
      .eq('org_id', orgId)
      .is('used_at', null)
      .gt('expires_at', new Date().toISOString()),
  ]);
  return (members ?? 0) + (invites ?? 0);
}

async function requireManager(ctx: ActionContext): Promise<OrgMembership | OrgActionState> {
  const membership = await getOrgMembership(ctx.admin, ctx.user.id);
  if (!membership) return fail('You are not in a team workspace.');
  if (!canManageOrg(membership.role)) return fail('Only workspace owners and admins can do this.');
  return membership;
}

const isState = (value: unknown): value is OrgActionState =>
  typeof value === 'object' && value !== null && 'status' in value && 'message' in value;

// ------------------------------------------------------------------------------------------

export async function createOrganization(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgNameSchema, formData);
  if (!input) return fail('Enter a workspace name between 2 and 80 characters.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');

  if ((await getOwnPlanTier(ctx.admin, ctx.user.id)) !== 'Enterprise') {
    return fail('Team workspaces are part of Zelsis Enterprise.');
  }
  if (await getOrgMembership(ctx.admin, ctx.user.id)) return fail('You already belong to a workspace.');

  const { data: org, error } = await ctx.admin
    .from('organizations')
    .insert({ name: input.name, owner_id: ctx.user.id })
    .select('id')
    .single();
  if (error || !org) {
    logger.error('[Org] Create failed:', error?.message);
    return fail('Could not create the workspace. Please try again.');
  }
  const { error: memberErr } = await ctx.admin
    .from('organization_members')
    .insert({ org_id: org.id, user_id: ctx.user.id, role: 'owner' });
  if (memberErr) {
    await ctx.admin.from('organizations').delete().eq('id', org.id);
    return fail('Could not create the workspace. Please try again.');
  }
  await audit(ctx.admin, ctx.user.id, 'org.created', org.id, { name: input.name });
  return ok(`Workspace "${input.name}" created.`);
}

export async function createInvite(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgInviteSchema, formData);
  if (!input) return fail('Invalid invite request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await requireManager(ctx);
  if (isState(membership)) return membership;

  if ((await getOwnPlanTier(ctx.admin, membership.ownerId)) !== 'Enterprise') {
    return fail("The workspace owner's Enterprise plan is not active.");
  }
  if (input.role === 'admin' && membership.role !== 'owner') return fail('Only the owner can invite admins.');
  if ((await seatsInUse(ctx.admin, membership.orgId)) >= ENTERPRISE_SEAT_LIMIT) {
    return fail(`All ${ENTERPRISE_SEAT_LIMIT} seats are in use. Remove a member or revoke an invite first.`);
  }

  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { error } = await ctx.admin.from('organization_invites').insert({
    org_id: membership.orgId,
    token_hash: hashToken(token),
    role: input.role,
    created_by: ctx.user.id,
    expires_at: expiresAt,
  });
  if (error) {
    logger.error('[Org] Invite insert failed:', error.message);
    return fail('Could not create the invite. Please try again.');
  }
  const inviteUrl = `${getConfiguredAppUrl()}/invite/${token}`;
  let emailDispatched = false;

  if (input.email) {
    const { data: orgData } = await ctx.admin
      .from('organizations')
      .select('name')
      .eq('id', membership.orgId)
      .maybeSingle();

    const orgName = orgData?.name || 'Workspace';
    const emailResult = await sendWorkspaceInviteEmail({
      toEmail: input.email,
      orgName,
      role: input.role,
      inviteUrl,
    });
    emailDispatched = emailResult.success;
  }

  await audit(ctx.admin, ctx.user.id, 'org.invite_created', membership.orgId, {
    role: input.role,
    email: input.email || null,
    emailDispatched,
  });

  const successMessage = emailDispatched
    ? `Invite link created and email sent to ${input.email}. It expires in ${INVITE_TTL_DAYS} days.`
    : `Invite link created. It works once and expires in ${INVITE_TTL_DAYS} days.`;

  return ok(successMessage, {
    inviteUrl,
  });
}

export async function revokeInvite(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgInviteRevokeSchema, formData);
  if (!input) return fail('Invalid request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await requireManager(ctx);
  if (isState(membership)) return membership;

  const { error } = await ctx.admin
    .from('organization_invites')
    .delete()
    .eq('id', input.inviteId)
    .eq('org_id', membership.orgId)
    .is('used_at', null);
  if (error) return fail('Could not revoke the invite.');
  await audit(ctx.admin, ctx.user.id, 'org.invite_revoked', membership.orgId, { inviteId: input.inviteId });
  return ok('Invite revoked.');
}

export async function acceptInvite(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgAcceptInviteSchema, formData);
  if (!input) return fail('This invite link is not valid.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in to accept the invite.');

  const { data: invite } = await ctx.admin
    .from('organization_invites')
    .select('id, org_id, role, expires_at, used_at')
    .eq('token_hash', hashToken(input.token))
    .maybeSingle();
  if (!invite || invite.used_at) return fail('This invite link was already used or revoked.');
  if (new Date(invite.expires_at).getTime() < Date.now()) return fail('This invite link has expired. Ask for a new one.');
  if (await getOrgMembership(ctx.admin, ctx.user.id)) return fail('You already belong to a workspace. Leave it first.');

  const { count: members } = await ctx.admin
    .from('organization_members')
    .select('user_id', { count: 'exact', head: true })
    .eq('org_id', invite.org_id);
  if ((members ?? 0) >= ENTERPRISE_SEAT_LIMIT) return fail('This workspace has no free seats.');

  // Claim the invite first so two people cannot redeem the same link.
  const { data: claimed } = await ctx.admin
    .from('organization_invites')
    .update({ used_at: new Date().toISOString(), used_by: ctx.user.id })
    .eq('id', invite.id)
    .is('used_at', null)
    .select('id')
    .maybeSingle();
  if (!claimed) return fail('This invite link was already used.');

  const { error } = await ctx.admin
    .from('organization_members')
    .insert({ org_id: invite.org_id, user_id: ctx.user.id, role: invite.role });
  if (error) {
    await ctx.admin.from('organization_invites').update({ used_at: null, used_by: null }).eq('id', invite.id);
    return fail('Could not join the workspace. Please try again.');
  }
  await audit(ctx.admin, ctx.user.id, 'org.member_joined', invite.org_id, { role: invite.role });
  return ok('You joined the workspace.');
}

export async function updateMemberRole(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgMemberActionSchema, formData);
  if (!input?.role) return fail('Invalid request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await getOrgMembership(ctx.admin, ctx.user.id);
  if (membership?.role !== 'owner') return fail('Only the owner can change roles.');
  if (input.userId === membership.ownerId) return fail("The owner's role cannot change.");

  const { data, error } = await ctx.admin
    .from('organization_members')
    .update({ role: input.role })
    .eq('org_id', membership.orgId)
    .eq('user_id', input.userId)
    .select('user_id')
    .maybeSingle();
  if (error || !data) return fail('Member not found.');
  await audit(ctx.admin, ctx.user.id, 'org.role_changed', membership.orgId, { userId: input.userId, role: input.role });
  return ok('Role updated.');
}

export async function removeMember(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgMemberActionSchema, formData);
  if (!input) return fail('Invalid request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await requireManager(ctx);
  if (isState(membership)) return membership;
  if (input.userId === membership.ownerId) return fail('The owner cannot be removed.');
  if (input.userId === ctx.user.id) return fail('Use "Leave workspace" to remove yourself.');

  const { data: target } = await ctx.admin
    .from('organization_members')
    .select('role')
    .eq('org_id', membership.orgId)
    .eq('user_id', input.userId)
    .maybeSingle();
  if (!target) return fail('Member not found.');
  if (target.role === 'admin' && membership.role !== 'owner') return fail('Only the owner can remove admins.');

  await ctx.admin.from('organization_members').delete().eq('org_id', membership.orgId).eq('user_id', input.userId);
  await audit(ctx.admin, ctx.user.id, 'org.member_removed', membership.orgId, { userId: input.userId });
  return ok('Member removed.');
}

export async function leaveOrganization(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgNameSchema.pick({ accessToken: true }), formData);
  if (!input) return fail('Invalid request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await getOrgMembership(ctx.admin, ctx.user.id);
  if (!membership) return fail('You are not in a workspace.');
  if (membership.role === 'owner') return fail('The owner cannot leave. Delete the workspace instead.');

  await ctx.admin.from('organization_members').delete().eq('org_id', membership.orgId).eq('user_id', ctx.user.id);
  await audit(ctx.admin, ctx.user.id, 'org.member_left', membership.orgId);
  return ok('You left the workspace.');
}

export async function deleteOrganization(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgNameSchema.pick({ accessToken: true }), formData);
  if (!input) return fail('Invalid request.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await getOrgMembership(ctx.admin, ctx.user.id);
  if (membership?.role !== 'owner') return fail('Only the owner can delete the workspace.');

  await audit(ctx.admin, ctx.user.id, 'org.deleted', membership.orgId);
  const { error } = await ctx.admin.from('organizations').delete().eq('id', membership.orgId);
  if (error) return fail('Could not delete the workspace.');
  return ok('Workspace deleted. Members keep their own accounts and projects.');
}

export async function updateOrgPolicy(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgPolicyUpdateSchema, formData);
  if (!input) return fail('Invalid policy.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await requireManager(ctx);
  if (isState(membership)) return membership;

  let json: unknown;
  try {
    json = input.policy.trim() ? JSON.parse(input.policy) : {};
  } catch {
    return fail('Policy must be valid JSON.');
  }
  const policy = OrgPolicySchema.safeParse(json);
  if (!policy.success) {
    const issue = policy.error.issues[0];
    return fail(`Policy error at "${issue?.path.join('.') || 'root'}": ${issue?.message ?? 'invalid value'}`);
  }

  const { error } = await ctx.admin.from('organizations').update({ policy: policy.data }).eq('id', membership.orgId);
  if (error) return fail('Could not save the policy.');
  await audit(ctx.admin, ctx.user.id, 'org.policy_updated', membership.orgId);
  return ok('Organization policy saved. It applies to every member’s next scan.');
}

export async function updateOrgBranding(_prev: OrgActionState, formData: FormData): Promise<OrgActionState> {
  const input = parseForm(OrgBrandingSchema, formData);
  if (!input) return fail('Logo URL must start with https:// and names are limited to 80 characters.');
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');
  const membership = await requireManager(ctx);
  if (isState(membership)) return membership;

  const { error } = await ctx.admin
    .from('organizations')
    .update({ brand_name: input.brandName, brand_logo_url: input.brandLogoUrl })
    .eq('id', membership.orgId);
  if (error) return fail('Could not save branding.');
  await audit(ctx.admin, ctx.user.id, 'org.branding_updated', membership.orgId);
  return ok('Report branding saved.');
}

/** Everything the Team Workspace card needs, in one round trip. */
export async function getMyWorkspace(accessToken: string): Promise<WorkspaceSnapshot> {
  const empty: WorkspaceSnapshot = { effectiveTier: 'Free', ownTier: 'Free', org: null, role: null, members: [], invites: [], seatLimit: ENTERPRISE_SEAT_LIMIT };
  if (typeof accessToken !== 'string' || accessToken.length < 20) return empty;
  const ctx = await authenticate(accessToken);
  if (!ctx) return empty;

  const [ownTier, effectiveTier, membership] = await Promise.all([
    getOwnPlanTier(ctx.admin, ctx.user.id),
    getEffectivePlanTier(ctx.admin, ctx.user.id, ctx.user.email),
    getOrgMembership(ctx.admin, ctx.user.id),
  ]);
  if (!membership) return { ...empty, ownTier, effectiveTier };

  const [{ data: org }, { data: memberRows }, { data: inviteRows }] = await Promise.all([
    ctx.admin.from('organizations').select('id, name, owner_id, policy, brand_name, brand_logo_url').eq('id', membership.orgId).single(),
    ctx.admin
      .from('organization_members')
      .select('user_id, role, joined_at, profiles!inner(email, full_name)')
      .eq('org_id', membership.orgId)
      .order('joined_at', { ascending: true }),
    canManageOrg(membership.role)
      ? ctx.admin
          .from('organization_invites')
          .select('id, role, expires_at, created_at')
          .eq('org_id', membership.orgId)
          .is('used_at', null)
          .gt('expires_at', new Date().toISOString())
          .order('created_at', { ascending: false })
      : Promise.resolve({ data: [] as { id: string; role: string; expires_at: string; created_at: string }[] }),
  ]);
  if (!org) return { ...empty, ownTier, effectiveTier };

  const ownerTier = membership.ownerId === ctx.user.id ? ownTier : await getOwnPlanTier(ctx.admin, membership.ownerId);

  return {
    effectiveTier,
    ownTier,
    role: membership.role,
    seatLimit: ENTERPRISE_SEAT_LIMIT,
    org: {
      id: org.id,
      name: org.name,
      ownerPlanActive: ownerTier === 'Enterprise',
      policy: JSON.stringify(org.policy ?? {}, null, 2),
      brandName: org.brand_name,
      brandLogoUrl: org.brand_logo_url,
    },
    members: (memberRows ?? []).map((row) => {
      const profile = (Array.isArray(row.profiles) ? row.profiles[0] : row.profiles) as { email: string; full_name: string | null } | null;
      return {
        userId: row.user_id as string,
        role: row.role as OrgRole,
        email: profile?.email ?? '',
        name: profile?.full_name ?? null,
        joinedAt: row.joined_at as string,
      };
    }),
    invites: (inviteRows ?? []).map((row) => ({ id: row.id, role: row.role as 'admin' | 'member', expiresAt: row.expires_at })),
  };
}
