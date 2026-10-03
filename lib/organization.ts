import type { SupabaseClient } from '@supabase/supabase-js';
import { isPlatformAdminEmail, resolveServerPlanTier } from '@/lib/subscription-utils';

export type PlanTier = 'Free' | 'Pro' | 'Enterprise';
export type OrgRole = 'owner' | 'admin' | 'member';

export { ENTERPRISE_SEAT_LIMIT } from '@/data/pricing-plans';
export const INVITE_TTL_DAYS = 7;

export interface OrgMembership {
  orgId: string;
  role: OrgRole;
  ownerId: string;
}

/** The caller's workspace membership, read with a service-role client. */
export async function getOrgMembership(admin: SupabaseClient, userId: string): Promise<OrgMembership | null> {
  const { data } = await admin
    .from('organization_members')
    .select('org_id, role, organizations!inner(owner_id)')
    .eq('user_id', userId)
    .maybeSingle();
  if (!data) return null;
  const org = (Array.isArray(data.organizations) ? data.organizations[0] : data.organizations) as { owner_id: string } | null;
  if (!org) return null;
  return { orgId: data.org_id as string, role: data.role as OrgRole, ownerId: org.owner_id };
}

/** Own subscription tier, period end applied. */
export async function getOwnPlanTier(admin: SupabaseClient, userId: string): Promise<PlanTier> {
  const { data: sub } = await admin
    .from('subscriptions')
    .select('plan_tier, current_period_end')
    .eq('user_id', userId)
    .maybeSingle();
  return resolveServerPlanTier({ storedTier: sub?.plan_tier, currentPeriodEnd: sub?.current_period_end });
}

/**
 * Plan a user can use right now: their own subscription, or Pro when they belong to a
 * workspace whose owner holds an active Enterprise plan.
 */
export async function getEffectivePlanTier(
  admin: SupabaseClient,
  userId: string,
  email?: string | null
): Promise<PlanTier> {
  if (isPlatformAdminEmail(email)) return 'Enterprise';
  const own = await getOwnPlanTier(admin, userId);
  if (own !== 'Free') return own;
  const membership = await getOrgMembership(admin, userId);
  if (!membership || membership.ownerId === userId) return own;
  const ownerTier = await getOwnPlanTier(admin, membership.ownerId);
  return ownerTier === 'Enterprise' ? 'Pro' : own;
}

/** Organization gate policy (.zelsisrc.json shape) for the user's workspace, if any. */
export async function getOrgPolicy(admin: SupabaseClient, userId: string): Promise<string | null> {
  const membership = await getOrgMembership(admin, userId);
  if (!membership) return null;
  const { data } = await admin.from('organizations').select('policy').eq('id', membership.orgId).maybeSingle();
  const policy = data?.policy as Record<string, unknown> | undefined;
  return policy && Object.keys(policy).length > 0 ? JSON.stringify(policy) : null;
}

export const canManageOrg = (role: OrgRole | null | undefined): boolean => role === 'owner' || role === 'admin';
