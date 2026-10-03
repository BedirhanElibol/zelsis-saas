/** Result returned by the workspace server actions in app/actions/organization.ts. */
export interface OrgActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
  /** Present after createInvite: the one-time link to share. */
  inviteUrl?: string;
}

export const initialOrgActionState: OrgActionState = { status: 'idle', message: '' };

export interface WorkspaceMember {
  userId: string;
  role: 'owner' | 'admin' | 'member';
  email: string;
  name: string | null;
  joinedAt: string;
}

export interface WorkspaceSnapshot {
  /** Plan the user can use now: own subscription, or Pro through an Enterprise workspace seat. */
  effectiveTier: 'Free' | 'Pro' | 'Enterprise';
  ownTier: 'Free' | 'Pro' | 'Enterprise';
  role: 'owner' | 'admin' | 'member' | null;
  seatLimit: number;
  org: {
    id: string;
    name: string;
    /** False when the owner's Enterprise plan lapsed: members lose their Pro seat. */
    ownerPlanActive: boolean;
    /** Organization gate policy as pretty-printed .zelsisrc JSON. */
    policy: string;
    brandName: string | null;
    brandLogoUrl: string | null;
  } | null;
  members: WorkspaceMember[];
  invites: { id: string; role: 'admin' | 'member'; expiresAt: string }[];
}
