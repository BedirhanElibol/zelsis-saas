import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { SupabaseClient } from '@supabase/supabase-js';
import { getEffectivePlanTier } from '../../lib/organization';
import { hasFixPromptAccess } from '../../lib/subscription-utils';

interface Data {
  subs?: Record<string, { plan_tier: string; current_period_end: string | null }>;
  members?: Record<string, { org_id: string; role: string; owner: string }>;
  emails?: Record<string, string>;
}

/** Minimal stand-in for the service-role client: only the calls getEffectivePlanTier makes. */
function fakeAdmin(data: Data) {
  const lookups: string[] = [];
  const admin = {
    auth: { admin: { getUserById: async (id: string) => { lookups.push(id); return { data: { user: data.emails?.[id] ? { email: data.emails[id] } : null } }; } } },
    from: (table: string) => ({
      select: () => ({
        eq: (_col: string, id: string) => ({
          maybeSingle: async () => {
            if (table === 'subscriptions') return { data: data.subs?.[id] ?? null };
            const m = data.members?.[id];
            return { data: m ? { org_id: m.org_id, role: m.role, organizations: { owner_id: m.owner } } : null };
          },
        }),
      }),
    }),
  };
  return { admin: admin as unknown as SupabaseClient, lookups };
}

const future = new Date(Date.now() + 30 * 864e5).toISOString();
const past = new Date(Date.now() - 864e5).toISOString();

test('a paying Pro customer gets Pro and fixes through an API key', async () => {
  const { admin } = fakeAdmin({ subs: { u1: { plan_tier: 'Pro', current_period_end: future } }, emails: { u1: 'dev@acme.io' } });
  const tier = await getEffectivePlanTier(admin, 'u1');
  assert.equal(tier, 'Pro');
  assert.equal(hasFixPromptAccess(tier), true);
});

test('a Team owner gets Enterprise and a workspace member gets Pro', async () => {
  const data: Data = {
    subs: { owner: { plan_tier: 'Enterprise', current_period_end: future } },
    members: { m1: { org_id: 'o1', role: 'member', owner: 'owner' } },
    emails: { owner: 'cto@acme.io', m1: 'dev@acme.io' },
  };
  assert.equal(await getEffectivePlanTier(fakeAdmin(data).admin, 'owner'), 'Enterprise');
  const member = await getEffectivePlanTier(fakeAdmin(data).admin, 'm1');
  assert.equal(member, 'Pro');
  assert.equal(hasFixPromptAccess(member), true);
});

test('an expired Pro period falls back to Free', async () => {
  const { admin } = fakeAdmin({ subs: { u2: { plan_tier: 'Pro', current_period_end: past } } });
  assert.equal(await getEffectivePlanTier(admin, 'u2'), 'Free');
});

test('the founder account is recognised from its e-mail without a subscription', async () => {
  const { admin, lookups } = fakeAdmin({ subs: { f: { plan_tier: 'Free', current_period_end: null } }, emails: { f: 'bedirelibol7@gmail.com' } });
  assert.equal(await getEffectivePlanTier(admin, 'f'), 'Enterprise');
  assert.deepEqual(lookups, ['f']);
});

test('a passed e-mail, or null, skips the lookup', async () => {
  const { admin, lookups } = fakeAdmin({ subs: { u3: { plan_tier: 'Free', current_period_end: null } }, emails: { u3: 'bedirelibol7@gmail.com' } });
  assert.equal(await getEffectivePlanTier(admin, 'u3', null), 'Free');
  assert.equal(await getEffectivePlanTier(admin, 'u3', 'someone@else.io'), 'Free');
  assert.deepEqual(lookups, []);
});

test('a failed lookup leaves a free user on Free', async () => {
  const { admin } = fakeAdmin({ subs: { u4: { plan_tier: 'Free', current_period_end: null } } });
  (admin.auth.admin as unknown as { getUserById: () => Promise<never> }).getUserById = async () => { throw new Error('down'); };
  assert.equal(await getEffectivePlanTier(admin, 'u4'), 'Free');
});
