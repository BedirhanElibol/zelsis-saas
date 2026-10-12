import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inviteAcceptError, maskEmail } from '../../lib/organization';
import { OrgInviteSchema } from '../../lib/validations/api-schemas';

const TOKEN = 'a'.repeat(40);

test('invites require an email and store it lowercased', () => {
  assert.equal(OrgInviteSchema.safeParse({ accessToken: TOKEN, role: 'member' }).success, false);
  assert.equal(OrgInviteSchema.safeParse({ accessToken: TOKEN, role: 'member', email: '' }).success, false);
  const ok = OrgInviteSchema.safeParse({ accessToken: TOKEN, role: 'member', email: '  Jane.Doe@Company.COM ' });
  assert.ok(ok.success);
  assert.equal(ok.data.email, 'jane.doe@company.com');
});

test('only a confirmed user with the invited address can accept', () => {
  const invited = 'jane@company.com';
  assert.equal(inviteAcceptError({ email: 'Jane@Company.com', email_confirmed_at: '2026-10-01T00:00:00Z' }, invited), null);
  assert.match(inviteAcceptError({ email: 'mallory@evil.io', email_confirmed_at: '2026-10-01T00:00:00Z' }, invited)!, /sent to j\*\*\*@company\.com/);
  assert.match(inviteAcceptError({ email: invited, email_confirmed_at: null }, invited)!, /Confirm your email/);
  assert.notEqual(inviteAcceptError({ email: null, email_confirmed_at: '2026-10-01T00:00:00Z' }, invited), null);
});

test('maskEmail keeps the first letter and the domain only', () => {
  assert.equal(maskEmail('jane.doe@company.com'), 'j***@company.com');
  assert.equal(maskEmail('not-an-email'), '***');
});
