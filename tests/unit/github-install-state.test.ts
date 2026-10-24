import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.GITHUB_APP_WEBHOOK_SECRET = 'test-state-secret';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { signInstallState, verifyInstallState } = require('../../lib/github/installations') as typeof import('../../lib/github/installations');

test('install state round-trips the user id and rejects tampering and expiry', () => {
  const now = 1_800_000_000_000;
  const state = signInstallState('user-123', now);
  assert.equal(verifyInstallState(state, now + 1000), 'user-123');

  const decoded = Buffer.from(state, 'base64url').toString('utf8');
  const forged = Buffer.from(decoded.replace('user-123', 'user-999')).toString('base64url');
  assert.equal(verifyInstallState(forged, now + 1000), null, 'another user id with the old signature');

  assert.equal(verifyInstallState(state, now + 2 * 60 * 60 * 1000), null, 'older than an hour');
  assert.equal(verifyInstallState('not-a-state', now), null);
});
