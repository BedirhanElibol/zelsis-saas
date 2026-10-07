import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { isValidUnsubscribeToken, pickFirstScanNudges, unsubscribeToken, type LifecycleUser } from '../../lib/lifecycle-emails';
import { sendFirstScanNudgeEmail } from '../../lib/email';
import { isAuthorizedCron } from '../../lib/cron-auth';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-10-07T15:00:00Z');
const user = (over: Partial<LifecycleUser>): LifecycleUser => ({
  id: 'u1', email: 'a@b.com', created_at: new Date(NOW - 2 * DAY).toISOString(), email_confirmed_at: '2026-10-05T15:00:00Z', app_metadata: {}, ...over,
});

test('nudges confirmed 1-3 day old accounts that never scanned, once, unless they opted out', () => {
  const picked = pickFirstScanNudges([
    user({ id: 'ok' }),
    user({ id: 'scanned' }),
    user({ id: 'too-new', created_at: new Date(NOW - 2 * 60 * 60 * 1000).toISOString() }),
    user({ id: 'too-old', created_at: new Date(NOW - 10 * DAY).toISOString() }),
    user({ id: 'unconfirmed', email_confirmed_at: null }),
    user({ id: 'already', app_metadata: { first_scan_nudge_at: '2026-10-06T15:00:00Z' } }),
    user({ id: 'opted-out', app_metadata: { email_opt_out: true } }),
    user({ id: 'no-email', email: null }),
  ], new Set(['scanned']), NOW);
  assert.deepEqual(picked.map((u) => u.id), ['ok']);
});

test('unsubscribe tokens are bound to one account', () => {
  const t = unsubscribeToken('user-a');
  assert.ok(t);
  assert.equal(isValidUnsubscribeToken('user-a', t), true);
  assert.equal(isValidUnsubscribeToken('user-b', t), false);
  assert.equal(isValidUnsubscribeToken('user-a', 'forged'), false);
  assert.equal(isValidUnsubscribeToken('user-a', null), false);
});

test('the nudge email carries a one-click List-Unsubscribe header and an escaped link', async () => {
  const origKey = process.env.RESEND_API_KEY;
  process.env.RESEND_API_KEY = 're_test';
  let body: { headers?: Record<string, string>; html?: string; subject?: string } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: unknown, init?: RequestInit) => {
    body = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ id: 'x' }), { status: 200 });
  });
  try {
    const res = await sendFirstScanNudgeEmail({ toEmail: 'a@b.com', unsubscribeUrl: 'https://app.test/api/v1/email/unsubscribe?u=1&t=a"b' });
    assert.equal(res.success, true);
    assert.equal(body.subject, 'Run your first Zelsis scan');
    assert.equal(body.headers?.['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click');
    assert.match(body.headers?.['List-Unsubscribe'] ?? '', /^<https:\/\/app\.test\/api\/v1\/email\/unsubscribe/);
    assert.ok(!(body.html ?? '').includes('t=a"b'));
  } finally {
    fetchMock.mock.restore();
    if (origKey === undefined) delete process.env.RESEND_API_KEY;
    else process.env.RESEND_API_KEY = origKey;
  }
});

test('cron routes accept only the configured bearer secret', () => {
  const orig = process.env.CRON_SECRET;
  try {
    delete process.env.CRON_SECRET;
    assert.equal(isAuthorizedCron('Bearer undefined'), false);
    process.env.CRON_SECRET = 's3cret';
    assert.equal(isAuthorizedCron('Bearer s3cret'), true);
    assert.equal(isAuthorizedCron('Bearer wrong!'), false);
    assert.equal(isAuthorizedCron(null), false);
  } finally {
    if (orig === undefined) delete process.env.CRON_SECRET;
    else process.env.CRON_SECRET = orig;
  }
});
