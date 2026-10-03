import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { sendEmail, sendWaitlistWelcomeEmail, sendWorkspaceInviteEmail } from '../../lib/email';

test('sendEmail skips dispatch gracefully when RESEND_API_KEY is missing', async () => {
  const origKey = process.env.RESEND_API_KEY;
  delete process.env.RESEND_API_KEY;

  try {
    const result = await sendEmail({
      to: 'user@example.com',
      subject: 'Test Subject',
      html: '<p>Test</p>',
    });

    assert.equal(result.success, false);
    assert.match(result.error ?? '', /RESEND_API_KEY is not configured/i);
  } finally {
    if (origKey !== undefined) {
      process.env.RESEND_API_KEY = origKey;
    }
  }
});

test('sendEmail dispatches POST to api.resend.com with proper headers and payload', async () => {
  const origKey = process.env.RESEND_API_KEY;
  const origFrom = process.env.RESEND_FROM_EMAIL;
  process.env.RESEND_API_KEY = 're_test_key_12345';
  process.env.RESEND_FROM_EMAIL = 'Zelsis <alerts@zelsis.dev>';

  let interceptedUrl = '';
  let interceptedHeaders: Record<string, string> = {};
  let interceptedBody: Record<string, unknown> = {};

  const fetchMock = mock.method(globalThis, 'fetch', async (url: string | URL | Request, init?: RequestInit) => {
    interceptedUrl = String(url);
    interceptedHeaders = (init?.headers ?? {}) as Record<string, string>;
    interceptedBody = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ id: 'res_test_msg_987' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });

  try {
    const res = await sendEmail({
      to: 'recipient@company.com',
      subject: 'Security Alert',
      html: '<h1>Alert</h1>',
      text: 'Alert text',
    });

    assert.equal(res.success, true);
    assert.equal(res.id, 'res_test_msg_987');
    assert.equal(interceptedUrl, 'https://api.resend.com/emails');
    assert.equal(interceptedHeaders['Authorization'], 'Bearer re_test_key_12345');
    assert.equal(interceptedHeaders['Content-Type'], 'application/json');
    assert.deepEqual(interceptedBody.to, ['recipient@company.com']);
    assert.equal(interceptedBody.from, 'Zelsis <alerts@zelsis.dev>');
    assert.equal(interceptedBody.subject, 'Security Alert');
    assert.equal(interceptedBody.html, '<h1>Alert</h1>');
  } finally {
    fetchMock.mock.restore();
    if (origKey !== undefined) process.env.RESEND_API_KEY = origKey;
    else delete process.env.RESEND_API_KEY;
    if (origFrom !== undefined) process.env.RESEND_FROM_EMAIL = origFrom;
    else delete process.env.RESEND_FROM_EMAIL;
  }
});

test('sendWaitlistWelcomeEmail formats HTML template and dispatches', async () => {
  const origKey = process.env.RESEND_API_KEY;
  process.env.RESEND_API_KEY = 're_mock_key';

  let interceptedBody: { to?: string[]; subject?: string; html?: string } = {};

  const fetchMock = mock.method(globalThis, 'fetch', async (_url: string | URL | Request, init?: RequestInit) => {
    interceptedBody = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ id: 'msg_waitlist_1' }), { status: 200 });
  });

  try {
    const res = await sendWaitlistWelcomeEmail('newuser@example.com', 'Next.js');
    assert.equal(res.success, true);
    assert.deepEqual(interceptedBody.to, ['newuser@example.com']);
    assert.match(interceptedBody.subject ?? '', /Erken Erişim/i);
    assert.match(interceptedBody.html ?? '', /ZELSIS/);
    assert.match(interceptedBody.html ?? '', /Next\.js/);
  } finally {
    fetchMock.mock.restore();
    if (origKey !== undefined) process.env.RESEND_API_KEY = origKey;
    else delete process.env.RESEND_API_KEY;
  }
});

test('sendWorkspaceInviteEmail formats invitation with role and inviteUrl', async () => {
  const origKey = process.env.RESEND_API_KEY;
  process.env.RESEND_API_KEY = 're_mock_key';

  let interceptedBody: { to?: string[]; subject?: string; html?: string } = {};

  const fetchMock = mock.method(globalThis, 'fetch', async (_url: string | URL | Request, init?: RequestInit) => {
    interceptedBody = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ id: 'msg_invite_1' }), { status: 200 });
  });

  try {
    const res = await sendWorkspaceInviteEmail({
      toEmail: 'teammate@company.com',
      orgName: 'Acme Corp',
      role: 'admin',
      inviteUrl: 'https://shipguard-saas.vercel.app/invite/token123',
    });

    assert.equal(res.success, true);
    assert.deepEqual(interceptedBody.to, ['teammate@company.com']);
    assert.match(interceptedBody.subject ?? '', /Acme Corp/);
    assert.match(interceptedBody.html ?? '', /token123/);
    assert.match(interceptedBody.html ?? '', /admin/i);
    assert.match(interceptedBody.html ?? '', /Zelsis üzerinde/);
  } finally {
    fetchMock.mock.restore();
    if (origKey !== undefined) process.env.RESEND_API_KEY = origKey;
    else delete process.env.RESEND_API_KEY;
  }
});
