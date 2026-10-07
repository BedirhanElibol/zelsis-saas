import { expect, test } from '@playwright/test';

test.describe('public pages', () => {
  test('landing page renders without runtime errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    const res = await page.goto('/');
    expect(res?.status()).toBe(200);
    await expect(page.locator('h1').first()).toBeVisible();
    expect(errors).toEqual([]);
  });

  for (const path of ['/privacy', '/terms', '/refund', '/cookies']) {
    test(`${path} is reachable`, async ({ page }) => {
      const res = await page.goto(path);
      expect(res?.status()).toBe(200);
    });
  }

  test('unknown routes return 404', async ({ page }) => {
    const res = await page.goto('/this-page-does-not-exist');
    expect(res?.status()).toBe(404);
  });
});

test.describe('auth gate', () => {
  test('dashboard asks anonymous visitors to sign in', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create Free Account' })).toBeVisible();
  });
});

test.describe('API guards', () => {
  test('scan queue rejects anonymous requests', async ({ request }) => {
    const res = await request.post('/api/v1/scans/queue', {
      data: { repoUrl: 'https://github.com/vercel/next.js' }
    });
    expect(res.status()).toBe(401);
  });

  test('scan worker rejects calls without the internal secret', async ({ request }) => {
    const res = await request.post('/api/v1/scans/process-job', {
      data: { jobId: 'x', repoUrl: 'https://github.com/vercel/next.js' },
      headers: { 'x-zelsis-internal-secret': 'wrong-secret' }
    });
    expect(res.status()).toBe(401);
  });
});

test.describe('cron and email endpoints', () => {
  for (const path of ['/api/cron/rescan', '/api/cron/lifecycle']) {
    test(`${path} rejects calls without the cron secret`, async ({ request }) => {
      const res = await request.get(path, { headers: { authorization: 'Bearer undefined' } });
      expect(res.status()).toBe(401);
    });
  }

  test('unsubscribe rejects a forged token without changing anything', async ({ request }) => {
    const res = await request.get('/api/v1/email/unsubscribe?u=00000000-0000-0000-0000-000000000000&t=forged');
    expect(res.status()).toBe(400);
  });
});

test.describe('badge', () => {
  test('an unknown project never renders as passing', async ({ request }) => {
    const res = await request.get('/api/v1/badge?projectId=proj-does-not-exist');
    expect(res.status()).toBe(200);
    const svg = await res.text();
    expect(svg).toContain('NOT SCANNED');
    expect(svg).not.toContain('PASSED');
  });
});

test.describe('public scan', () => {
  test('landing preview scan returns a gate result for a public repo', async ({ request }) => {
    test.setTimeout(90_000);
    const res = await request.post('/api/v1/scans/preview', {
      data: { repoUrl: 'https://github.com/vercel/nextjs-subscription-payments' },
      timeout: 80_000
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(['PASSED', 'WARNING', 'FAILED']).toContain(body.gateStatus);
    expect(body.filesScanned).toBeGreaterThan(0);
  });

  test('gate-check returns line annotations for the PR diff', async ({ request }) => {
    test.setTimeout(90_000);
    const res = await request.post('/api/v1/gate-check', {
      data: { repoUrl: 'https://github.com/gothinkster/node-express-realworld-example-app' },
      timeout: 80_000
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(Array.isArray(body.annotations)).toBeTruthy();
    for (const line of body.annotations) expect(line).toMatch(/^::(error|warning) file=[^\n]+,line=\d+/);
  });
});
