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
