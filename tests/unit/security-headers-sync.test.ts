import { test } from 'node:test';
import assert from 'node:assert/strict';
import nextConfig from '../../next.config.mjs';
import { CANONICAL_SECURITY_HEADERS, buildCspString } from '../../lib/security-headers';

// Pages get their security headers from next.config.mjs (the proxy only runs for /api),
// so the config must carry the same values as the canonical list.
test('next.config page headers match the canonical security headers, CSP included', async () => {
  const rules = await nextConfig.headers!();
  const all = rules.find((r) => r.source === '/:path*');
  assert.ok(all, 'a /:path* header rule exists');
  const got = Object.fromEntries(all.headers.map((h) => [h.key, h.value]));
  assert.equal(got['Content-Security-Policy'], buildCspString());
  for (const [key, value] of Object.entries(CANONICAL_SECURITY_HEADERS)) {
    if (key === 'Content-Security-Policy') continue;
    assert.equal(got[key], value, key);
  }
});
