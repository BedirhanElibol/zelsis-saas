import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getInternalBaseUrl, getInternalSecret, isValidInternalSecret } from '../../lib/internal-auth';

const env = process.env as Record<string, string | undefined>;
const KEYS = ['NODE_ENV', 'INTERNAL_API_SECRET', 'NEXT_PUBLIC_APP_URL', 'VERCEL_URL'] as const;
const saved = Object.fromEntries(KEYS.map((k) => [k, env[k]]));

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete env[k]; else env[k] = saved[k];
  }
});

describe('internal-auth', () => {
  it('has no worker secret in production without INTERNAL_API_SECRET', () => {
    env.NODE_ENV = 'production';
    delete env.INTERNAL_API_SECRET;
    assert.equal(getInternalSecret(), null);
    assert.equal(isValidInternalSecret('anything'), false);
  });

  it('uses a dev-only secret outside production', () => {
    env.NODE_ENV = 'development';
    delete env.INTERNAL_API_SECRET;
    assert.ok(getInternalSecret());
  });

  it('accepts only the exact secret', () => {
    env.INTERNAL_API_SECRET = 'abc123';
    assert.equal(isValidInternalSecret('abc123'), true);
    assert.equal(isValidInternalSecret('abc12'), false);
    assert.equal(isValidInternalSecret(null), false);
  });

  it('resolves the worker origin from configuration only', () => {
    env.NODE_ENV = 'production';
    env.NEXT_PUBLIC_APP_URL = 'zelsis.com/path';
    assert.equal(getInternalBaseUrl(), 'https://zelsis.com');
    delete env.NEXT_PUBLIC_APP_URL;
    env.VERCEL_URL = 'zelsis-abc.vercel.app';
    assert.equal(getInternalBaseUrl(), 'https://zelsis-abc.vercel.app');
    delete env.VERCEL_URL;
    assert.equal(getInternalBaseUrl(), null);
  });
});
