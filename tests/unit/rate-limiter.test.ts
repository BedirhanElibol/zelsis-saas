import { afterEach, describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { checkRateLimit } from '../../lib/rate-limiter';

const env = process.env as Record<string, string | undefined>;
const reqFrom = (ip: string) => new NextRequest('http://localhost/api/test', { headers: { 'x-real-ip': ip } });
const withRedis = () => {
  env.UPSTASH_REDIS_REST_URL = 'https://redis.example';
  env.UPSTASH_REDIS_REST_TOKEN = 'token';
};

afterEach(() => {
  mock.restoreAll();
  delete env.UPSTASH_REDIS_REST_URL;
  delete env.UPSTASH_REDIS_REST_TOKEN;
});

describe('checkRateLimit (in-memory)', () => {
  it('allows up to the limit, then blocks', async () => {
    const opts = { maxRequests: 2, windowSeconds: 60, prefix: `mem-${Date.now()}` };
    assert.equal((await checkRateLimit(reqFrom('10.0.0.1'), opts)).allowed, true);
    assert.equal((await checkRateLimit(reqFrom('10.0.0.1'), opts)).allowed, true);
    assert.equal((await checkRateLimit(reqFrom('10.0.0.1'), opts)).allowed, false);
    assert.equal((await checkRateLimit(reqFrom('10.0.0.2'), opts)).allowed, true, 'limits are per IP');
  });
});

describe('checkRateLimit (Upstash)', () => {
  it('sends INCR + EXPIRE NX in one pipeline and reports TTL', async () => {
    withRedis();
    const fetchMock = mock.method(globalThis, 'fetch', async () =>
      new Response(JSON.stringify([{ result: 3 }, { result: 0 }, { result: 42 }]), { status: 200 })
    );

    const res = await checkRateLimit(reqFrom('10.0.1.1'), { maxRequests: 2, prefix: 'up' });

    assert.equal(fetchMock.mock.callCount(), 1);
    const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
    assert.equal(url, 'https://redis.example/pipeline');
    const commands = JSON.parse(String(init.body)) as string[][];
    assert.deepEqual(commands[0], ['INCR', 'rl:up:10.0.1.1']);
    assert.deepEqual(commands[1], ['EXPIRE', 'rl:up:10.0.1.1', '60', 'NX']);
    assert.equal(res.allowed, false);
    assert.equal(res.resetSeconds, 42);
  });

  it('fails closed when Redis is unreachable and failClosed is set', async () => {
    withRedis();
    mock.method(globalThis, 'fetch', async () => { throw new Error('network down'); });
    const res = await checkRateLimit(reqFrom('10.0.2.1'), { prefix: `fc-${Date.now()}`, failClosed: true });
    assert.equal(res.allowed, false);
  });

  it('falls back to in-memory when Redis is unreachable by default', async () => {
    withRedis();
    mock.method(globalThis, 'fetch', async () => { throw new Error('network down'); });
    const res = await checkRateLimit(reqFrom('10.0.3.1'), { prefix: `fo-${Date.now()}` });
    assert.equal(res.allowed, true);
  });
});
