import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetChallengedError, createRequestLimiter } from '../../lib/scanner/request-limiter';
import { botChallengeMessage } from '../../lib/bot-challenge';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('never more than `concurrency` requests in flight, starts spaced by minIntervalMs', async () => {
  let inFlight = 0; let peak = 0; const starts: number[] = [];
  const fetchImpl = (async () => {
    starts.push(Date.now()); inFlight++; peak = Math.max(peak, inFlight);
    await sleep(30); inFlight--;
    return new Response('ok');
  }) as unknown as typeof fetch;
  const limiter = createRequestLimiter({ concurrency: 3, minIntervalMs: 20, fetchImpl });
  await Promise.all(Array.from({ length: 12 }, (_, i) => limiter.fetch(`https://site.example/${i}`)));
  assert.equal(starts.length, 12);
  assert.ok(peak <= 3, `peak ${peak}`);
  for (let i = 1; i < starts.length; i++) assert.ok(starts[i] - starts[i - 1] >= 18, `gap ${starts[i] - starts[i - 1]}ms`);
});

test('stops sending once the target answers with a challenge', async () => {
  let calls = 0;
  const fetchImpl = (async () => {
    calls++;
    return calls === 2
      ? new Response('<title>Vercel Security Checkpoint</title>', { status: 403, headers: { 'x-vercel-mitigated': 'challenge' } })
      : new Response('ok');
  }) as unknown as typeof fetch;
  const limiter = createRequestLimiter({ concurrency: 1, minIntervalMs: 0, fetchImpl });
  const results = await Promise.allSettled(Array.from({ length: 6 }, (_, i) => limiter.fetch(`https://site.example/${i}`)));
  assert.equal(calls, 2, 'nothing is sent after the challenge');
  assert.equal(limiter.challenged, true);
  assert.equal(limiter.provider, 'vercel');
  assert.ok(results.slice(2).every((r) => r.status === 'rejected' && r.reason instanceof TargetChallengedError));
});

test('cloudflare challenges are recorded too, and note() works for custom fetch wrappers', () => {
  const limiter = createRequestLimiter();
  limiter.note(new Response('', { status: 403, headers: { 'cf-mitigated': 'challenge' } }));
  assert.equal(limiter.challenged, true);
  assert.equal(limiter.provider, 'cloudflare');
});

test('challenge messages name the right firewall and the fix', () => {
  assert.match(botChallengeMessage('https://a.example', 'vercel'), /Vercel's Security Checkpoint[\s\S]*Firewall[\s\S]*Bypass rule/);
  assert.match(botChallengeMessage('https://a.example', 'cloudflare'), /Cloudflare[\s\S]*WAF[\s\S]*Skip rule/);
  assert.match(botChallengeMessage('https://a.example', undefined), /Vercel or Cloudflare/);
});
