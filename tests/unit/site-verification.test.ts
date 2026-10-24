import { test } from 'node:test';
import assert from 'node:assert/strict';
import { coveringHostnames, createProbeKey, createVerificationToken, isVerificationToken, normalizeHostname, verifyOwnership } from '../../lib/site-verification';

test('normalizeHostname accepts public domains and URLs, rejects IPs, ports, localhost and junk', () => {
  assert.equal(normalizeHostname('Example.COM'), 'example.com');
  assert.equal(normalizeHostname('https://app.example.com/pricing?x=1'), 'app.example.com');
  assert.equal(normalizeHostname('shop.example.co.uk.'), 'shop.example.co.uk');
  for (const bad of ['127.0.0.1', 'http://10.0.0.5/', 'localhost', 'https://example.com:8443', 'https://user:pw@example.com', 'intranet', 'api.internal', '[::1]', 'example.com/path', 'exa mple.com', '-bad.com', '']) {
    assert.equal(normalizeHostname(bad), null, bad);
  }
});

test('a verified parent domain covers its subdomains, not the other way round', () => {
  assert.deepEqual(coveringHostnames('app.eu.example.com'), ['app.eu.example.com', 'eu.example.com', 'example.com']);
  assert.deepEqual(coveringHostnames('example.com'), ['example.com']);
});

test('tokens are 32 hex characters and unique', () => {
  const a = createVerificationToken();
  assert.ok(isVerificationToken(a));
  assert.notEqual(a, createVerificationToken());
  assert.equal(isVerificationToken('zelsis-verify=abc'), false);
});

test('verifyOwnership accepts the well-known file or the DNS TXT record and nothing else', async () => {
  const token = createVerificationToken();
  const urls: string[] = [];
  const none = { fetchText: async (u: string) => { urls.push(u); return null; }, resolveTxt: async () => [] as string[][] };
  assert.equal(await verifyOwnership('example.com', token, { ...none, fetchText: async () => `${token}\n` }), 'file');
  assert.equal(await verifyOwnership('example.com', token, { ...none, resolveTxt: async () => [['v=spf1 -all'], ['zelsis-verify=', token]] }), 'dns');
  assert.equal(await verifyOwnership('example.com', token, { ...none, fetchText: async () => `other ${token.slice(0, 31)}` }), null);
  assert.equal(await verifyOwnership('example.com', token, { ...none, resolveTxt: async () => [[`zelsis-verify=${createVerificationToken()}`]] }), null);
  assert.equal(await verifyOwnership('example.com', token, none), null);
  assert.ok(urls.length > 0 && urls.every((u) => u === 'https://example.com/.well-known/zelsis-verify.txt'), 'only the well-known file over https');
  assert.equal(await verifyOwnership('127.0.0.1', token, { ...none, fetchText: async () => token }), null, 'IP hosts are never verified');
  assert.equal(await verifyOwnership('example.com', 'not-a-token', { ...none, fetchText: async () => 'not-a-token' }), null);
  assert.equal(await verifyOwnership('example.com', token, { fetchText: async () => { throw new Error('net'); }, resolveTxt: async () => { throw new Error('dns'); } }), null);
});

test('probe keys are secret-length, distinct from verification tokens and unique', () => {
  const k = createProbeKey();
  assert.match(k, /^zp_[0-9a-f]{48}$/);
  assert.equal(isVerificationToken(k), false);
  assert.notEqual(k, createProbeKey());
});
