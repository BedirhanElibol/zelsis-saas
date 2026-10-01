import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { isPwnedPassword, rangeContainsSuffix } from '../../lib/pwned-password';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PREFIX = '5BAA6';
const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

test('rangeContainsSuffix matches only listed suffixes with a positive count', () => {
  const body = `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${SUFFIX}:9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0`;
  assert.equal(rangeContainsSuffix(body, SUFFIX), true);
  assert.equal(rangeContainsSuffix(body, '00D4F6E8FA6EECAD2A3AA415EEC418D38EC'), false); // padding row
  assert.equal(rangeContainsSuffix(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), false);
});

test('isPwnedPassword sends only the 5-char hash prefix', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => new Response(`${SUFFIX}:3`));
  try {
    assert.equal(await isPwnedPassword('password'), true);
    const url = String(fetchMock.mock.calls[0].arguments[0]);
    assert.equal(url, `https://api.pwnedpasswords.com/range/${PREFIX}`);
  } finally {
    fetchMock.mock.restore();
  }
});

test('isPwnedPassword fails open when the service is unreachable', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => { throw new Error('offline'); });
  try {
    assert.equal(await isPwnedPassword('password'), null);
  } finally {
    fetchMock.mock.restore();
  }
});
