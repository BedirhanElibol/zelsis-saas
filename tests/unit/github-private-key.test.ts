import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync } from 'crypto';
import { normalizePrivateKey } from '../../lib/github/private-key';

// A throwaway key generated per run, in the PKCS#1 format GitHub issues
const pem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const loads = (k: string | null) => { assert.ok(k); createPrivateKey(k); return true; };

test('pasted private keys in common broken shapes still load', () => {
  assert.ok(loads(normalizePrivateKey(pem)), 'as downloaded');
  assert.ok(loads(normalizePrivateKey(pem.replace(/\n/g, '\\n'))), 'literal \\n');
  assert.ok(loads(normalizePrivateKey(pem.replace(/\n/g, ' '))), 'newlines became spaces');
  assert.ok(loads(normalizePrivateKey(`"${pem.replace(/\n/g, '\r\n')}"`)), 'quoted with CRLF');
  assert.ok(loads(normalizePrivateKey(Buffer.from(pem).toString('base64'))), 'whole PEM base64-encoded');
  assert.equal(normalizePrivateKey('not a key'), null);
  assert.equal(normalizePrivateKey(undefined), null);
});
