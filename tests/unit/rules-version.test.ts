import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isScanOutdated, RULES_UPDATED_AT } from '../../lib/rules-version';

test('a scan is outdated when it predates the current rules or has no date', () => {
  assert.match(RULES_UPDATED_AT, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(isScanOutdated({ findings: [{}], lastScanIso: '2020-01-01T10:00:00Z' }), true);
  assert.equal(isScanOutdated({ findings: [{}] }), true);
  assert.equal(isScanOutdated({ findings: [{}], lastScanIso: `${RULES_UPDATED_AT}T23:59:00Z` }), false);
  assert.equal(isScanOutdated({ findings: [] }), false);
});
