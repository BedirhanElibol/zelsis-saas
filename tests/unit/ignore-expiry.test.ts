import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseZelsisIgnore } from '../../lib/scanner/ignore-parser';

const NOW = Date.UTC(2027, 0, 15);

describe('.zelsisignore reason and expiry', () => {
  it('honors a line before its date, including the last day', () => {
    const { ignoredRuleIds, lapsed } = parseZelsisIgnore('RULE-12 # reason: test key; expires: 2027-01-15', NOW);
    assert.ok(ignoredRuleIds.has(12));
    assert.equal(lapsed.length, 0);
  });

  it('brings a finding back after the date and reports it', () => {
    const { ignoredRuleIds, lapsed } = parseZelsisIgnore('RULE-12 # reason: test key; expires: 2027-01-14', NOW);
    assert.ok(!ignoredRuleIds.has(12));
    assert.deepEqual(lapsed, [{ entry: 'RULE-12', expires: '2027-01-14', reason: 'test key' }]);
  });

  it('does not honor an unreadable date', () => {
    for (const date of ['someday', '2027-02-31']) {
      const { ignoredRuleIds, lapsed } = parseZelsisIgnore(`RULE-12 # expires: ${date}`, NOW);
      assert.ok(!ignoredRuleIds.has(12), date);
      assert.equal(lapsed.length, 1, date);
    }
  });

  it('applies expiry to paths and keeps plain lines working', () => {
    const { ignoredPaths, ignoredRuleIds } = parseZelsisIgnore('Vendor/Old/ # expires: 2027-02-01\nold/ # expires: 2026-01-01\nRULE-7 # only a note\nRULE-8\n# comment', NOW);
    assert.deepEqual(ignoredPaths, ['vendor/old/']);
    assert.ok(ignoredRuleIds.has(7) && ignoredRuleIds.has(8));
  });
});
