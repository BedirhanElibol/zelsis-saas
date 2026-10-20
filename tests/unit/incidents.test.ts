import { test } from 'node:test';
import assert from 'node:assert/strict';
import { INCIDENTS, incidentFor } from '@/data/incidents';

test('each incident has a real https source and plain text without invented figures', () => {
  for (const i of INCIDENTS) {
    assert.match(i.source.url, /^https:\/\/[^\s]+$/, i.id);
    assert.ok(i.what.length > 40 && i.what.length < 400, `${i.id}: what length`);
    assert.ok(i.year >= 2010 && i.year <= 2026, `${i.id}: year`);
  }
});

test('rules map to the incident of the same kind', () => {
  assert.equal(incidentFor(9106)?.id, 'first-american-2019');
  assert.equal(incidentFor(6010)?.id, 'lovable-rls-2025');
  assert.equal(incidentFor(18043)?.id, 'tea-app-2025');
  assert.equal(incidentFor(5013)?.id, 'toyota-github-key-2022');
  assert.equal(incidentFor(30307)?.id, 'starbucks-race-2015');
  assert.equal(incidentFor(30312)?.id, 'twitter-sms-pumping-2023');
});

test('rules without a matching incident show nothing', () => {
  assert.equal(incidentFor(28001), null);
  assert.equal(incidentFor(1244), null);
});

test('the one unverified figure says so', () => {
  assert.match(incidentFor(30312)!.what, /not independently verified/);
});
