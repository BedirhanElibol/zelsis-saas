import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TestimonialSchema } from '../../lib/validations/api-schemas';

const base = { accessToken: 'x'.repeat(30), quote: 'It caught a webhook that charged twice.', displayName: 'Jane D.', consent: 'on' };

test('a quote with consent is accepted, role optional', () => {
  assert.ok(TestimonialSchema.safeParse(base).success);
  assert.ok(TestimonialSchema.safeParse({ ...base, role: 'CTO, Acme' }).success);
});

test('consent is required to save a quote', () => {
  const r = TestimonialSchema.safeParse({ ...base, consent: undefined });
  assert.ok(!r.success);
  assert.match(r.error!.issues[0].message, /Tick the box/);
});

test('length limits match the database checks', () => {
  assert.ok(!TestimonialSchema.safeParse({ ...base, quote: 'Too short' }).success);
  assert.ok(!TestimonialSchema.safeParse({ ...base, quote: 'x'.repeat(281) }).success);
  assert.ok(!TestimonialSchema.safeParse({ ...base, displayName: '' }).success);
  assert.ok(!TestimonialSchema.safeParse({ ...base, role: 'r'.repeat(81) }).success);
});
