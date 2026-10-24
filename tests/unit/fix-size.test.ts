import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixSize } from '@/lib/fix-size';

test('fix size follows the kind of finding', () => {
  assert.equal(fixSize({ ruleId: 5010, category: 'Secrets', title: 'Stripe Live Secret Key Exposure', type: 'SECURITY' }).size, 'Small');
  assert.equal(fixSize({ ruleId: 30307, category: 'Data Integrity', title: 'Balance Updated With a Race Condition', type: 'SECURITY' }).size, 'Large');
  assert.equal(fixSize({ ruleId: 3001, category: 'Database', title: 'PostgreSQL Table "notes" Missing Row Level Security (RLS)', type: 'INFRA_DATABASE' }).kind, 'database migration');
  assert.equal(fixSize({ ruleId: 29301, category: 'Broken Access Control', title: 'IDOR: Record Accessed by Request ID', type: 'SECURITY' }).size, 'Medium');
  assert.equal(fixSize({ ruleId: 24101, category: 'Injection & Data Handling', title: 'SQL Injection: Query Built From Dynamic Values', type: 'SECURITY' }).kind, 'change the call site');
  assert.equal(fixSize({ ruleId: 7004, category: 'Container Security', title: 'Docker Container Running as Default Root User', type: 'INFRA_DATABASE' }).kind, 'configuration change');
});
