import { test } from 'node:test';
import assert from 'node:assert/strict';
import { acceptReview, applyReviews, blockingFindings, localImports, AI_VERIFY_MAX_FINDINGS } from '@/lib/ai-verify';
import { aiDoubleCheck, aiReviewSection } from '@/lib/github/ai-double-check';
import type { Finding } from '@/data/schema';

const finding = (id: string, severity: Finding['severity'], extra: Partial<Finding> = {}): Finding => ({
  id, ruleId: 15, type: 'SECURITY', title: 'Unauthenticated API Mutation', severity, category: 'Auth',
  filePath: 'app/api/orders/route.ts', lineRange: 'L4', snippet: '', reproductionSteps: [], remediationPrompt: '',
  status: 'OPEN', falsePositive: false, maturity: 'verified', ...extra,
});

test('blockingFindings keeps open, gating CRITICAL findings only, capped', () => {
  const list = [
    finding('a', 'CRITICAL'),
    finding('b', 'HIGH'),
    finding('c', 'CRITICAL', { maturity: 'experimental' }),
    finding('d', 'CRITICAL', { falsePositive: true }),
    finding('e', 'CRITICAL', { maturity: 'unproven' }),
    ...['f', 'g', 'h', 'i'].map((id) => finding(id, 'CRITICAL')),
  ];
  const ids = blockingFindings(list).map((f) => f.id);
  assert.equal(ids.length, AI_VERIFY_MAX_FINDINGS);
  assert.deepEqual(ids, ['a', 'f', 'g']);
});

test('localImports resolves relative and @/ imports that exist in the repo', () => {
  const paths = new Set(['lib/auth.ts', 'lib/db/index.ts', 'app/api/orders/helpers.tsx']);
  const src = [
    "import { requireUser } from '@/lib/auth';",
    "import db from '../../../lib/db';",
    "import { x } from './helpers';",
    "import React from 'react';",
    "const m = await import('./missing');",
  ].join('\n');
  assert.deepEqual(localImports('app/api/orders/route.ts', src, (p) => paths.has(p)), [
    'lib/auth.ts', 'lib/db/index.ts', 'app/api/orders/helpers.tsx',
  ]);
});

test('a guarded verdict must name a file that was sent, otherwise it is unsure', () => {
  const sent = ['app/api/orders/route.ts', 'lib/auth.ts'];
  assert.equal(acceptReview({ verdict: 'guarded', reason: 'requireUser() in lib/auth.ts runs first.' }, sent).verdict, 'guarded');
  assert.equal(acceptReview({ verdict: 'guarded', reason: 'auth.ts line 3 checks the session' }, sent).verdict, 'guarded');
  assert.equal(acceptReview({ verdict: 'guarded', reason: 'Probably protected somewhere.' }, sent).verdict, 'unsure');
  assert.equal(acceptReview({ verdict: 'real', reason: 'No check.' }, sent).verdict, 'real');
});

test('applyReviews only softens guarded CRITICAL to HIGH and keeps every finding', () => {
  const list = [finding('a', 'CRITICAL'), finding('b', 'CRITICAL'), finding('c', 'CRITICAL')];
  const out = applyReviews(list, new Map([
    ['a', { verdict: 'guarded', reason: 'lib/auth.ts' }],
    ['b', { verdict: 'real', reason: 'no check' }],
  ]));
  assert.equal(out.length, 3);
  assert.equal(out[0].severity, 'HIGH');
  assert.equal(out[0].aiReview?.verdict, 'guarded');
  assert.equal(out[1].severity, 'CRITICAL');
  assert.equal(out[2].aiReview, undefined);
});

test('aiDoubleCheck does nothing without an API key', async () => {
  const saved = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    let reads = 0;
    const list = [finding('a', 'CRITICAL')];
    const res = await aiDoubleCheck(list, new Set(), async () => { reads++; return ''; });
    assert.equal(res.findings, list);
    assert.equal(reads, 0);
  } finally {
    if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
  }
});

test('aiReviewSection flattens the model reason into one short line', () => {
  const f = finding('a', 'HIGH');
  const md = aiReviewSection([{ finding: f, review: { verdict: 'guarded', reason: 'line one\n\n## injected heading' } }]);
  assert.match(md, /not blocking, guarded\. line one ## injected heading/);
  assert.equal(md.split('\n').filter((l) => l.startsWith('#### ')).length, 1);
});
