import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RULE_IMPACT } from '@/data/rule-impact';
import { runStaticCodeScan } from '@/lib/scanner-engine';

test('impact sentences are short, plain and free of banned wording', () => {
  for (const [id, text] of Object.entries(RULE_IMPACT)) {
    assert.ok(text.length > 0 && text.length <= 110, `rule ${id}: keep it to one short sentence`);
    assert.ok(text.endsWith('.'), `rule ${id}: end with a period`);
    assert.ok(!/—|small teams?/i.test(text), `rule ${id}: no em dash or "small team"`);
  }
});

test('scanner attaches the impact sentence to findings of a mapped rule', async () => {
  const content = [
    "import Stripe from 'stripe';",
    'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);',
    'export async function POST(req: Request) {',
    '  const body = await req.json();',
    '  const intent = await stripe.paymentIntents.create({ amount: body.amount, currency: "usd" });',
    '  return Response.json({ id: intent.id });',
    '}',
  ].join('\n');
  const { findings } = await runStaticCodeScan([{ path: 'app/api/pay/route.ts', content }], 'impact');
  const f = findings.find((x) => x.ruleId === 23004);
  assert.ok(f, 'SAAS-04 should fire on a client-supplied amount');
  assert.equal(f.impact, RULE_IMPACT[23004]);
});
