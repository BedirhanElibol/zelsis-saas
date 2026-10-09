import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Stripe Charges 100x Less? Amount Must Be in Cents - Zelsis Guides',
  description:
    'Stripe amount and unit_amount are integers in the smallest currency unit. Why $19.99 becomes $0.20 or an error, how to use Math.round(price * 100), and zero-decimal currencies.',
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function StripeAmountCentsPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Stripe charges 100x less: amount must be in cents</h1>
      <p className="text-zinc-400">
        Your product costs $19.99, but the Stripe Checkout page shows $0.20, or the API rejects the request with an &quot;Invalid
        integer&quot; error. Stripe does not take prices in dollars. It takes an integer number of the smallest currency unit: cents for
        USD and EUR.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>The cause</h2>
        <p className="text-zinc-300">
          The <code>amount</code> field on PaymentIntents and the <code>unit_amount</code> field on Prices and Checkout line items are
          integers. <code>1999</code> means $19.99. Passing <code>19.99</code> fails because it is not an integer; passing{' '}
          <code>20</code> (a rounded dollar value) charges 20 cents, which is 100 times less than you meant.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: price in dollars"
          code={`const price = 19.99;

await stripe.paymentIntents.create({
  amount: price,          // rejected: not an integer
  currency: 'usd',
});

await stripe.checkout.sessions.create({
  mode: 'payment',
  line_items: [{
    quantity: 1,
    price_data: {
      currency: 'usd',
      unit_amount: Math.round(price), // 20 cents, not $19.99
      product_data: { name: 'Pro plan' },
    },
  }],
  success_url: \`\${origin}/success\`,
});`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>The fix</h2>
        <p className="text-zinc-300">
          Multiply by 100 and round. The rounding is not optional: floating point math gives <code>19.99 * 100 === 1998.9999999999998</code>,
          which Stripe rejects, and truncating with <code>Math.floor</code> or <code>| 0</code> would charge one cent too little.
        </p>
        <CodeBlock
          tone="good"
          label="Good: integer cents"
          code={`function toCents(price: number): number {
  return Math.round(price * 100);
}

await stripe.paymentIntents.create({
  amount: toCents(19.99), // 1999
  currency: 'usd',
});`}
        />
        <p className="text-zinc-300">
          A better long-term fix is to store prices in cents everywhere (database column <code>price_cents integer</code>) and only divide
          by 100 when you display them. Then there is no conversion to forget. Never take the amount from the browser either: look the price
          up on the server by product id, or use a Stripe Price id.
        </p>
        <CodeBlock
          tone="good"
          label="Good: display from cents"
          code={`const label = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
}).format(priceCents / 100); // "$19.99"`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Zero-decimal currencies</h2>
        <p className="text-zinc-300">
          &quot;Multiply by 100&quot; is only right for currencies with two decimal places. Some currencies have no minor unit, so the
          amount is the whole number: <code>amount: 500</code> in <code>jpy</code> is 500 yen, not 5 yen. Examples include JPY, KRW, VND
          and CLP. A few currencies use three decimals (such as BHD, KWD and OMR). Stripe&apos;s currency documentation has the full list and
          some special cases, so check it before you add a new currency.
        </p>
        <CodeBlock
          label="Convert per currency"
          code={`const ZERO_DECIMAL = new Set(['jpy', 'krw', 'vnd', 'clp' /* see Stripe docs for the full list */]);

function toStripeAmount(price: number, currency: string): number {
  return ZERO_DECIMAL.has(currency.toLowerCase())
    ? Math.round(price)
    : Math.round(price * 100);
}`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Verify it</h2>
        <TestStep>
          In test mode, create a Checkout session or PaymentIntent for your most expensive and cheapest products and read the amount on the
          hosted page or in the Dashboard. Add one assertion to your tests, for example that <code>toCents(19.99)</code> returns{' '}
          <code>1999</code> and <code>toCents(0.29)</code> returns <code>29</code>.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'BUG-10', title: 'Stripe amount or unit_amount given in dollars instead of cents' }]}>
        In files that use Stripe, Zelsis flags <code>amount</code> and <code>unit_amount</code> set to a decimal literal or to a variable
        holding one, and suggests the integer-cents fix.
      </ZelsisCatches>

      <p className="text-zinc-400">
        More logic bugs from real code:{' '}
        <Link href="/docs/real-world-bugs" className={LINK}>
          bugs we found in popular open-source repos
        </Link>
        .
      </p>

      <ScanCta />
    </article>
  );
}
