import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'How to Stop Charging Customers Twice with Stripe - Zelsis Guides',
  description:
    'Why customers get charged twice: double clicks, retries after a timeout, and webhooks delivered more than once. Idempotency keys, a disabled pay button and webhook de-duplication, with code and a test you can run.',
  alternates: { canonical: '/guides/stripe-double-charge' },
};

const H2 = 'text-xl font-semibold text-white';

export default function StripeDoubleChargePage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">How to stop charging customers twice with Stripe</h1>
      <p className="text-zinc-400">
        A double charge rarely comes from one big bug. It comes from three ordinary things: a customer clicks Pay twice, your server
        retries a request that timed out but actually went through, or Stripe delivers the same webhook more than once and your code
        fulfils the order again. Each is easy to miss in review because every line looks correct. Here is how to close all three.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>1. Send an idempotency key with every payment request</h2>
        <p className="text-zinc-300">
          Stripe accepts an <code>Idempotency-Key</code> header on POST requests. If the same key arrives again, Stripe returns the
          first result instead of creating a second charge. Derive the key from something that identifies this one purchase, such as
          the order ID, so a retry or a second click sends the same key.
        </p>
        <CodeBlock
          tone="bad"
          label="A retry or a second click creates a second PaymentIntent"
          code={`const intent = await stripe.paymentIntents.create({
  amount: order.totalCents,
  currency: 'usd',
  customer: order.customerId,
});`}
        />
        <CodeBlock
          tone="good"
          label="The same order always maps to the same request"
          code={`const intent = await stripe.paymentIntents.create(
  { amount: order.totalCents, currency: 'usd', customer: order.customerId },
  { idempotencyKey: \`order-\${order.id}-payment\` },
);`}
        />
        <p className="text-zinc-300">
          Stripe keeps keys for at least 24 hours. If the customer changes the cart, the order should get a new ID or a new key, because
          reusing a key with different parameters returns an error.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className={H2}>2. Disable the pay button while the request runs</h2>
        <p className="text-zinc-300">
          The idempotency key protects the server. The button protects the customer from waiting on two spinners and from the case
          where the key was built from something that changes between clicks.
        </p>
        <CodeBlock
          tone="good"
          label="One submission at a time"
          code={`const [paying, setPaying] = useState(false);

async function pay() {
  if (paying) return;
  setPaying(true);
  try {
    await confirmPayment();
  } finally {
    setPaying(false);
  }
}

<button onClick={pay} disabled={paying}>{paying ? 'Processing…' : 'Pay'}</button>`}
        />
      </section>

      <section className="space-y-3">
        <h2 className={H2}>3. Handle each webhook event once</h2>
        <p className="text-zinc-300">
          Stripe may send the same event more than once, for example when your endpoint answered slowly the first time. If the handler
          ships the order or adds credits on every delivery, the customer is not charged twice but you give the goods away twice, or
          send two receipts. Store the event ID and skip events you have already seen.
        </p>
        <CodeBlock
          tone="good"
          label="A unique constraint makes the check race-free"
          code={`-- once
create table processed_stripe_events (id text primary key, processed_at timestamptz default now());

// in the webhook handler, after verifying the signature
const inserted = await db.query(
  'insert into processed_stripe_events (id) values ($1) on conflict do nothing returning id',
  [event.id],
);
if (inserted.rowCount === 0) return new Response('already handled', { status: 200 });
await fulfil(event);`}
        />
      </section>

      <section className="space-y-3">
        <h2 className={H2}>Test it before you ship</h2>
        <TestStep>
          In Stripe test mode, open the checkout, throttle the network in your browser dev tools to Slow 3G and click Pay three times
          quickly. The dashboard should show one PaymentIntent.
        </TestStep>
        <TestStep>
          Resend a <code>checkout.session.completed</code> or <code>payment_intent.succeeded</code> event from the Stripe dashboard (or
          with <code>stripe events resend</code>). The order should be fulfilled once and the second delivery should answer 200 without
          doing anything.
        </TestStep>
      </section>

      <ZelsisCatches
        rules={[
          { id: 'FINTECH-03', title: 'Missing Idempotency-Key on a payment mutation' },
          { id: 'UI-INTERACT-11', title: 'Button that can submit the same mutation twice' },
        ]}
      >
        Zelsis checks each pull request for payment calls sent without an idempotency key and for submit buttons that stay clickable
        while their request runs, and shows the file and line with a fix.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
