import React from 'react';
import Link from 'next/link';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'Stripe Webhook: No Signatures Found Matching the Expected Signature - Zelsis Guides',
  description:
    'Why Stripe webhook signature verification fails in Next.js and Express (parsed body, wrong secret), why skipping it lets anyone fake a payment, and the raw-body fix with a test.',
};

const H2 = 'text-xl font-semibold text-white';
const LINK = 'text-emerald-400 hover:text-emerald-300 underline';

export default function StripeWebhookSignaturePage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Stripe webhook: &quot;No signatures found matching the expected signature&quot;</h1>
      <p className="text-zinc-400">
        Your webhook handler calls <code>stripe.webhooks.constructEvent</code> and every event fails with this error. The tempting fix is
        to delete the check and read the JSON directly. Then anyone who finds the URL can send a fake <code>checkout.session.completed</code>{' '}
        and get a paid plan without paying.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>Cause 1: the body was parsed before you verified it</h2>
        <p className="text-zinc-300">
          Stripe signs the exact bytes it sent. If a framework parses the body into an object and you turn it back into a string, the
          spacing and key order can change, and the signature no longer matches. Verify over the raw body.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: verifying a re-serialized body"
          code={`// app/api/webhooks/stripe/route.ts
export async function POST(req: Request) {
  const body = await req.json();
  const event = stripe.webhooks.constructEvent(
    JSON.stringify(body),                 // not the bytes Stripe signed
    req.headers.get('stripe-signature')!,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );
}`}
        />
        <CodeBlock
          tone="good"
          label="Good: Next.js App Router, raw text"
          code={`export async function POST(req: Request) {
  const body = await req.text();
  const signature = req.headers.get('stripe-signature');
  if (!signature) return new Response('Missing signature', { status: 400 });

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }

  // handle event.type here
  return new Response(null, { status: 200 });
}`}
        />
        <p className="text-zinc-300">
          In Express, <code>app.use(express.json())</code> runs before your route and parses the body. Give the webhook route its own raw
          parser and register it before the JSON middleware.
        </p>
        <CodeBlock
          tone="good"
          label="Good: Express raw body"
          code={`app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).send('Invalid signature');
  }
  res.sendStatus(200);
});

app.use(express.json()); // after the webhook route`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Cause 2: the wrong signing secret</h2>
        <p className="text-zinc-300">
          Each webhook endpoint has its own <code>whsec_</code> secret, and test mode and live mode endpoints have different ones. The
          Stripe CLI prints yet another secret when you run <code>stripe listen</code>. Use that one locally and the endpoint&apos;s secret
          from the Dashboard in production. The secret key (<code>sk_</code>) is a different value and never works here.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Why you should never skip the check</h2>
        <p className="text-zinc-300">
          A webhook URL is not a secret. It shows up in logs, docs and browser history, and attackers guess common paths like{' '}
          <code>/api/webhooks/stripe</code>. Without signature verification, a single forged request can mark an order as paid, grant
          credits or upgrade a plan. If you also handle retries, store the event id so the same event is processed once: see{' '}
          <Link href="/guides/stripe-double-charge" className={LINK}>
            how to stop charging customers twice
          </Link>
          .
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Verify it</h2>
        <TestStep>
          Run <code>stripe listen --forward-to localhost:3000/api/webhooks/stripe</code>, then <code>stripe trigger checkout.session.completed</code>{' '}
          and expect a 200. Then send the same path a request without a signature, for example{' '}
          <code>curl -X POST localhost:3000/api/webhooks/stripe -d &apos;{'{}'}&apos;</code>, and expect a 400 with no change in your database.
        </TestStep>
      </section>

      <ZelsisCatches
        rules={[
          { id: 'FINTECH-04', title: 'Payment webhook processes events without verifying the signature' },
          { id: 'SAAS3-01', title: 'Webhook signature verified over re-serialized JSON instead of the raw body' },
        ]}
      >
        Zelsis flags payment webhook handlers that read the request body without a signature check, and handlers that verify over{' '}
        <code>JSON.stringify</code> of a parsed body, on the pull request.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
