import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const NEXT16_PKG = `{
  "name": "acme-app",
  "private": true,
  "dependencies": {
    "next": "^16.0.3",
    "react": "19.2.0",
    "react-dom": "19.2.0"
  }
}
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [28701],
    name: 'Clerk/Svix webhook verified over JSON.stringify(await req.json())',
    detects: f('app/api/webhooks/clerk/route.ts', `import { Webhook } from 'svix';
import { headers } from 'next/headers';
import type { WebhookEvent } from '@clerk/nextjs/server';

export async function POST(req: Request) {
  const headerPayload = await headers();
  const payload = await req.json();
  const body = JSON.stringify(payload);
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  let evt: WebhookEvent;
  try {
    evt = wh.verify(body, {
      'svix-id': headerPayload.get('svix-id')!,
      'svix-timestamp': headerPayload.get('svix-timestamp')!,
      'svix-signature': headerPayload.get('svix-signature')!,
    }) as WebhookEvent;
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }
  await syncUser(evt);
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/clerk/route.ts', `import { Webhook } from 'svix';
import { headers } from 'next/headers';
import type { WebhookEvent } from '@clerk/nextjs/server';

export async function POST(req: Request) {
  const headerPayload = await headers();
  const body = await req.text();
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  let evt: WebhookEvent;
  try {
    evt = wh.verify(body, {
      'svix-id': headerPayload.get('svix-id')!,
      'svix-timestamp': headerPayload.get('svix-timestamp')!,
      'svix-signature': headerPayload.get('svix-signature')!,
    }) as WebhookEvent;
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }
  await syncUser(evt);
  return new Response(JSON.stringify({ received: true }));
}
`)
  },
  {
    ruleIds: [28701],
    name: 'Stripe constructEvent over JSON.stringify(req.body) in Express',
    detects: f('src/routes/billing.ts', `import express from 'express';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export const router = express.Router();

router.post('/webhook', express.json(), async (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(JSON.stringify(req.body), sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return res.status(400).send('Webhook Error');
  }
  await handleStripeEvent(event);
  res.json({ received: true });
});
`),
    ignores: f('src/routes/billing.ts', `import express from 'express';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export const router = express.Router();

router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return res.status(400).send('Webhook Error');
  }
  await handleStripeEvent(event);
  res.json(JSON.stringify({ received: true }));
});
`)
  },
  {
    ruleIds: [28702],
    name: 'Stripe checkout webhook increments credits with Prisma without recording event.id',
    detects: f('app/api/stripe/webhook/route.ts', `import Stripe from 'stripe';
import { prisma } from '@/lib/prisma';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature')!;
  const evt = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);

  if (evt.type === 'checkout.session.completed') {
    const session = evt.data.object as Stripe.Checkout.Session;
    const userId = session.metadata?.userId;
    const amount = Number(session.metadata?.credits ?? 0);
    await prisma.user.update({
      where: { id: userId },
      data: { credits: { increment: amount } },
    });
  }
  return new Response('ok');
}
`),
    ignores: f('app/api/stripe/webhook/route.ts', `import Stripe from 'stripe';
import { prisma } from '@/lib/prisma';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature')!;
  const evt = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);

  if (evt.type === 'checkout.session.completed') {
    const session = evt.data.object as Stripe.Checkout.Session;
    const userId = session.metadata?.userId;
    const amount = Number(session.metadata?.credits ?? 0);
    await prisma.$transaction(async (tx) => {
      const seen = await tx.processedWebhook.findUnique({ where: { id: evt.id } });
      if (seen) return;
      await tx.processedWebhook.create({ data: { id: evt.id } });
      await tx.user.update({
        where: { id: userId },
        data: { credits: { increment: amount } },
      });
    });
  }
  return new Response('ok');
}
`)
  },
  {
    ruleIds: [28702],
    name: 'Lemon Squeezy order webhook adds credits through a Supabase RPC without dedupe',
    detects: f('src/server/webhooks/lemonsqueezy.ts', `import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { supabaseAdmin } from '../supabase';

export async function lemonWebhook(req: Request, res: Response) {
  const digest = crypto.createHmac('sha256', process.env.LEMON_WEBHOOK_SECRET!).update(req.rawBody).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(req.get('x-signature') || ''))) {
    return res.status(401).end();
  }
  const payload = JSON.parse(req.rawBody.toString());
  if (payload.meta.event_name === 'order_created') {
    const userId = payload.meta.custom_data.user_id;
    await supabaseAdmin.rpc('increment_credits', { uid: userId, amount: 100 });
  }
  res.status(200).end();
}
`),
    ignores: f('src/server/webhooks/lemonsqueezy.ts', `import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { supabaseAdmin } from '../supabase';

export async function lemonWebhook(req: Request, res: Response) {
  const digest = crypto.createHmac('sha256', process.env.LEMON_WEBHOOK_SECRET!).update(req.rawBody).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(req.get('x-signature') || ''))) {
    return res.status(401).end();
  }
  const payload = JSON.parse(req.rawBody.toString());
  if (payload.meta.event_name === 'order_created') {
    const { error } = await supabaseAdmin.from('orders').insert({ order_id: payload.data.id, user_id: payload.meta.custom_data.user_id });
    if (error?.code === '23505') return res.status(200).end();
    await supabaseAdmin.rpc('increment_credits', { uid: payload.meta.custom_data.user_id, amount: 100 });
  }
  res.status(200).end();
}
`)
  },
  {
    ruleIds: [28703],
    name: 'Hand-rolled webhook HMAC signs t= timestamp but never checks its age',
    detects: f('app/api/webhooks/payments/route.ts', `import crypto from 'crypto';

export async function POST(req: Request) {
  const raw = await req.text();
  const header = req.headers.get('x-payments-signature') || '';
  const parts = Object.fromEntries(header.split(',').map((kv) => kv.split('=')));
  const timestamp = parts['t'];
  const expected = crypto.createHmac('sha256', process.env.PAYMENTS_WEBHOOK_SECRET!).update(\`\${timestamp}.\${raw}\`).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts['v1'] || ''))) {
    return new Response('bad signature', { status: 401 });
  }
  await handlePayment(JSON.parse(raw));
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/payments/route.ts', `import crypto from 'crypto';

const TOLERANCE_SECONDS = 300;

export async function POST(req: Request) {
  const raw = await req.text();
  const header = req.headers.get('x-payments-signature') || '';
  const parts = Object.fromEntries(header.split(',').map((kv) => kv.split('=')));
  const timestamp = parts['t'];
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > TOLERANCE_SECONDS) {
    return new Response('stale', { status: 401 });
  }
  const expected = crypto.createHmac('sha256', process.env.PAYMENTS_WEBHOOK_SECRET!).update(\`\${timestamp}.\${raw}\`).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts['v1'] || ''))) {
    return new Response('bad signature', { status: 401 });
  }
  await handlePayment(JSON.parse(raw));
  return new Response('ok');
}
`)
  },
  {
    ruleIds: [28704],
    name: 'Inline window message listener stores a token from event.data with no origin check',
    detects: f('components/auth/popup-listener.tsx', `'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export function PopupListener() {
  const router = useRouter();
  useEffect(() => {
    const off = () => window.removeEventListener('message', () => {});
    window.addEventListener('message', (event) => {
      if (event.data?.type === 'oauth-complete') {
        localStorage.setItem('session', event.data.token);
        router.push(event.data.redirectTo);
      }
    });
    return off;
  }, [router]);
  return null;
}
`),
    ignores: f('components/auth/popup-listener.tsx', `'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export function PopupListener() {
  const router = useRouter();
  useEffect(() => {
    const off = () => window.removeEventListener('message', () => {});
    window.addEventListener('message', (event) => {
      if (event.origin !== window.location.origin) return;
      if (event.data?.type === 'oauth-complete') {
        localStorage.setItem('session', event.data.token);
        router.push(event.data.redirectTo);
      }
    });
    return off;
  }, [router]);
  return null;
}
`)
  },
  {
    ruleIds: [28704],
    name: 'Named message handler destructures data and injects HTML without an origin check',
    detects: f('src/embed/widget.ts', `const container = document.getElementById('widget-root')!;

function handleMessage({ data }: MessageEvent) {
  if (data.kind === 'render') {
    container.innerHTML = data.html;
  }
}

window.addEventListener('message', handleMessage);
`),
    ignores: f('src/embed/widget.ts', `const container = document.getElementById('widget-root')!;
const TRUSTED_ORIGIN = 'https://app.acme.com';

function handleMessage({ data, origin }: MessageEvent) {
  if (origin !== TRUSTED_ORIGIN) return;
  if (data.kind === 'render') {
    container.textContent = data.text;
  }
}

window.addEventListener('message', handleMessage);
`)
  },
  {
    ruleIds: [28705],
    name: 'RLS policy grants project access by the JWT email claim',
    detects: f('supabase/migrations/20250101000000_invites.sql', `create table public.project_invites (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id),
  invitee_email text not null
);
alter table public.project_invites enable row level security;

create policy "Invitees can read their invites"
  on public.project_invites for select
  to authenticated
  using (invitee_email = (auth.jwt() ->> 'email'));
`),
    ignores: f('supabase/migrations/20250101000000_invites.sql', `create table public.project_invites (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id),
  invitee_id uuid not null references auth.users(id)
);
alter table public.project_invites enable row level security;

create policy "Invitees can read their invites"
  on public.project_invites for select
  to authenticated
  using (invitee_id = (select auth.uid()));
`)
  },
  {
    ruleIds: [28706],
    name: 'Next 16 page reads params.id synchronously before an ownership query',
    detects: [
      { path: 'package.json', content: NEXT16_PKG },
      { path: 'app/invoices/[id]/page.tsx', content: `import { notFound } from 'next/navigation';
import { getCurrentUser } from '@/lib/session';
import { db } from '@/lib/db';

export default async function InvoicePage({ params }: { params: { id: string } }) {
  const user = await getCurrentUser();
  const invoice = await db.invoice.findFirst({ where: { id: params.id, ownerId: user?.id } });
  if (!invoice) notFound();
  return <h1>Invoice {invoice.number}</h1>;
}
` }
    ],
    ignores: [
      { path: 'package.json', content: NEXT16_PKG },
      { path: 'app/invoices/[id]/page.tsx', content: `import { notFound } from 'next/navigation';
import { getCurrentUser } from '@/lib/session';
import { db } from '@/lib/db';

export default async function InvoicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getCurrentUser();
  const invoice = await db.invoice.findFirst({ where: { id, ownerId: user?.id } });
  if (!invoice) notFound();
  return <h1>Invoice {invoice.number}</h1>;
}
` }
    ]
  },
  {
    ruleIds: [28706],
    name: 'Next 16 route handler reads context.params synchronously',
    detects: [
      { path: 'package.json', content: NEXT16_PKG },
      { path: 'app/api/projects/[projectId]/route.ts', content: `import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

export async function DELETE(req: Request, context: { params: { projectId: string } }) {
  const session = await auth();
  await db.project.deleteMany({ where: { id: context.params.projectId, ownerId: session?.user.id } });
  return Response.json({ ok: true });
}
` }
    ],
    ignores: [
      { path: 'package.json', content: NEXT16_PKG },
      { path: 'app/api/projects/[projectId]/route.ts', content: `import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

export async function DELETE(req: Request, context: { params: Promise<{ projectId: string }> }) {
  const session = await auth();
  const { projectId } = await context.params;
  await db.project.deleteMany({ where: { id: projectId, ownerId: session?.user.id } });
  return Response.json({ ok: true });
}
` }
    ]
  }
];
