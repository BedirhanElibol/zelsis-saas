import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29660], name: 'BUG-60 email / Stripe call not awaited in a route handler',
    detects: f('app/api/invite/route.ts', `import { NextResponse } from 'next/server';
import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);
export async function POST(req: Request) {
  const { email } = await req.json();
  resend.emails.send({ from: 'team@acme.dev', to: email, subject: 'You are invited', html: '<p>Join</p>' });
  fetch('https://hooks.slack.com/services/x', { method: 'POST', body: JSON.stringify({ text: email }) });
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('app/api/invite/route.ts', `import { NextResponse, after } from 'next/server';
import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);
export async function POST(req: Request) {
  const { email } = await req.json();
  const { error } = await resend.emails.send({ from: 'team@acme.dev', to: email, subject: 'You are invited', html: '<p>Join</p>' });
  if (error) return NextResponse.json({ error: error.message }, { status: 502 });
  after(() => {
    void fetch('https://hooks.slack.com/services/x', { method: 'POST', body: JSON.stringify({ text: email }) });
  });
  fetch('https://api.example.com/warmup');
  return NextResponse.json({ ok: true });
}
`),
  },
  {
    ruleIds: [29661], name: 'BUG-61 return without await inside try',
    detects: f('lib/billing.ts', `export async function loadInvoices(customerId: string) {
  try {
    return fetch(\`/api/invoices?customer=\${customerId}\`);
  } catch (err) {
    console.error('invoice fetch failed', err);
    return null;
  }
}
`),
    ignores: f('lib/billing.ts', `export async function loadInvoices(customerId: string) {
  try {
    return await fetch(\`/api/invoices?customer=\${customerId}\`);
  } catch (err) {
    console.error('invoice fetch failed', err);
    return null;
  }
}
export async function loadAll() {
  return fetch('/api/invoices');
}
`),
  },
  {
    ruleIds: [29662], name: 'BUG-62 .map(async) result returned as data',
    detects: f('app/api/projects/route.ts', `import { NextResponse } from 'next/server';
export async function GET() {
  const projects = await prisma.project.findMany();
  const withOwners = projects.map(async (p) => ({ ...p, owner: await prisma.user.findUnique({ where: { id: p.ownerId } }) }));
  return NextResponse.json({ projects: withOwners, total: withOwners.length });
}
`),
    ignores: f('app/api/projects/route.ts', `import { NextResponse } from 'next/server';
export async function GET() {
  const projects = await prisma.project.findMany();
  const pending = projects.map(async (p) => ({ ...p, owner: await prisma.user.findUnique({ where: { id: p.ownerId } }) }));
  const withOwners = await Promise.all(pending);
  return NextResponse.json({ projects: withOwners, total: withOwners.length });
}
`),
  },
  {
    ruleIds: [29663], name: 'BUG-63 async predicate in filter',
    detects: f('lib/access.ts', `export async function visibleDocs(user: User, docs: Doc[]) {
  return docs.filter(async (doc) => await canRead(user.id, doc.id));
}
`),
    ignores: f('lib/access.ts', `export async function visibleDocs(user: User, docs: Doc[]) {
  const allowed = await Promise.all(docs.map(async (doc) => canRead(user.id, doc.id)));
  return docs.filter((_, i) => allowed[i]);
}
`),
  },
  {
    ruleIds: [29664], name: 'BUG-64 async reduce without awaiting the accumulator',
    detects: f('lib/stats.ts', `export async function totalsByTeam(teams: Team[]) {
  return teams.reduce(async (acc, team) => {
    acc[team.id] = await countMembers(team.id);
    return acc;
  }, {} as Record<string, number>);
}
`),
    ignores: f('lib/stats.ts', `export async function totalsByTeam(teams: Team[]) {
  return teams.reduce(async (accP, team) => {
    const acc = await accP;
    acc[team.id] = await countMembers(team.id);
    return acc;
  }, Promise.resolve({} as Record<string, number>));
}
`),
  },
  {
    ruleIds: [29665], name: 'BUG-65 async check used in a condition without await',
    detects: f('app/api/admin/route.ts', `async function isAdmin(userId: string) {
  const row = await db.user.findUnique({ where: { id: userId } });
  return row?.role === 'admin';
}
export async function DELETE(req: Request) {
  const userId = req.headers.get('x-user')!;
  if (!isAdmin(userId)) return new Response('Forbidden', { status: 403 });
  await db.post.deleteMany();
  return new Response('ok');
}
`),
    ignores: f('app/api/admin/route.ts', `async function isAdmin(userId: string) {
  const row = await db.user.findUnique({ where: { id: userId } });
  return row?.role === 'admin';
}
function isOwner(userId: string, ownerId: string) { return userId === ownerId; }
export async function DELETE(req: Request) {
  const userId = req.headers.get('x-user')!;
  if (!(await isAdmin(userId))) return new Response('Forbidden', { status: 403 });
  if (isOwner(userId, 'x')) console.log('owner');
  await db.post.deleteMany();
  return new Response('ok');
}
`),
  },
  {
    ruleIds: [29666], name: 'BUG-66 balance read then written back (lost update)',
    detects: f('app/actions/credits.ts', `'use server';
export async function spendCredits(userId: string, cost: number) {
  const supabase = await createClient();
  const { data: profile } = await supabase.from('profiles').select('credits').eq('id', userId).single();
  if (!profile || profile.credits < cost) return { error: 'Not enough credits' };
  await supabase.from('profiles').update({ credits: profile.credits - cost }).eq('id', userId);
  const user = await prisma.user.findUnique({ where: { id: userId } });
  await prisma.user.update({ where: { id: userId }, data: { balance: user!.balance - cost } });
  return { ok: true };
}
`),
    ignores: f('app/actions/credits.ts', `'use server';
export async function spendCredits(userId: string, cost: number) {
  const supabase = await createClient();
  const { data: profile } = await supabase.from('profiles').select('credits').eq('id', userId).single();
  if (!profile || profile.credits < cost) return { error: 'Not enough credits' };
  const { error } = await supabase.rpc('spend_credits', { p_user: userId, p_cost: cost });
  await prisma.user.update({ where: { id: userId, balance: { gte: cost } }, data: { balance: { decrement: cost } } });
  const user = await prisma.user.findUnique({ where: { id: userId } });
  await prisma.user.update({ where: { id: userId, balance: user!.balance }, data: { balance: user!.balance - cost } });
  return { ok: !error, preview: { credits: profile.credits - cost } };
}
`),
  },
  {
    ruleIds: [29667], name: 'BUG-67 .single() makes the not-found branch unreachable',
    detects: f('lib/profile.ts', `export async function getOrCreateProfile(supabase: SupabaseClient, userId: string) {
  const { data: profile, error } = await supabase.from('profiles').select('*').eq('user_id', userId).single();
  if (error) throw error;
  if (!profile) {
    const { data } = await supabase.from('profiles').insert({ user_id: userId }).select().single();
    return data;
  }
  return profile;
}
`),
    ignores: f('lib/profile.ts', `export async function getOrCreateProfile(supabase: SupabaseClient, userId: string) {
  const { data: profile, error } = await supabase.from('profiles').select('*').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  if (!profile) {
    return supabase.from('profiles').insert({ user_id: userId }).select().single();
  }
  return profile;
}
export async function getProject(supabase: SupabaseClient, id: string) {
  const { data: project, error } = await supabase.from('projects').select('*').eq('id', id).single();
  if (error) throw error;
  if (!project) throw new Error('Project not found');
  return project;
}
`),
  },
  {
    ruleIds: [29668], name: 'BUG-68 Supabase insert error dropped, data used',
    detects: f('app/actions/orders.ts', `'use server';
export async function createOrder(items: Item[]) {
  const supabase = await createClient();
  const { data: order } = await supabase.from('orders').insert({ items, status: 'pending' }).select().single();
  return { success: true, orderId: order.id };
}
`),
    ignores: f('app/actions/orders.ts', `'use server';
export async function createOrder(items: Item[]) {
  const supabase = await createClient();
  const { data: order, error } = await supabase.from('orders').insert({ items, status: 'pending' }).select().single();
  if (error) return { success: false, error: error.message };
  const { data: log } = await supabase.from('order_logs').insert({ order_id: order.id }).select().single();
  if (!log) console.warn('log not written');
  return { success: true, orderId: order.id };
}
`),
  },
  {
    ruleIds: [29669], name: 'BUG-69 dollars * 100 not rounded for Stripe',
    detects: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const { price, name } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ quantity: 1, price_data: { currency: 'usd', product_data: { name }, unit_amount: parseFloat(price) * 100 } }],
    success_url: 'https://acme.dev/ok',
  });
  return Response.json({ url: session.url });
}
`),
    ignores: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const { price, name, seats } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ quantity: 1, price_data: { currency: 'usd', product_data: { name }, unit_amount: Math.round(parseFloat(price) * 100) } }],
    metadata: { amount: seats * 100 },
    success_url: 'https://acme.dev/ok',
  });
  return Response.json({ url: session.url });
}
`),
  },
  {
    ruleIds: [29670], name: 'BUG-70 rounded to whole dollars before cents',
    detects: f('lib/stripe/charge.ts', `import { stripe } from './client';
export async function chargeOrder(order: { total: number; customerId: string }) {
  return stripe.paymentIntents.create({
    amount: Math.round(order.total) * 100,
    currency: 'usd',
    customer: order.customerId,
  });
}
`),
    ignores: f('lib/stripe/charge.ts', `import { stripe } from './client';
export async function chargeOrder(order: { total: number; customerId: string }) {
  return stripe.paymentIntents.create({
    amount: Math.round(order.total * 100),
    currency: 'usd',
    customer: order.customerId,
  });
}
`),
  },
  {
    ruleIds: [29671], name: 'BUG-71 toFixed string + number',
    detects: f('components/cart-summary.tsx', `export function CartSummary({ subtotal, shipping }: { subtotal: number; shipping: number }) {
  const total = subtotal.toFixed(2) + shipping;
  return <p>Total: {total}</p>;
}
`),
    ignores: f('components/cart-summary.tsx', `export function CartSummary({ subtotal, shipping }: { subtotal: number; shipping: number }) {
  const total = (subtotal + shipping).toFixed(2);
  const label = '$' + subtotal.toFixed(2) + ' USD';
  return <p>Total: {total} {label}</p>;
}
`),
  },
  {
    ruleIds: [29672], name: 'BUG-72 input string + number literal',
    detects: f('components/pager.tsx', `'use client';
import { useSearchParams, useRouter } from 'next/navigation';
export function Pager() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const next = () => router.push(\`?page=\${(searchParams.get('page') || 1) + 1}\`);
  return <input type="number" onChange={(e) => setQty(e.target.value + 1)} onBlur={next} />;
}
`),
    ignores: f('components/pager.tsx', `'use client';
import { useSearchParams, useRouter } from 'next/navigation';
export function Pager() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const next = () => router.push(\`?page=\${Number(searchParams.get('page') || 1) + 1}\`);
  const label = searchParams.get('q') + ' results';
  return <input type="number" onChange={(e) => setQty(+e.target.value + 1)} onBlur={next} title={label} />;
}
`),
  },
  {
    ruleIds: [29673], name: 'BUG-73 checkout.session.completed fulfilled without payment_status',
    detects: f('app/api/webhooks/stripe/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!);
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      await prisma.order.update({ where: { id: session.metadata!.orderId }, data: { status: 'paid' } });
      break;
    }
    case 'invoice.paid':
      break;
  }
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/stripe/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!);
  switch (event.type) {
    case 'checkout.session.completed':
    case 'checkout.session.async_payment_succeeded': {
      const session = event.data.object as Stripe.Checkout.Session;
      if (session.payment_status !== 'paid') break;
      await prisma.order.update({ where: { id: session.metadata!.orderId }, data: { status: 'paid' } });
      break;
    }
  }
  return new Response('ok');
}
`),
  },
  {
    ruleIds: [29674], name: 'BUG-74 subscription.created grants access regardless of status',
    detects: f('app/api/webhooks/stripe/route.ts', `import Stripe from 'stripe';
export async function POST(req: Request) {
  const event = await verify(req);
  switch (event.type) {
    case 'customer.subscription.created': {
      const sub = event.data.object as Stripe.Subscription;
      await supabase.from('profiles').update({ is_pro: true, stripe_subscription_id: sub.id }).eq('stripe_customer_id', sub.customer);
      break;
    }
  }
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/stripe/route.ts', `import Stripe from 'stripe';
export async function POST(req: Request) {
  const event = await verify(req);
  switch (event.type) {
    case 'customer.subscription.created': {
      const sub = event.data.object as Stripe.Subscription;
      const active = ['active', 'trialing'].includes(sub.status);
      await supabase.from('profiles').update({ is_pro: active, subscription_status: sub.status }).eq('stripe_customer_id', sub.customer);
      break;
    }
  }
  return new Response('ok');
}
`),
  },
  {
    ruleIds: [29675], name: 'BUG-75 Stripe seconds used as milliseconds',
    detects: f('lib/stripe/sync.ts', `import Stripe from 'stripe';
export async function syncSubscription(stripe: Stripe, id: string) {
  const subscription = await stripe.subscriptions.retrieve(id);
  const renewsAt = new Date(subscription.current_period_end);
  const expired = subscription.current_period_end < Date.now();
  return { renewsAt, expired };
}
`),
    ignores: f('lib/stripe/sync.ts', `import Stripe from 'stripe';
export async function syncSubscription(stripe: Stripe, id: string, row: { current_period_end: string }) {
  const subscription = await stripe.subscriptions.retrieve(id);
  const renewsAt = new Date(subscription.current_period_end * 1000);
  const expired = subscription.current_period_end * 1000 < Date.now();
  const stored = new Date(row.current_period_end);
  return { renewsAt, expired, stored };
}
`),
  },
  {
    ruleIds: [29676], name: 'BUG-76 date-only string shown with local getters',
    detects: f('components/booking-form.tsx', `'use client';
import { useState } from 'react';
export function BookingForm() {
  const [label, setLabel] = useState('');
  return <input type="date" onChange={(e) => {
    const day = new Date(e.target.value);
    setLabel(day.toLocaleDateString());
  }} />;
}
`),
    ignores: f('components/booking-form.tsx', `'use client';
import { useState } from 'react';
export function BookingForm() {
  const [label, setLabel] = useState('');
  return <input type="date" onChange={(e) => {
    const [y, m, d] = e.target.value.split('-').map(Number);
    const day = new Date(y, m - 1, d);
    setLabel(day.toLocaleDateString());
    console.log(new Date(e.target.value).toLocaleDateString(undefined, { timeZone: 'UTC' }));
  }} />;
}
`),
  },
  {
    ruleIds: [29677], name: 'BUG-77 getMonth() used as 1-12',
    detects: f('lib/format.ts', `export function formatDate(d: Date) {
  return \`\${d.getDate()}/\${d.getMonth()}/\${d.getFullYear()}\`;
}
`),
    ignores: f('lib/format.ts', `export function formatDate(d: Date) {
  return \`\${d.getDate()}/\${d.getMonth() + 1}/\${d.getFullYear()}\`;
}
export const nextMonth = (d: Date) => new Date(d.getFullYear(), d.getMonth() + 1, 1);
`),
  },
  {
    ruleIds: [29678], name: 'BUG-78 getDay() as day of month',
    detects: f('lib/format.ts', `export function shortDate(date: Date) {
  return date.getDay() + '/' + (date.getMonth() + 1) + '/' + date.getFullYear();
}
`),
    ignores: f('lib/format.ts', `const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
export function shortDate(date: Date) {
  return DAYS[date.getDay()] + ' ' + date.getDate() + '/' + (date.getMonth() + 1) + '/' + date.getFullYear();
}
`),
  },
  {
    ruleIds: [29679], name: 'BUG-79 Date objects compared with ===',
    detects: f('lib/schedule.ts', `export function isToday(value: string) {
  const day = new Date(value);
  const today = new Date();
  day.setHours(0, 0, 0, 0);
  today.setHours(0, 0, 0, 0);
  return day === today;
}
`),
    ignores: f('lib/schedule.ts', `export function isToday(value: string) {
  const day = new Date(value);
  const today = new Date();
  day.setHours(0, 0, 0, 0);
  today.setHours(0, 0, 0, 0);
  return day.getTime() === today.getTime() && new Date(value).getTime() !== new Date(0).getTime();
}
`),
  },
  {
    ruleIds: [29680], name: 'BUG-80 toISOString() as local today in the browser',
    detects: f('components/due-date.tsx', `'use client';
import { useState } from 'react';
export function DueDate() {
  const [date, setDate] = useState(new Date().toISOString().split('T')[0]);
  return <input type="date" value={date} onChange={(e) => setDate(e.target.value)} />;
}
`),
    ignores: f('components/due-date.tsx', `'use client';
import { useState } from 'react';
import { format } from 'date-fns';
export function DueDate() {
  const [date, setDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const exportName = \`report-\${new Date().toISOString().slice(0, 10)}.csv\`;
  return <input type="date" value={date} title={exportName} onChange={(e) => setDate(e.target.value)} />;
}
`),
  },
  {
    ruleIds: [29681], name: 'BUG-81 Date mutated through setDate inside new Date()',
    detects: f('lib/range.ts', `export function nextDayRange() {
  const today = new Date();
  const tomorrow = new Date(today.setDate(today.getDate() + 1));
  return { from: today, to: tomorrow };
}
`),
    ignores: f('lib/range.ts', `export function nextDayRange() {
  const today = new Date();
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  return { from: today, to: tomorrow };
}
`),
  },
  {
    ruleIds: [29682], name: 'BUG-82 getUser() user used without null check',
    detects: f('app/dashboard/page.tsx', `import { createClient } from '@/lib/supabase/server';
export default async function Dashboard() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  const { data: projects } = await supabase.from('projects').select('*').eq('owner_id', user!.id);
  return <ul>{projects?.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
`),
    ignores: f('app/dashboard/page.tsx', `import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
export default async function Dashboard() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login');
  const { data: projects } = await supabase.from('projects').select('*').eq('owner_id', user.id);
  return <ul>{projects?.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29683], name: 'BUG-83 email stored lowercased, looked up raw',
    detects: f('app/actions/auth.ts', `'use server';
export async function signUp(formData: FormData) {
  const email = String(formData.get('email'));
  await prisma.user.create({ data: { email: email.toLowerCase(), name: String(formData.get('name')) } });
}
export async function requestReset(formData: FormData) {
  const email = String(formData.get('email'));
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return { error: 'No account with that email' };
  await sendResetLink(user);
}
`),
    ignores: f('app/actions/auth.ts', `'use server';
const normalize = (v: FormDataEntryValue | null) => String(v).trim().toLowerCase();
export async function signUp(formData: FormData) {
  const email = normalize(formData.get('email'));
  await prisma.user.create({ data: { email: email.toLowerCase(), name: String(formData.get('name')) } });
}
export async function requestReset(formData: FormData) {
  const email = String(formData.get('email')).toLowerCase();
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return { error: 'No account with that email' };
  await sendResetLink(user);
}
`),
  },
  {
    ruleIds: [29684], name: 'BUG-84 numeric array default sort',
    detects: f('lib/pricing.ts', `export function cheapestPlan(plans: { price: number }[]) {
  const prices = plans.map((p) => p.price);
  prices.sort();
  return prices[0];
}
export const median = (rows: { score: number }[]) => rows.map((r) => r.score).sort()[Math.floor(rows.length / 2)];
`),
    ignores: f('lib/pricing.ts', `export function cheapestPlan(plans: { price: number; name: string }[]) {
  const prices = plans.map((p) => p.price);
  prices.sort((a, b) => a - b);
  const names = plans.map((p) => p.name).sort();
  return { min: prices[0], names };
}
`),
  },
  {
    ruleIds: [29685], name: 'BUG-85 comparison with [] / {} literal',
    detects: f('components/cart.tsx', `export function Cart({ items, selected, item }: Props) {
  if (items === []) return <p>Your cart is empty</p>;
  const isSelected = selected.includes({ id: item.id });
  return <List items={items} active={isSelected} />;
}
`),
    ignores: f('components/cart.tsx', `export function Cart({ items, selected, item }: Props) {
  if (items.length === 0) return <p>Your cart is empty</p>;
  const isSelected = selected.some((s) => s.id === item.id);
  const opts: Record<string, string> = {};
  return <List items={items} active={isSelected} opts={opts} />;
}
`),
  },
  {
    ruleIds: [29686], name: "BUG-86 typeof compared with 'array'",
    detects: f('lib/normalize.ts', `export function toList(value: unknown) {
  if (typeof value === 'array') return value;
  return [value];
}
`),
    ignores: f('lib/normalize.ts', `export function toList(value: unknown) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'object' || typeof value === 'undefined') return [];
  return [value];
}
`),
  },
  {
    ruleIds: [29687], name: 'BUG-87 assignment inside if condition',
    detects: f('app/api/posts/[id]/route.ts', `export async function DELETE(req: Request) {
  const user = await getUser(req);
  if (user.role = 'admin') {
    await db.post.deleteMany();
  }
  return new Response('ok');
}
`),
    ignores: f('app/api/posts/[id]/route.ts', `export async function DELETE(req: Request) {
  const user = await getUser(req);
  let m;
  if (user.role === 'admin') {
    await db.post.deleteMany();
  }
  if ((m = /x/.exec(req.url))) console.log(m);
  return new Response('ok');
}
`),
  },
  {
    ruleIds: [29688], name: 'BUG-88 Math.round(x * 100 / 100)',
    detects: f('lib/money.ts', `export const roundMoney = (value: number) => Math.round(value * 100 / 100);
`),
    ignores: f('lib/money.ts', `export const roundMoney = (value: number) => Math.round(value * 100) / 100;
`),
  },
  {
    ruleIds: [29689], name: 'BUG-89 delete and insert on the same table in Promise.all',
    detects: f('app/actions/tags.ts', `'use server';
export async function replaceTags(postId: string, tags: string[]) {
  const supabase = await createClient();
  await Promise.all([
    supabase.from('post_tags').delete().eq('post_id', postId),
    supabase.from('post_tags').insert(tags.map((tag) => ({ post_id: postId, tag }))),
  ]);
}
`),
    ignores: f('app/actions/tags.ts', `'use server';
export async function replaceTags(postId: string, tags: string[]) {
  const supabase = await createClient();
  await supabase.from('post_tags').delete().eq('post_id', postId);
  await Promise.all([
    supabase.from('post_tags').insert(tags.map((tag) => ({ post_id: postId, tag }))),
    supabase.from('audit').delete().eq('post_id', postId),
  ]);
}
`),
  },
  {
    ruleIds: [29690], name: 'BUG-90 response.json() not awaited',
    detects: f('lib/weather.ts', `export async function getForecast(city: string) {
  const res = await fetch(\`https://api.example.com/forecast?city=\${city}\`);
  const data = res.json();
  return { temp: data.main.temp, city };
}
`),
    ignores: f('lib/weather.ts', `export async function getForecast(city: string) {
  const res = await fetch(\`https://api.example.com/forecast?city=\${city}\`);
  const data = await res.json();
  return { temp: data.main.temp, city };
}
`),
  },
  {
    ruleIds: [29691], name: 'BUG-91 Python mutable default argument mutated',
    detects: f('app/services/cart.py', `def add_item(item, cart=[]):
    cart.append(item)
    return cart
`),
    ignores: f('app/services/cart.py', `def add_item(item, cart=None):
    cart = [] if cart is None else cart
    cart.append(item)
    return cart


def total(items, discounts={}):
    return sum(i.price - discounts.get(i.id, 0) for i in items)
`),
  },
  {
    ruleIds: [29692], name: 'BUG-92 Python is with a literal',
    detects: f('app/api/orders.py', `def can_ship(order):
    if order.status is "paid":
        return True
    return False
`),
    ignores: f('app/api/orders.py', `def can_ship(order):
    """Return True if the status is 'paid'."""
    if order.status == "paid" and order.shipped_at is None:
        return True
    return False
`),
  },
  {
    ruleIds: [29693], name: 'BUG-93 Python utcnow().timestamp()',
    detects: f('app/core/tokens.py', `from datetime import datetime, timedelta


def expiry():
    return int((datetime.utcnow() + timedelta(hours=1)).timestamp())


def issued_at():
    return datetime.utcnow().timestamp()
`),
    ignores: f('app/core/tokens.py', `from datetime import datetime, timedelta, timezone


def issued_at():
    return datetime.now(timezone.utc).timestamp()
`),
  },
];
