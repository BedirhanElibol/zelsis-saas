import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29601], name: 'BUG-01 Supabase / Prisma write never awaited',
    detects: f('app/actions/log.ts', `'use server';
export async function logVisit(path: string) {
  const supabase = await createClient();
  supabase.from('visits').insert({ path });
  prisma.audit.create({ data: { path } });
  return { ok: true };
}
`),
    ignores: f('app/actions/log.ts', `'use server';
export async function logVisit(path: string) {
  const supabase = await createClient();
  const { error } = await supabase.from('visits').insert({ path });
  supabase.from('visits').update({ seen: true }).eq('path', path).then(() => {});
  await prisma.$transaction([
    // keep the audit row
    prisma.audit.create({ data: { path } }),
  ]);
  return { ok: !error };
}
`),
  },
  {
    ruleIds: [29602], name: 'BUG-02 redirect() swallowed by catch',
    detects: f('app/actions/login.ts', `'use server';
import { redirect } from 'next/navigation';
export async function login(formData: FormData) {
  try {
    await signIn(formData);
    redirect('/dashboard');
  } catch (e) {
    return { error: 'Login failed' };
  }
}
`),
    ignores: f('app/actions/login.ts', `'use server';
import { redirect, unstable_rethrow } from 'next/navigation';
export async function login(formData: FormData) {
  try {
    await signIn(formData);
    redirect('/dashboard');
  } catch (e) {
    unstable_rethrow(e);
    return { error: 'Login failed' };
  }
}
`),
  },
  {
    ruleIds: [29603], name: 'BUG-03 async function passed to useEffect',
    detects: f('components/profile.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Profile() {
  const [p, setP] = useState(null);
  useEffect(async () => { setP(await (await fetch('/api/me')).json()); }, []);
  return <pre>{JSON.stringify(p)}</pre>;
}
`),
    ignores: f('components/profile.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Profile() {
  const [p, setP] = useState(null);
  useEffect(() => { (async () => setP(await (await fetch('/api/me')).json()))(); }, []);
  return <pre>{JSON.stringify(p)}</pre>;
}
`),
  },
  {
    ruleIds: [29604], name: 'BUG-04 effect without deps sets state',
    detects: f('components/items.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Items() {
  const [items, setItems] = useState<string[]>([]);
  useEffect(() => { fetch('/api/items').then((r) => r.json()).then(setItems); });
  return <ul>{items.map((i) => <li key={i}>{i}</li>)}</ul>;
}
`),
    ignores: f('components/items.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Items() {
  const [items, setItems] = useState<string[]>([]);
  useEffect(() => { fetch('/api/items').then((r) => r.json()).then(setItems); }, []);
  useEffect(() => { document.title = String(items.length); });
  return <ul>{items.map((i) => <li key={i}>{i}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29605], name: 'BUG-05 setInterval in effect without cleanup',
    detects: f('components/clock.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Clock() {
  const [t, setT] = useState(Date.now());
  useEffect(() => { setInterval(() => setT(Date.now()), 1000); }, []);
  return <span>{t}</span>;
}
`),
    ignores: f('components/clock.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Clock() {
  const [t, setT] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setT(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{t}</span>;
}
`),
  },
  {
    ruleIds: [29606], name: 'BUG-06 async callback in forEach',
    detects: f('app/api/import/route.ts', `export async function POST(req: Request) {
  const { rows } = await req.json();
  rows.forEach(async (row: { id: string }) => { await db.insert(items).values(row); });
  return Response.json({ imported: rows.length });
}
`),
    ignores: f('app/api/import/route.ts', `export async function POST(req: Request) {
  const { rows } = await req.json();
  await Promise.all(rows.map(async (row: { id: string }) => db.insert(items).values(row)));
  rows.forEach((row: { id: string }) => console.log(row.id));
  return Response.json({ imported: rows.length });
}
`),
  },
  {
    ruleIds: [29607], name: 'BUG-07 Supabase range end off by one',
    detects: f('app/posts/page.tsx', `export default async function Posts() {
  const page = 2, pageSize = 20;
  const { data } = await supabase.from('posts').select('*').range(page * pageSize, (page + 1) * pageSize);
  return <ul>{data?.map((p) => <li key={p.id}>{p.title}</li>)}</ul>;
}
`),
    ignores: f('app/posts/page.tsx', `export default async function Posts() {
  const page = 2, pageSize = 20;
  const { data } = await supabase.from('posts').select('*').range(page * pageSize, (page + 1) * pageSize - 1);
  const { data: top } = await supabase.from('posts').select('*').range(0, 9);
  return <ul>{data?.concat(top ?? []).map((p) => <li key={p.id}>{p.title}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29608], name: 'BUG-08 comparison with NaN',
    detects: f('lib/parse.ts', `export function parseQty(v: string) {
  const n = Number(v);
  if (n === NaN) throw new Error('bad qty');
  return n;
}
`),
    ignores: f('lib/parse.ts', `export function parseQty(v: string) {
  const n = Number(v);
  if (Number.isNaN(n)) throw new Error('bad qty');
  return n;
}
`),
  },
  {
    ruleIds: [29609], name: 'BUG-09 state array sorted in place',
    detects: f('components/table.tsx', `'use client';
import { useState } from 'react';
export function Table({ initial }: { initial: { name: string }[] }) {
  const [rows, setRows] = useState(initial);
  const sortByName = () => setRows(rows.sort((a, b) => a.name.localeCompare(b.name)));
  return <button type="button" onClick={sortByName}>Sort</button>;
}
`),
    ignores: f('components/table.tsx', `'use client';
import { useState } from 'react';
export function Table({ initial }: { initial: { name: string }[] }) {
  const [rows, setRows] = useState(initial);
  const sortByName = () => setRows([...rows].sort((a, b) => a.name.localeCompare(b.name)));
  return <button type="button" onClick={sortByName}>Sort</button>;
}
`),
  },
  {
    ruleIds: [29610], name: 'BUG-10 Stripe amount in dollars',
    detects: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const PRICE_USD = 19.99;
export async function POST() {
  const session = await stripe.checkout.sessions.create({ mode: 'payment',
    line_items: [{ price_data: { currency: 'usd', unit_amount: PRICE_USD, product_data: { name: 'Pro' } }, quantity: 1 }],
    success_url: 'https://x.com', cancel_url: 'https://x.com' });
  return Response.json({ url: session.url });
}
`),
    ignores: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const PRICE_CENTS = 1999;
export async function POST() {
  const session = await stripe.checkout.sessions.create({ mode: 'payment',
    line_items: [{ price_data: { currency: 'usd', unit_amount: PRICE_CENTS, product_data: { name: 'Pro' } }, quantity: 1 }],
    success_url: 'https://x.com', cancel_url: 'https://x.com' });
  return Response.json({ url: session.url });
}
`),
  },
  {
    ruleIds: [29611], name: 'BUG-11 localStorage read at module load',
    detects: f('components/theme.tsx', `'use client';
const saved = localStorage.getItem('theme');
export function Theme() { return <div data-theme={saved ?? 'light'} />; }
`),
    ignores: f('components/theme.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Theme() {
  const [saved, setSaved] = useState<string | null>(null);
  useEffect(() => { setSaved(localStorage.getItem('theme')); }, []);
  return <div data-theme={saved ?? 'light'} />;
}
`),
  },
  {
    ruleIds: [29613], name: 'BUG-13 error swallowed then success shown',
    detects: f('components/save.tsx', `'use client';
export function Save({ data }: { data: unknown }) {
  async function save() {
    try { await fetch('/api/save', { method: 'POST', body: JSON.stringify(data) }); } catch {}
    alert('Saved!');
  }
  return <button type="button" onClick={save}>Save</button>;
}
`),
    ignores: f('components/save.tsx', `'use client';
export function Save({ data }: { data: unknown }) {
  async function save() {
    try { await fetch('/api/save', { method: 'POST', body: JSON.stringify(data) }); alert('Saved!'); }
    catch { alert('Could not save'); }
  }
  return <button type="button" onClick={save}>Save</button>;
}
`),
  },
  {
    ruleIds: [29614], name: 'BUG-14 INSERT policy with USING',
    detects: f('supabase/migrations/20250101_posts.sql', `create policy "insert own posts" on public.posts for insert to authenticated using (auth.uid() = user_id);
`),
    ignores: f('supabase/migrations/20250101_posts.sql', `create policy "insert own posts" on public.posts for insert to authenticated with check (auth.uid() = user_id);
create policy "read own posts" on public.posts for select using (auth.uid() = user_id);
`),
  },
  {
    ruleIds: [29615], name: 'BUG-15 signup trigger function without security definer',
    detects: f('supabase/migrations/20250101_profiles.sql', `create function public.handle_new_user() returns trigger language plpgsql as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end; $$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
`),
    ignores: f('supabase/migrations/20250101_profiles.sql', `create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end; $$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
`),
  },
  {
    ruleIds: [29616], name: 'BUG-16 policy compares auth.uid() with the generated row id',
    detects: f('supabase/migrations/20250101_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text
);
create policy "own notes" on public.notes for select using (auth.uid() = id);
`),
    ignores: f('supabase/migrations/20250101_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text
);
create table public.profiles (id uuid primary key references auth.users on delete cascade, name text);
create policy "own notes" on public.notes for select using (auth.uid() = user_id);
create policy "own profile" on public.profiles for select using (auth.uid() = id);
`),
  },
  {
    ruleIds: [29617], name: 'BUG-17 FK to auth.users without on delete',
    detects: f('supabase/migrations/20250101_orders.sql', `create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total int
);
`),
    ignores: f('supabase/migrations/20250101_orders.sql', `create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  total int
);
`),
  },
  {
    ruleIds: [29618], name: 'BUG-18 Express response without return',
    detects: f('src/routes/users.js', `app.post('/users', async (req, res) => {
  if (!req.body.email) {
    res.status(400).json({ error: 'email required' });
  }
  const user = await db.users.create(req.body);
  res.status(201).json(user);
});
`),
    ignores: f('src/routes/users.js', `app.post('/users', async (req, res) => {
  if (!req.body.email) {
    return res.status(400).json({ error: 'email required' });
  }
  const user = await db.users.create(req.body);
  res.status(201).json(user);
});
app.get('/health', (req, res) => {
  if (req.query.verbose) {
    res.json({ ok: true, uptime: process.uptime() });
  } else {
    res.json({ ok: true });
  }
});
`),
  },
  {
    ruleIds: [29619], name: 'BUG-19 route handler response not returned',
    detects: f('app/api/items/route.ts', `import { NextResponse } from 'next/server';
export async function POST(req: Request) {
  const body = await req.json();
  if (!body.name) {
    NextResponse.json({ error: 'name required' }, { status: 400 });
  }
  return NextResponse.json(await create(body.name));
}
`),
    ignores: f('app/api/items/route.ts', `import { NextResponse } from 'next/server';
export async function POST(req: Request) {
  const body = await req.json();
  if (!body.name) {
    return NextResponse.json({ error: 'name required' }, { status: 400 });
  }
  const res = NextResponse.json(await create(body.name));
  return res;
}
`),
  },
];
