import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29820], name: 'BUG-149 transaction callback writes through the outer client',
    detects: f('lib/orders.ts', `import { prisma } from './db';
export async function placeOrder(userId: string, total: number) {
  await prisma.$transaction(async (tx) => {
    const order = await tx.order.create({ data: { userId, total } });
    await prisma.wallet.update({ where: { userId }, data: { balance: { decrement: total } } });
    return order;
  });
}
`),
    ignores: f('lib/orders.ts', `import { prisma } from './db';
export async function placeOrder(userId: string, total: number) {
  await prisma.$transaction(async (tx) => {
    const order = await tx.order.create({ data: { userId, total } });
    await tx.wallet.update({ where: { userId }, data: { balance: { decrement: total } } });
    return order;
  });
}
`),
  },
  {
    ruleIds: [29821], name: 'BUG-150 useActionState action takes only formData',
    detects: f('components/signup.tsx', `'use client';
import { useActionState } from 'react';
async function signup(formData: FormData) {
  const email = formData.get('email');
  return { ok: !!email };
}
export function Signup() {
  const [state, action] = useActionState(signup, { ok: false });
  return <form action={action}><input name="email" />{String(state.ok)}</form>;
}
`),
    ignores: f('components/signup.tsx', `'use client';
import { useActionState } from 'react';
async function signup(prev: { ok: boolean }, formData: FormData) {
  const email = formData.get('email');
  return { ok: !!email };
}
export function Signup() {
  const [state, action] = useActionState(signup, { ok: false });
  return <form action={action}><input name="email" />{String(state.ok)}</form>;
}
`),
  },
  {
    ruleIds: [29822], name: 'BUG-151 fetch catch expects err.response.status',
    detects: f('lib/api.ts', `export async function loadUser(id: string) {
  try {
    const res = await fetch('/api/users/' + id);
    return await res.json();
  } catch (err: any) {
    if (err.response?.status === 404) return null;
    throw err;
  }
}
`),
    ignores: f('lib/api.ts', `export async function loadUser(id: string) {
  const res = await fetch('/api/users/' + id);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('failed ' + res.status);
  return res.json();
}
`),
  },
  {
    ruleIds: [29823], name: 'BUG-152 forEach with a named async function',
    detects: f('lib/billing.ts', `async function chargeItem(item: { id: string }) {
  await fetch('/charge/' + item.id, { method: 'POST' });
}
export function chargeAll(items: { id: string }[]) {
  items.forEach(chargeItem);
  return 'done';
}
`),
    ignores: f('lib/billing.ts', `async function chargeItem(item: { id: string }) {
  await fetch('/charge/' + item.id, { method: 'POST' });
}
function logItem(item: { id: string }) { console.log(item.id); }
export async function chargeAll(items: { id: string }[]) {
  items.forEach(logItem);
  await Promise.all(items.map(chargeItem));
}
`),
  },
  {
    ruleIds: [29824], name: 'BUG-153 Array.fill with a shared object',
    detects: f('lib/grid.ts', `export function makeGrid(rows: number) {
  const grid = new Array(rows).fill([]);
  grid[0].push(1);
  return grid;
}
`),
    ignores: f('lib/grid.ts', `export function makeGrid(rows: number) {
  const grid = Array.from({ length: rows }, () => []);
  const zeros = new Array(rows).fill(0);
  return { grid, zeros };
}
`),
  },
  {
    ruleIds: [29825], name: 'BUG-154 route handler destructures params from the request',
    detects: f('app/api/posts/[id]/route.ts', `export async function GET({ params }: { params: { id: string } }) {
  return Response.json({ id: params.id });
}
`),
    ignores: f('app/api/posts/[id]/route.ts', `export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return Response.json({ id });
}
`),
  },
  {
    ruleIds: [29826], name: 'BUG-155 useSearchParams result mutated',
    detects: f('components/filters.tsx', `'use client';
import { useRouter, useSearchParams } from 'next/navigation';
export function Filters() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pick = (v: string) => { searchParams.set('status', v); router.push('?' + searchParams.toString()); };
  return <button onClick={() => pick('open')}>Open</button>;
}
`),
    ignores: f('components/filters.tsx', `'use client';
import { useRouter, useSearchParams } from 'next/navigation';
export function Filters() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pick = (v: string) => { const p = new URLSearchParams(searchParams.toString()); p.set('status', v); router.push('?' + p); };
  return <button onClick={() => pick('open')}>Open</button>;
}
`),
  },
  {
    ruleIds: [29827], name: 'BUG-156 in operator on an array of values',
    detects: f('lib/roles.ts', `export function canEdit(user: { role: string }) {
  if (user.role in ['admin', 'owner']) return true;
  return false;
}
`),
    ignores: f('lib/roles.ts', `export function canEdit(user: { role: string }) {
  if (['admin', 'owner'].includes(user.role)) return true;
  if ('role' in user) return false;
  return false;
}
`),
  },
  {
    ruleIds: [29828], name: 'BUG-157 1-based page multiplied without -1',
    detects: f('app/api/items/route.ts', `import { prisma } from '@/lib/db';
export async function GET(req: Request) {
  const url = new URL(req.url);
  const page = Number(url.searchParams.get('page')) || 1;
  const pageSize = 20;
  const items = await prisma.item.findMany({ skip: page * pageSize, take: pageSize });
  return Response.json(items);
}
`),
    ignores: f('app/api/items/route.ts', `import { prisma } from '@/lib/db';
export async function GET(req: Request) {
  const url = new URL(req.url);
  const page = Number(url.searchParams.get('page')) || 1;
  const pageSize = 20;
  const items = await prisma.item.findMany({ skip: (page - 1) * pageSize, take: pageSize });
  return Response.json(items);
}
`),
  },
  {
    ruleIds: [29829], name: 'BUG-158 redirect with a relative path',
    detects: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function middleware(req: NextRequest) {
  if (!req.cookies.get('session')) return NextResponse.redirect('/login');
  return NextResponse.next();
}
`),
    ignores: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function middleware(req: NextRequest) {
  if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
`),
  },
  {
    ruleIds: [29831], name: 'BUG-160 res.text() after res.json() in catch',
    detects: f('lib/client.ts', `export async function call(url: string) {
  const res = await fetch(url);
  try {
    return await res.json();
  } catch {
    const body = await res.text();
    throw new Error(body);
  }
}
`),
    ignores: f('lib/client.ts', `export async function call(url: string) {
  const res = await fetch(url);
  const raw = await res.text();
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(raw);
  }
}
`),
  },
  {
    ruleIds: [29832], name: 'BUG-161 replaceAll with a non-global regex',
    detects: f('lib/slug.ts', `export const slug = (s: string) => s.toLowerCase().replaceAll(/\\s+/, '-');
`),
    ignores: f('lib/slug.ts', `export const slug = (s: string) => s.toLowerCase().replaceAll(/\\s+/g, '-').replaceAll(' ', '-');
`),
  },
  {
    ruleIds: [29833], name: 'BUG-162 Drizzle update without where',
    detects: f('app/actions.ts', `'use server';
import { eq } from 'drizzle-orm';
import { db } from '@/db';
import { users } from '@/db/schema';
export async function deactivate(id: string) {
  await db.update(users).set({ active: false });
}
`),
    ignores: f('app/actions.ts', `'use server';
import { eq } from 'drizzle-orm';
import { db } from '@/db';
import { users } from '@/db/schema';
export async function deactivate(id: string) {
  await db.update(users).set({ active: false }).where(eq(users.id, id));
  await db.delete(users).where(eq(users.id, id));
}
`),
  },
  {
    ruleIds: [29834], name: 'BUG-163 includes with an array literal',
    detects: f('lib/seats.ts', `export function isTaken(taken: number[][], row: number, col: number) {
  return taken.includes([row, col]);
}
`),
    ignores: f('lib/seats.ts', `export function isTaken(taken: Set<string>, row: number, col: number) {
  return taken.has(\`\${row}:\${col}\`);
}
`),
  },
  {
    ruleIds: [29835], name: 'BUG-164 async Promise executor',
    detects: f('lib/wait.ts', `export function loadConfig(path: string) {
  return new Promise(async (resolve) => {
    const res = await fetch(path);
    resolve(await res.json());
  });
}
`),
    ignores: f('lib/wait.ts', `export async function loadConfig(path: string) {
  const res = await fetch(path);
  return res.json();
}
export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
`),
  },
  {
    ruleIds: [29836], name: 'BUG-165 relative fetch in a server component',
    detects: f('app/dashboard/page.tsx', `export default async function Dashboard() {
  const res = await fetch('/api/stats');
  const stats = await res.json();
  return <div>{stats.count}</div>;
}
`),
    ignores: f('app/dashboard/page.tsx', `import { getStats } from '@/lib/stats';
export default async function Dashboard() {
  const stats = await getStats();
  return <div>{stats.count}</div>;
}
`),
  },
  {
    ruleIds: [29837], name: 'BUG-166 Supabase eq with null',
    detects: f('lib/tasks.ts', `import { supabase } from './supabase';
export async function unassigned() {
  return supabase.from('tasks').select('*').eq('assignee_id', null);
}
`),
    ignores: f('lib/tasks.ts', `import { supabase } from './supabase';
export async function unassigned() {
  return supabase.from('tasks').select('*').is('assignee_id', null);
}
`),
  },
  {
    ruleIds: [29838], name: 'BUG-167 Python dict mutated while iterating',
    detects: f('app/cache.py', `def prune(cache, now):
    for key in cache:
        if cache[key] < now:
            del cache[key]
    return cache
`),
    ignores: f('app/cache.py', `def prune(cache, now):
    for key in list(cache):
        if cache[key] < now:
            del cache[key]
    return cache
`),
  },
  {
    ruleIds: [29839], name: 'BUG-168 strftime with %M as the month',
    detects: f('app/report.py', `from datetime import datetime
def stamp(d: datetime) -> str:
    return d.strftime("%Y-%M-%d")
`),
    ignores: f('app/report.py', `from datetime import datetime
def stamp(d: datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M")
`),
  },
  {
    ruleIds: [29840], name: 'BUG-169 parseFloat on toLocaleString output',
    detects: f('lib/total.ts', `export function addTax(total: number) {
  const shown = parseFloat(total.toLocaleString('en-US'));
  return shown * 1.2;
}
`),
    ignores: f('lib/total.ts', `export function addTax(total: number) {
  const withTax = total * 1.2;
  return withTax.toLocaleString('en-US');
}
`),
  },
  {
    ruleIds: [29841], name: 'BUG-170 async function in useMemo',
    detects: f('components/profile.tsx', `'use client';
import { useMemo } from 'react';
export function Profile({ id }: { id: string }) {
  const user = useMemo(async () => (await fetch('/api/u/' + id)).json(), [id]);
  return <div>{String(user)}</div>;
}
`),
    ignores: f('components/profile.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Profile({ id }: { id: string }) {
  const [user, setUser] = useState(null);
  useEffect(() => { fetch('/api/u/' + id).then((r) => r.json()).then(setUser); }, [id]);
  return <div>{String(user)}</div>;
}
`),
  },
  {
    ruleIds: [29842], name: 'BUG-171 while exec with a non-global regex',
    detects: f('lib/tags.ts', `export function tags(text: string) {
  const re = /#(\\w+)/;
  const out: string[] = [];
  let m;
  while ((m = re.exec(text))) out.push(m[1]);
  return out;
}
`),
    ignores: f('lib/tags.ts', `export function tags(text: string) {
  const re = /#(\\w+)/g;
  const out: string[] = [];
  let m;
  while ((m = re.exec(text))) out.push(m[1]);
  return out;
}
`),
  },
  {
    ruleIds: [29843], name: 'BUG-172 return inside finally',
    detects: f('lib/save.ts', `export async function save(data: unknown) {
  try {
    await fetch('/api/save', { method: 'POST', body: JSON.stringify(data) });
  } catch (e) {
    throw e;
  } finally {
    return true;
  }
}
`),
    ignores: f('lib/save.ts', `export async function save(data: unknown, done: () => void) {
  try {
    await fetch('/api/save', { method: 'POST', body: JSON.stringify(data) });
    return true;
  } finally {
    done();
  }
}
`),
  },
  {
    ruleIds: [29844], name: 'BUG-173 Promise.all with separate arguments',
    detects: f('lib/load.ts', `export async function load() {
  const [a, b] = await Promise.all(fetch('/a'), fetch('/b'));
  return { a, b };
}
`),
    ignores: f('lib/load.ts', `export async function load(ids: string[]) {
  const [a, b] = await Promise.all([fetch('/a'), fetch('/b')]);
  const all = await Promise.all(ids.map((id) => fetch('/x/' + id)));
  return { a, b, all };
}
`),
  },
  {
    ruleIds: [29845], name: 'BUG-174 plain object as Response body',
    detects: f('app/api/health/route.ts', `export async function GET() {
  return new Response({ ok: true }, { status: 200 });
}
`),
    ignores: f('app/api/health/route.ts', `export async function GET() {
  return Response.json({ ok: true }, { status: 200 });
}
`),
  },
  {
    ruleIds: [29846], name: 'BUG-175 plain object passed to new Map',
    detects: f('lib/labels.ts', `export const LABELS = new Map({ open: 'Open', done: 'Done' });
`),
    ignores: f('lib/labels.ts', `export const LABELS = new Map(Object.entries({ open: 'Open', done: 'Done' }));
export const KEYS = new Set(['open', 'done']);
`),
  },
  {
    ruleIds: [29847], name: 'BUG-176 route placeholder left in a link',
    detects: f('components/user-row.tsx', `import Link from 'next/link';
export function UserRow({ user }: { user: { id: string; name: string } }) {
  return <Link href="/users/[id]">{user.name}</Link>;
}
`),
    ignores: f('components/user-row.tsx', `import Link from 'next/link';
export function UserRow({ user }: { user: { id: string; name: string } }) {
  return <Link href={\`/users/\${user.id}\`}>{user.name}</Link>;
}
`),
  },
  {
    ruleIds: [29848], name: 'BUG-177 padStart arguments swapped',
    detects: f('lib/time.ts', `export const two = (n: number) => String(n).padStart('0', 2);
`),
    ignores: f('lib/time.ts', `export const two = (n: number) => String(n).padStart(2, '0');
`),
  },
  {
    ruleIds: [29849], name: 'BUG-178 timedelta.seconds as total duration',
    detects: f('app/tokens.py', `from datetime import datetime
def expired(created: datetime) -> bool:
    age = datetime.utcnow() - created
    return age.seconds > 3600
`),
    ignores: f('app/tokens.py', `from datetime import datetime
def expired(created: datetime) -> bool:
    age = datetime.utcnow() - created
    return age.total_seconds() > 3600
`),
  },
  {
    ruleIds: [29850], name: 'BUG-179 indexOf(NaN)',
    detects: f('lib/clean.ts', `export const hasBad = (xs: number[]) => xs.indexOf(NaN) !== -1;
`),
    ignores: f('lib/clean.ts', `export const hasBad = (xs: number[]) => xs.some(Number.isNaN);
`),
  },
  {
    ruleIds: [29851], name: 'BUG-180 new URL with a lone relative path',
    detects: f('lib/links.ts', `export function apiUrl(q: string) {
  const url = new URL('/api/search');
  url.searchParams.set('q', q);
  return url.toString();
}
`),
    ignores: f('lib/links.ts', `export function apiUrl(q: string, base: string) {
  const url = new URL('/api/search', base);
  url.searchParams.set('q', q);
  return url.toString();
}
`),
  },
  {
    ruleIds: [29852], name: 'BUG-181 AbortController never wired to fetch',
    detects: f('components/search.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Search({ q }: { q: string }) {
  const [data, setData] = useState(null);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/search?q=' + q).then((r) => r.json()).then(setData);
    return () => controller.abort();
  }, [q]);
  return <div>{String(data)}</div>;
}
`),
    ignores: f('components/search.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Search({ q }: { q: string }) {
  const [data, setData] = useState(null);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/search?q=' + q, { signal: controller.signal }).then((r) => r.json()).then(setData);
    return () => controller.abort();
  }, [q]);
  return <div>{String(data)}</div>;
}
`),
  },
  {
    ruleIds: [29853], name: 'BUG-182 map(parseInt)',
    detects: f('lib/ids.ts', `export const toIds = (raw: string) => raw.split(',').map(parseInt);
`),
    ignores: f('lib/ids.ts', `export const toIds = (raw: string) => raw.split(',').map((s) => parseInt(s, 10));
`),
  },
  {
    ruleIds: [29854], name: 'BUG-183 sort comparator returns boolean',
    detects: f('lib/rank.ts', `export const rank = (xs: { score: number }[]) => xs.sort((a, b) => a.score > b.score);
`),
    ignores: f('lib/rank.ts', `export const rank = (xs: { score: number }[]) => xs.sort((a, b) => b.score - a.score);
`),
  },
  {
    ruleIds: [29855], name: 'BUG-184 coroutine called without await',
    detects: f('app/jobs.py', `async def send_email(to: str) -> None:
    ...

async def on_signup(user) -> None:
    send_email(user.email)
    return None
`),
    ignores: f('app/jobs.py', `import asyncio

async def send_email(to: str) -> None:
    ...

async def on_signup(user) -> None:
    await send_email(user.email)
    asyncio.create_task(send_email(user.backup_email))
`),
  },
  {
    ruleIds: [29856], name: 'BUG-185 cents via Math.floor(amount * 100)',
    detects: f('lib/pay.ts', `export const toCents = (amount: number) => Math.floor(amount * 100);
`),
    ignores: f('lib/pay.ts', `export const toCents = (amount: number) => Math.round(amount * 100);
`),
  },
  {
    ruleIds: [29857], name: 'BUG-186 toFixed strings added',
    detects: f('lib/sum.ts', `export function sum(items: { price: number }[]) {
  let total: any = 0;
  for (const it of items) total += it.price.toFixed(2);
  return total;
}
`),
    ignores: f('lib/sum.ts', `export function sum(items: { price: number }[]) {
  let total = 0;
  for (const it of items) total += it.price;
  return total.toFixed(2);
}
`),
  },
  {
    ruleIds: [29858], name: 'BUG-187 Number.isNaN on a raw query string',
    detects: f('app/api/page/route.ts', `export async function GET(req: Request) {
  const searchParams = new URL(req.url).searchParams;
  if (Number.isNaN(searchParams.get('page'))) return new Response('bad', { status: 400 });
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/page/route.ts', `export async function GET(req: Request) {
  const searchParams = new URL(req.url).searchParams;
  if (Number.isNaN(Number(searchParams.get('page')))) return new Response('bad', { status: 400 });
  return Response.json({ ok: true });
}
`),
  },
  {
    ruleIds: [29859], name: 'BUG-188 second Set-Cookie set() overwrites the first',
    detects: f('app/api/login/route.ts', `export async function POST() {
  const headers = new Headers();
  headers.set('Set-Cookie', 'session=abc; HttpOnly');
  headers.set('Set-Cookie', 'csrf=xyz');
  return new Response(null, { status: 204, headers });
}
`),
    ignores: f('app/api/login/route.ts', `export async function POST() {
  const headers = new Headers();
  headers.append('Set-Cookie', 'session=abc; HttpOnly');
  headers.append('Set-Cookie', 'csrf=xyz');
  return new Response(null, { status: 204, headers });
}
`),
  },
  {
    ruleIds: [29860], name: 'BUG-189 FileList appended to FormData',
    detects: f('components/upload.tsx', `'use client';
export function Upload() {
  const send = async (input: HTMLInputElement) => {
    const fd = new FormData();
    fd.append('files', input.files);
    await fetch('/api/upload', { method: 'POST', body: fd });
  };
  return <input type="file" multiple onChange={(e) => send(e.currentTarget)} />;
}
`),
    ignores: f('components/upload.tsx', `'use client';
export function Upload() {
  const send = async (input: HTMLInputElement) => {
    const fd = new FormData();
    for (const file of Array.from(input.files ?? [])) fd.append('files', file);
    await fetch('/api/upload', { method: 'POST', body: fd });
  };
  return <input type="file" multiple onChange={(e) => send(e.currentTarget)} />;
}
`),
  },
];
