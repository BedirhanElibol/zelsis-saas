import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const NEXT16 = { path: 'package.json', content: '{ "dependencies": { "next": "16.0.0", "react": "19.2.0" } }' };

export const CASES: RuleCase[] = [
  {
    ruleIds: [29867], name: 'BUG-190 fetch body without a method',
    detects: f('lib/save.ts', `export async function save(data: unknown) {
  await fetch('/api/save', { body: JSON.stringify(data), headers: { 'Content-Type': 'application/json' } });
}
`),
    ignores: f('lib/save.ts', `export async function save(data: unknown) {
  await fetch('/api/save', { method: 'POST', body: JSON.stringify(data), headers: { 'Content-Type': 'application/json' } });
}
`),
  },
  {
    ruleIds: [29868], name: 'BUG-191 manual multipart Content-Type on FormData',
    detects: f('lib/upload.ts', `export async function upload(file: File) {
  const body = new FormData();
  body.append('file', file);
  await fetch('/api/upload', { method: 'POST', body, headers: { 'Content-Type': 'multipart/form-data' } });
}
`),
    ignores: f('lib/upload.ts', `export async function upload(file: File) {
  const body = new FormData();
  body.append('file', file);
  await fetch('/api/upload', { method: 'POST', body });
}
`),
  },
  {
    ruleIds: [29869], name: 'BUG-192 ref.current in a dependency array',
    detects: f('components/measure.tsx', `'use client';
import { useEffect, useRef } from 'react';
export function Measure() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { console.log(box.current?.offsetWidth); }, [box.current]);
  return <div ref={box} />;
}
`),
    ignores: f('components/measure.tsx', `'use client';
import { useEffect, useRef } from 'react';
export function Measure() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { console.log(box.current?.offsetWidth); }, []);
  return <div ref={box} />;
}
`),
  },
  {
    ruleIds: [29870], name: 'BUG-193 state array sorted in place',
    detects: f('components/list.tsx', `'use client';
import { useState } from 'react';
export function List({ initial }: { initial: number[] }) {
  const [items, setItems] = useState(initial);
  const sortAsc = () => setItems(items.sort((a, b) => a - b));
  return <button onClick={sortAsc}>{items.join(',')}</button>;
}
`),
    ignores: f('components/list.tsx', `'use client';
import { useState } from 'react';
export function List({ initial }: { initial: number[] }) {
  const [items, setItems] = useState(initial);
  const sortAsc = () => setItems([...items].sort((a, b) => a - b));
  return <button onClick={sortAsc}>{items.join(',')}</button>;
}
`),
  },
  {
    ruleIds: [29871], name: 'BUG-194 cookies() inside unstable_cache',
    detects: f('lib/prefs.ts', `import { unstable_cache } from 'next/cache';
import { cookies } from 'next/headers';
export const getPrefs = unstable_cache(async () => {
  const theme = (await cookies()).get('theme')?.value;
  return { theme };
}, ['prefs']);
`),
    ignores: f('lib/prefs.ts', `import { unstable_cache } from 'next/cache';
import { cookies } from 'next/headers';
const cachedPrefs = unstable_cache(async (theme?: string) => ({ theme }), ['prefs']);
export async function getPrefs() {
  return cachedPrefs((await cookies()).get('theme')?.value);
}
`),
  },
  {
    ruleIds: [29872], name: 'BUG-195 reduce without return',
    detects: f('lib/group.ts', `export const byId = (rows: { id: string }[]) => rows.reduce((acc, row) => {
  acc[row.id] = row;
}, {} as Record<string, { id: string }>);
`),
    ignores: f('lib/group.ts', `export const byId = (rows: { id: string }[]) => rows.reduce((acc, row) => {
  acc[row.id] = row;
  return acc;
}, {} as Record<string, { id: string }>);
`),
  },
  {
    ruleIds: [29873], name: 'BUG-196 Object.keys on URLSearchParams',
    detects: f('lib/filters.ts', `export function filters(url: string) {
  const params = new URLSearchParams(url.split('?')[1]);
  return Object.keys(params);
}
`),
    ignores: f('lib/filters.ts', `export function filters(url: string) {
  const params = new URLSearchParams(url.split('?')[1]);
  return Object.fromEntries(params);
}
`),
  },
  {
    ruleIds: [29874], name: 'BUG-197 use(fetch()) in a client component',
    detects: f('components/user.tsx', `'use client';
import { use } from 'react';
export function User({ id }: { id: string }) {
  const res = use(fetch('/api/users/' + id));
  return <div>{res.status}</div>;
}
`),
    ignores: f('components/user.tsx', `'use client';
import { use } from 'react';
export function User({ userPromise }: { userPromise: Promise<{ name: string }> }) {
  const user = use(userPromise);
  return <div>{user.name}</div>;
}
`),
  },
  {
    ruleIds: [29875], name: 'BUG-198 env var plus a number',
    detects: f('server/config.ts', `export const ADMIN_PORT = process.env.PORT + 1;
`),
    ignores: f('server/config.ts', `export const ADMIN_PORT = Number(process.env.PORT) + 1;
`),
  },
  {
    ruleIds: [29876], name: 'BUG-199 double encoding in URLSearchParams',
    detects: f('lib/search.ts', `export function link(q: string) {
  const searchParams = new URLSearchParams();
  searchParams.set('q', encodeURIComponent(q));
  return '/search?' + searchParams;
}
`),
    ignores: f('lib/search.ts', `export function link(q: string) {
  const searchParams = new URLSearchParams();
  searchParams.set('q', q);
  return '/search?' + searchParams;
}
`),
  },
  {
    ruleIds: [29877], name: 'BUG-200 btoa on JSON',
    detects: f('lib/state.ts', `export const encodeState = (s: object) => btoa(JSON.stringify(s));
`),
    ignores: f('lib/state.ts', `export const encodeState = (s: object) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(s))));
`),
  },
  {
    ruleIds: [29878], name: 'BUG-201 currency style without a code',
    detects: f('lib/money.ts', `export const fmt = (n: number) => new Intl.NumberFormat('en-US', { style: 'currency' }).format(n);
`),
    ignores: f('lib/money.ts', `export const fmt = (n: number) => new Intl.NumberFormat('en-US', { ...(n > 1e6 && { notation: 'compact' }), style: 'currency', currency: 'USD' }).format(n);
`),
  },
  {
    ruleIds: [29879], name: 'BUG-202 flatMap with async callback',
    detects: f('lib/tags.ts', `export const allTags = (ids: string[]) => ids.flatMap(async (id) => (await fetch('/t/' + id)).json());
`),
    ignores: f('lib/tags.ts', `export const allTags = async (ids: string[]) => (await Promise.all(ids.map(async (id) => (await fetch('/t/' + id)).json()))).flat();
`),
  },
  {
    ruleIds: [29880], name: 'BUG-203 useContext of the Provider',
    detects: f('components/theme.tsx', `'use client';
import { createContext, useContext } from 'react';
const ThemeContext = createContext('light');
export const useTheme = () => useContext(ThemeContext.Provider);
`),
    ignores: f('components/theme.tsx', `'use client';
import { createContext, useContext } from 'react';
const ThemeContext = createContext('light');
export const useTheme = () => useContext(ThemeContext);
`),
  },
  {
    ruleIds: [29881], name: 'BUG-204 OpenAI stream parser without [DONE]',
    detects: f('lib/chat.ts', `export async function readStream(res: Response, onToken: (t: string) => void) {
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const line of dec.decode(value).split('\\n')) {
      if (!line.startsWith('data:')) continue;
      const json = JSON.parse(line.slice(5));
      onToken(json.choices[0].delta.content ?? '');
    }
  }
}
`),
    ignores: f('lib/chat.ts', `export async function readStream(res: Response, onToken: (t: string) => void) {
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const line of dec.decode(value).split('\\n')) {
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (data === '[DONE]') return;
      onToken(JSON.parse(data).choices[0].delta.content ?? '');
    }
  }
}
`),
  },
  {
    ruleIds: [29882], name: 'BUG-205 find callback returns an object literal',
    detects: f('lib/find.ts', `export const findUser = (users: { id: string }[], id: string) => users.find((u) => ({ id }));
`),
    ignores: f('lib/find.ts', `export const findUser = (users: { id: string }[], id: string) => users.find((u) => u.id === id);
export const toRows = (users: { id: string }[]) => users.map((u) => ({ key: u.id }));
`),
  },
  {
    ruleIds: [29883], name: 'BUG-206 generateMetadata calls a hook',
    detects: f('app/posts/[slug]/page.tsx', `import { useParams } from 'next/navigation';
export async function generateMetadata() {
  const { slug } = useParams();
  return { title: String(slug) };
}
export default function Page() { return null; }
`),
    ignores: f('app/posts/[slug]/page.tsx', `export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return { title: slug };
}
export default function Page() { return null; }
`),
  },
  {
    ruleIds: [29884], name: 'BUG-207 Math.max given an array',
    detects: f('lib/stats.ts', `export function top(rows: { score: number }[]) {
  const scores = rows.map((r) => r.score);
  return Math.max(scores);
}
`),
    ignores: f('lib/stats.ts', `export function top(rows: { score: number }[], limit: number) {
  const scores = rows.map((r) => r.score);
  return Math.min(Math.max(...scores), limit);
}
`),
  },
  {
    ruleIds: [29885], name: 'BUG-208 new URL(req.url) in Express',
    detects: f('server/app.ts', `import express from 'express';
const app = express();
app.get('/search', (req, res) => {
  const url = new URL(req.url);
  res.json({ q: url.searchParams.get('q') });
});
`),
    ignores: f('server/app.ts', `import express from 'express';
const app = express();
app.get('/search', (req, res) => {
  const url = new URL(req.url, \`http://\${req.headers.host}\`);
  res.json({ q: url.searchParams.get('q') });
});
`),
  },
  {
    ruleIds: [29886], name: 'BUG-209 caught error spread into the response',
    detects: f('app/api/run/route.ts', `export async function POST() {
  try {
    await doWork();
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json({ ok: false, error: { ...error } }, { status: 500 });
  }
}
declare function doWork(): Promise<void>;
`),
    ignores: f('app/api/run/route.ts', `export async function POST() {
  try {
    await doWork();
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json({ ok: false, error: (error as Error).message }, { status: 500 });
  }
}
declare function doWork(): Promise<void>;
`),
  },
  {
    ruleIds: [29887], name: 'BUG-210 setMonth(getMonth() + 1)',
    detects: f('lib/billing.ts', `export function nextRenewal(from: Date) {
  const d = new Date(from);
  d.setMonth(d.getMonth() + 1);
  return d;
}
`),
    ignores: f('lib/billing.ts', `import { addMonths } from 'date-fns';
export const nextRenewal = (from: Date) => addMonths(from, 1);
`),
  },
  {
    ruleIds: [29888], name: 'BUG-211 test() on a module-level global regex',
    detects: f('lib/validate.ts', `const EMAIL = /^[^@\\s]+@[^@\\s]+$/g;
export const isEmail = (s: string) => EMAIL.test(s);
`),
    ignores: f('lib/validate.ts', `const EMAIL = /^[^@\\s]+@[^@\\s]+$/;
const WORDS = /\\w+/g;
export const isEmail = (s: string) => EMAIL.test(s);
export const words = (s: string) => s.match(WORDS) ?? [];
`),
  },
  {
    ruleIds: [29889], name: 'BUG-212 BigInt plus a number',
    detects: f('lib/ids.ts', `export const nextId = (id: string) => BigInt(id) + 1;
`),
    ignores: f('lib/ids.ts', `export const nextId = (id: string) => BigInt(id) + 1n;
`),
  },
  {
    ruleIds: [29890], name: 'BUG-213 JSON.stringify on a Map',
    detects: f('lib/cache.ts', `const seen = new Map<string, number>();
export function snapshot() {
  return JSON.stringify(seen);
}
`),
    ignores: f('lib/cache.ts', `const seen = new Map<string, number>();
export function snapshot() {
  return JSON.stringify(Object.fromEntries(seen));
}
`),
  },
  {
    ruleIds: [29891], name: 'BUG-214 Supabase in() with a joined string',
    detects: f('lib/posts.ts', `import { supabase } from './supabase';
export const byIds = (ids: string[]) => supabase.from('posts').select('*').in('id', ids.join(','));
`),
    ignores: f('lib/posts.ts', `import { supabase } from './supabase';
export const byIds = (ids: string[]) => supabase.from('posts').select('*').in('id', ids);
`),
  },
  {
    ruleIds: [29892], name: 'BUG-215 textSearch without websearch type',
    detects: f('lib/search.ts', `import { supabase } from './supabase';
export const search = (query: string) => supabase.from('docs').select('*').textSearch('fts', query);
`),
    ignores: f('lib/search.ts', `import { supabase } from './supabase';
export const search = (query: string) => supabase.from('docs').select('*').textSearch('fts', query, { type: 'websearch' });
`),
  },
  {
    ruleIds: [29893], name: 'BUG-216 JWT expiresIn in milliseconds',
    detects: f('lib/auth.ts', `import jwt from 'jsonwebtoken';
export const issue = (sub: string) => jwt.sign({ sub }, process.env.JWT_SECRET!, { expiresIn: 60 * 60 * 1000 });
`),
    ignores: f('lib/auth.ts', `import jwt from 'jsonwebtoken';
export const issue = (sub: string) => jwt.sign({ sub }, process.env.JWT_SECRET!, { expiresIn: '1h' });
`),
  },
  {
    ruleIds: [29894], name: 'BUG-217 timingSafeEqual without a length check',
    detects: f('lib/webhook.ts', `import { createHmac, timingSafeEqual } from 'crypto';
export function verify(body: string, sig: string, secret: string) {
  const expected = createHmac('sha256', secret).update(body).digest('hex');
  return timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
`),
    ignores: f('lib/webhook.ts', `import { createHmac, timingSafeEqual } from 'crypto';
export function verify(body: string, sig: string, secret: string) {
  const a = Buffer.from(sig);
  const b = Buffer.from(createHmac('sha256', secret).update(body).digest('hex'));
  return a.length === b.length && timingSafeEqual(a, b);
}
`),
  },
  {
    ruleIds: [29895], name: 'BUG-218 cookies() without await on Next 16',
    detects: [NEXT16, { path: 'app/page.tsx', content: `import { cookies } from 'next/headers';
export default async function Page() {
  const theme = cookies().get('theme')?.value;
  return <main>{theme}</main>;
}
` }],
    ignores: [NEXT16, { path: 'app/page.tsx', content: `import { cookies } from 'next/headers';
export default async function Page() {
  const theme = (await cookies()).get('theme')?.value;
  return <main>{theme}</main>;
}
` }],
  },
  {
    ruleIds: [29897], name: 'BUG-220 os.path.join with an absolute part',
    detects: f('app/files.py', `import os
BASE = "/srv/app"
def avatar_path(name: str) -> str:
    return os.path.join(BASE, "/uploads", name)
`),
    ignores: f('app/files.py', `import os
BASE = "/srv/app"
def avatar_path(name: str) -> str:
    return os.path.join(BASE, "uploads", name)
`),
  },
  {
    ruleIds: [29898], name: 'BUG-221 module variable updated without global',
    detects: f('app/counter.py', `hits = 0

def track():
    hits += 1
    return hits
`),
    ignores: f('app/counter.py', `hits = 0

def track():
    global hits
    hits += 1
    return hits
`),
  },
  {
    ruleIds: [29899], name: 'BUG-222 UploadFile read twice',
    detects: f('app/upload.py', `from fastapi import UploadFile

async def handle(file: UploadFile):
    data = await file.read()
    size = len(data)
    content = await file.read()
    return size, content
`),
    ignores: f('app/upload.py', `from fastapi import UploadFile

async def handle(file: UploadFile):
    data = await file.read()
    await file.seek(0)
    content = await file.read()
    return len(data), content
`),
  },
];
