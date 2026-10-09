import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const PKG16 = { path: 'package.json', content: '{ "dependencies": { "next": "16.0.1", "react": "19.2.0" } }' };

export const CASES: RuleCase[] = [
  {
    ruleIds: [29740], name: 'BUG-107 Tailwind class built from a variable',
    detects: f('components/badge.tsx', `export function Badge({ color, label }: { color: string; label: string }) {
  return <span className={\`rounded px-2 bg-\${color}-500 text-white\`}>{label}</span>;
}
`),
    ignores: f('components/badge.tsx', `const COLORS: Record<string, string> = { red: 'bg-red-500', green: 'bg-green-500' };
export function Badge({ color, label, size }: { color: string; label: string; size: string }) {
  return <span className={\`rounded px-2 \${COLORS[color]} \${size === 'lg' ? 'text-lg' : 'text-sm'}\`}>{label}</span>;
}
`),
  },
  {
    ruleIds: [29741], name: 'BUG-108 params read synchronously on Next.js 16',
    detects: [PKG16, { path: 'app/blog/[slug]/page.tsx', content: `export default async function Post({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  return <h1>{post.title}</h1>;
}
` }],
    ignores: [PKG16, { path: 'app/blog/[slug]/page.tsx', content: `export default async function Post({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = await getPost(slug);
  return <h1>{post.title}</h1>;
}
` }],
  },
  {
    ruleIds: [29742], name: 'BUG-109 input under 16px on mobile',
    detects: f('components/search.tsx', `export function Search() {
  return <input type="search" className="w-full rounded border px-3 py-2 text-xs" placeholder="Search" />;
}
`),
    ignores: f('components/search.tsx', `export function Search() {
  return (
    <>
      <input type="search" className="w-full rounded border px-3 py-2 text-base md:text-sm" placeholder="Search" />
      <input type="checkbox" className="h-4 w-4 text-sm" />
    </>
  );
}
`),
  },
  {
    ruleIds: [29743], name: 'BUG-110 useFormStatus in the component rendering the form',
    detects: f('components/newsletter.tsx', `'use client';
import { useFormStatus } from 'react-dom';
export function Newsletter({ action }: { action: (fd: FormData) => Promise<void> }) {
  const { pending } = useFormStatus();
  return (
    <form action={action}>
      <input name="email" />
      <button disabled={pending}>Subscribe</button>
    </form>
  );
}
`),
    ignores: f('components/newsletter.tsx', `'use client';
import { useFormStatus } from 'react-dom';
function SubmitButton() {
  const { pending } = useFormStatus();
  return <button disabled={pending}>Subscribe</button>;
}
export function Newsletter({ action }: { action: (fd: FormData) => Promise<void> }) {
  return (
    <form action={action}>
      <input name="email" />
      <SubmitButton />
    </form>
  );
}
`),
  },
  {
    ruleIds: [29744], name: 'BUG-111 DialogContent without a title',
    detects: f('components/delete-dialog.tsx', `import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog';
export function DeleteDialog() {
  return (
    <Dialog>
      <DialogTrigger>Delete</DialogTrigger>
      <DialogContent>
        <p>Are you sure?</p>
      </DialogContent>
    </Dialog>
  );
}
`),
    ignores: f('components/delete-dialog.tsx', `import { Dialog, DialogContent, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
export function DeleteDialog() {
  return (
    <Dialog>
      <DialogTrigger>Delete</DialogTrigger>
      <DialogContent>
        <DialogTitle>Delete project</DialogTitle>
        <p>Are you sure?</p>
      </DialogContent>
    </Dialog>
  );
}
`),
  },
  {
    ruleIds: [29745], name: 'BUG-112 JSON.parse of localStorage without try',
    detects: f('lib/cart.ts', `export function loadCart() {
  return JSON.parse(localStorage.getItem('cart') || '[]');
}
`),
    ignores: f('lib/cart.ts', `export function loadCart() {
  try {
    return JSON.parse(localStorage.getItem('cart') || '[]');
  } catch {
    return [];
  }
}
`),
  },
  {
    ruleIds: [29746], name: 'BUG-113 Image fill in an unpositioned parent',
    detects: f('components/hero.tsx', `import Image from 'next/image';
export function Hero() {
  return (
    <div className="h-64 w-full overflow-hidden">
      <Image src="/hero.jpg" alt="" fill className="object-cover" />
    </div>
  );
}
`),
    ignores: f('components/hero.tsx', `import Image from 'next/image';
export function Hero() {
  return (
    <div className="relative h-64 w-full overflow-hidden">
      <Image src="/hero.jpg" alt="" fill className="object-cover" />
    </div>
  );
}
`),
  },
  {
    ruleIds: [29747], name: 'BUG-114 action only visible on hover',
    detects: f('components/row.tsx', `export function Row({ name }: { name: string }) {
  return (
    <li className="group flex justify-between">
      {name}
      <button className="hidden group-hover:block text-red-500">Delete</button>
    </li>
  );
}
`),
    ignores: f('components/row.tsx', `export function Row({ name }: { name: string }) {
  return (
    <li className="group flex justify-between">
      {name}
      <button className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 text-red-500">Delete</button>
    </li>
  );
}
`),
  },
  {
    ruleIds: [29748], name: 'BUG-115 edge runtime with a Node-only module',
    detects: f('app/api/hash/route.ts', `import bcrypt from 'bcrypt';
export const runtime = 'edge';
export async function POST(req: Request) {
  const { password } = await req.json();
  return Response.json({ hash: await bcrypt.hash(password, 10) });
}
`),
    ignores: f('app/api/hash/route.ts', `import bcrypt from 'bcrypt';
export const runtime = 'nodejs';
export async function POST(req: Request) {
  const { password } = await req.json();
  return Response.json({ hash: await bcrypt.hash(password, 10) });
}
`),
  },
  {
    ruleIds: [29749], name: 'BUG-116 middleware matcher catches static assets',
    detects: f('middleware.ts', `import { NextResponse } from 'next/server';
export function middleware() { return NextResponse.next(); }
export const config = { matcher: ['/:path*'] };
`),
    ignores: f('middleware.ts', `import { NextResponse } from 'next/server';
export function middleware() { return NextResponse.next(); }
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
`),
  },
  {
    ruleIds: [29750], name: 'BUG-117 asChild with two children',
    detects: f('components/nav.tsx', `import Link from 'next/link';
import { Button } from '@/components/ui/button';
export function Nav() {
  return (
    <Button asChild>
      <span>Icon</span>
      <Link href="/pricing">Pricing</Link>
    </Button>
  );
}
`),
    ignores: f('components/nav.tsx', `import Link from 'next/link';
import { Button } from '@/components/ui/button';
export function Nav() {
  return (
    <Button asChild>
      <Link href="/pricing"><span>Icon</span> Pricing</Link>
    </Button>
  );
}
`),
  },
  {
    ruleIds: [29751], name: 'BUG-118 next-themes without suppressHydrationWarning',
    detects: f('app/layout.tsx', `import { ThemeProvider } from 'next-themes';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body><ThemeProvider attribute="class">{children}</ThemeProvider></body>
    </html>
  );
}
`),
    ignores: f('app/layout.tsx', `import { ThemeProvider } from 'next-themes';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body><ThemeProvider attribute="class">{children}</ThemeProvider></body>
    </html>
  );
}
`),
  },
  {
    ruleIds: [29752], name: 'BUG-119 search fetch without abort',
    detects: f('components/search-results.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Results({ query }: { query: string }) {
  const [items, setItems] = useState([]);
  useEffect(() => {
    fetch('/api/search?q=' + encodeURIComponent(query)).then((r) => r.json()).then(setItems);
  }, [query]);
  return <ul>{items.map((i: { id: string }) => <li key={i.id}>{i.id}</li>)}</ul>;
}
`),
    ignores: f('components/search-results.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Results({ query }: { query: string }) {
  const [items, setItems] = useState([]);
  useEffect(() => {
    const ctrl = new AbortController();
    fetch('/api/search?q=' + encodeURIComponent(query), { signal: ctrl.signal }).then((r) => r.json()).then(setItems).catch(() => {});
    return () => ctrl.abort();
  }, [query]);
  return <ul>{items.map((i: { id: string }) => <li key={i.id}>{i.id}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29753], name: 'BUG-120 useMutation without invalidation',
    detects: f('components/todos.tsx', `'use client';
import { useMutation, useQuery } from '@tanstack/react-query';
export function Todos() {
  const { data } = useQuery({ queryKey: ['todos'], queryFn: fetchTodos });
  const add = useMutation({ mutationFn: createTodo });
  return <button onClick={() => add.mutate({ title: 'x' })}>{data?.length}</button>;
}
`),
    ignores: f('components/todos.tsx', `'use client';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
export function Todos() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['todos'], queryFn: fetchTodos });
  const add = useMutation({ mutationFn: createTodo, onSuccess: () => qc.invalidateQueries({ queryKey: ['todos'] }) });
  return <button onClick={() => add.mutate({ title: 'x' })}>{data?.length}</button>;
}
`),
  },
  {
    ruleIds: [29755], name: 'BUG-122 Stripe relative return_url',
    detects: f('app/api/portal/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST() {
  const session = await stripe.billingPortal.sessions.create({ customer: 'cus_1', return_url: '/dashboard' });
  return Response.json({ url: session.url });
}
`),
    ignores: f('app/api/portal/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST() {
  const session = await stripe.billingPortal.sessions.create({ customer: 'cus_1', return_url: \`\${process.env.NEXT_PUBLIC_SITE_URL}/dashboard\` });
  return Response.json({ url: session.url });
}
`),
  },
  {
    ruleIds: [29756], name: 'BUG-123 Vue reactive destructure',
    detects: f('src/composables/useCounter.ts', `import { reactive } from 'vue';
export function useCounter() {
  const state = reactive({ count: 0, step: 1 });
  const { count, step } = reactive({ count: 0, step: 1 });
  return { state, count, step };
}
`),
    ignores: f('src/composables/useCounter.ts', `import { reactive, toRefs } from 'vue';
export function useCounter() {
  const state = reactive({ count: 0, step: 1 });
  const { count, step } = toRefs(state);
  return { state, count, step };
}
`),
  },
  {
    ruleIds: [29757], name: 'BUG-124 Platform.OS invalid literal',
    detects: f('src/screens/Home.tsx', `import { Platform, Text } from 'react-native';
export function Home() {
  return <Text style={{ paddingTop: Platform.OS === 'iOS' ? 44 : 0 }}>Home</Text>;
}
`),
    ignores: f('src/screens/Home.tsx', `import { Platform, Text } from 'react-native';
export function Home() {
  return <Text style={{ paddingTop: Platform.OS === 'ios' ? 44 : 0 }}>Home</Text>;
}
`),
  },
];
