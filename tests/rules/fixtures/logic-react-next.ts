import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const NEXT16 = { path: 'package.json', content: '{ "name": "app", "dependencies": { "next": "^16.1.0", "react": "^19.2.0" } }\n' };

export const CASES: RuleCase[] = [
  {
    ruleIds: [29620], name: 'BUG-20 random / time value rendered in a client component',
    detects: f('app/orders/[id]/page.tsx', `'use client';
export default function OrderCard({ order }: { order: Order }) {
  const ref = Math.random().toString(36).slice(2);
  const now = new Date();
  return (
    <div id={ref}>
      <h2>{order.title}</h2>
      <span>Rendered at {now.toLocaleTimeString()}</span>
    </div>
  );
}
`),
    ignores: f('app/orders/[id]/page.tsx', `'use client';
import { useEffect, useId, useState } from 'react';
export default function OrderCard({ order }: { order: Order }) {
  const ref = useId();
  const year = new Date().getFullYear();
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => setNow(new Date()), []);
  const onClick = () => track(Math.random());
  return (
    <div id={ref} onClick={onClick}>
      <h2>{order.title} {year}</h2>
      {now && <span>Rendered at {now.toLocaleTimeString('en-US', { timeZone: 'UTC' })}</span>}
    </div>
  );
}
`),
  },
  {
    ruleIds: [29621], name: 'BUG-21 date formatted with runtime time zone during render',
    detects: f('app/blog/[slug]/page.tsx', `'use client';
export default function PostMeta({ post }: { post: Post }) {
  return (
    <p className="text-sm">
      Published {new Date(post.createdAt).toLocaleDateString()}
    </p>
  );
}
`),
    ignores: f('app/blog/[slug]/page.tsx', `'use client';
export default function PostMeta({ post }: { post: Post }) {
  const onCopy = () => copy(new Date(post.createdAt).toLocaleDateString());
  return (
    <p className="text-sm" onClick={onCopy}>
      Published {new Date(post.createdAt).toLocaleDateString('en-US', { timeZone: 'UTC' })} · {post.views.toLocaleString()} views
    </p>
  );
}
`),
  },
  {
    ruleIds: [29622], name: 'BUG-22 window / localStorage read during render',
    detects: f('app/dashboard/page.tsx', `'use client';
import { useState } from 'react';
export default function DashboardPage() {
  const [open, setOpen] = useState(localStorage.getItem('sidebar') === 'open');
  return (
    <main>
      <aside className={open ? 'w-64' : 'w-16'} onClick={() => setOpen(!open)} />
      {window.location.hostname === 'localhost' && <p>Dev mode</p>}
    </main>
  );
}
`),
    ignores: f('app/dashboard/page.tsx', `'use client';
import { useEffect, useState } from 'react';
export default function DashboardPage({ document }: { document: Doc }) {
  const [open, setOpen] = useState(false);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setOpen(localStorage.getItem('sidebar') === 'open');
    setReady(true);
  }, []);
  if (!ready) return null;
  return (
    <main title={document.title}>
      <aside className={open ? 'w-64' : 'w-16'} onClick={() => setOpen(!open)} />
      {window.location.hostname === 'localhost' && <p>Dev mode</p>}
    </main>
  );
}
`),
  },
  {
    ruleIds: [29623], name: 'BUG-23 render output branches on typeof window',
    detects: f('pages/share.tsx', `'use client';
export default function ShareButton({ url }: { url: string }) {
  return (
    <div>
      {typeof window !== 'undefined' ? <button onClick={() => navigator.share({ url })}>Share</button> : null}
    </div>
  );
}
`),
    ignores: f('pages/share.tsx', `'use client';
import { useEffect, useState } from 'react';
export default function ShareButton({ url }: { url: string }) {
  const [canShare, setCanShare] = useState(false);
  useEffect(() => setCanShare(typeof window !== 'undefined' && 'share' in navigator), []);
  return <div>{canShare ? <button onClick={() => navigator.share({ url })}>Share</button> : null}</div>;
}
`),
  },
  {
    ruleIds: [29624], name: 'BUG-24 setState called unconditionally during render',
    detects: f('components/cart-total.tsx', `'use client';
import { useState } from 'react';
export function CartTotal({ items }: { items: Item[] }) {
  const [total, setTotal] = useState(0);
  setTotal(items.reduce((s, i) => s + i.price, 0));
  return <p>Total: {total}</p>;
}
`),
    ignores: f('components/cart-total.tsx', `'use client';
import { useState } from 'react';
export function CartTotal({ items }: { items: Item[] }) {
  const [prevItems, setPrevItems] = useState(items);
  const [discount, setDiscount] = useState(0);
  if (items !== prevItems) {
    setPrevItems(items);
    setDiscount(0);
  }
  const total = items.reduce((s, i) => s + i.price, 0) - discount;
  return <p onClick={() => setDiscount(5)}>Total: {total}</p>;
}
`),
  },
  {
    ruleIds: [29625], name: 'BUG-25 event prop given a setter call',
    detects: f('components/modal-trigger.tsx', `'use client';
import { useState } from 'react';
export function ModalTrigger() {
  const [open, setOpen] = useState(false);
  return <button type="button" onClick={setOpen(true)}>Open {String(open)}</button>;
}
`),
    ignores: f('components/modal-trigger.tsx', `'use client';
import { useState } from 'react';
export function ModalTrigger() {
  const [open, setOpen] = useState(false);
  return <button type="button" onClick={() => setOpen(true)} onBlur={setOpen.bind(null, false)}>Open {String(open)}</button>;
}
`),
  },
  {
    ruleIds: [29626], name: 'BUG-26 interval registered once reads stale state',
    detects: f('components/countdown.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Timer() {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const id = setInterval(() => {
      setSeconds(seconds + 1);
    }, 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{seconds}s</span>;
}
`),
    ignores: f('components/countdown.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Timer() {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const id = setInterval(() => {
      setSeconds((seconds) => seconds + 1);
    }, 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{seconds}s</span>;
}
`),
  },
  {
    ruleIds: [29627], name: 'BUG-27 prop copied into state that never updates',
    detects: f('components/profile-header.tsx', `'use client';
import { useState } from 'react';
export function ProfileHeader({ user }: { user: User }) {
  const [name] = useState(user.name);
  const [profile] = useState(user);
  return <h1>{name} {profile.email}</h1>;
}
`),
    ignores: f('components/profile-header.tsx', `'use client';
import { useState } from 'react';
export function ProfileHeader({ user, initialTab }: { user: User; initialTab: string }) {
  const [draft, setDraft] = useState(user);
  const [tab] = useState(initialTab);
  return <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} data-tab={tab} />;
}
`),
  },
  {
    ruleIds: [29628], name: 'BUG-28 dependency recreated every render',
    detects: f('components/product-list.tsx', `'use client';
import { useEffect, useState } from 'react';
export function ProductList({ category }: { category: string }) {
  const [products, setProducts] = useState<Product[]>([]);
  const filters = { category, inStock: true };
  useEffect(() => {
    fetch('/api/products?' + new URLSearchParams(filters as any)).then((r) => r.json()).then(setProducts);
  }, [filters]);
  return <ul>{products.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
`),
    ignores: f('components/product-list.tsx', `'use client';
import { useEffect, useMemo, useState } from 'react';
const DEFAULTS = { inStock: true };
export function ProductList({ category }: { category: string }) {
  const [products, setProducts] = useState<Product[]>([]);
  const filters = useMemo(() => ({ ...DEFAULTS, category }), [category]);
  useEffect(() => {
    fetch('/api/products?' + new URLSearchParams(filters as any)).then((r) => r.json()).then(setProducts);
  }, [filters, DEFAULTS]);
  return <ul>{products.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29629], name: 'BUG-29 useCallback with [] reads state',
    detects: f('components/search-box.tsx', `'use client';
import { useCallback, useState } from 'react';
export function SearchBox({ onSearch }: { onSearch: (q: string) => void }) {
  const [query, setQuery] = useState('');
  const submit = useCallback(() => {
    onSearch(query.trim());
  }, []);
  return <input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />;
}
`),
    ignores: f('components/search-box.tsx', `'use client';
import { useCallback, useState } from 'react';
export function SearchBox({ onSearch }: { onSearch: (q: string) => void }) {
  const [query, setQuery] = useState('');
  const submit = useCallback(() => {
    onSearch(query.trim());
  }, [query, onSearch]);
  const normalize = useCallback((query: string) => query.trim().toLowerCase(), []);
  const reset = useCallback(() => setQuery((query) => query && ''), []);
  return <input value={query} onChange={(e) => setQuery(normalize(e.target.value))} onBlur={reset} onKeyDown={(e) => e.key === 'Enter' && submit()} />;
}
`),
  },
  {
    ruleIds: [29630], name: 'BUG-30 effect updates its own dependency',
    detects: f('components/visit-counter.tsx', `'use client';
import { useEffect, useState } from 'react';
export function VisitCounter() {
  const [visits, setVisits] = useState(0);
  useEffect(() => {
    setVisits(visits + 1);
  }, [visits]);
  return <span>{visits}</span>;
}
`),
    ignores: f('components/visit-counter.tsx', `'use client';
import { useEffect, useState } from 'react';
export function VisitCounter({ page }: { page: string }) {
  const [visits, setVisits] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    setVisits((v) => v + 1);
  }, [page]);
  useEffect(() => {
    if (visits > 10) setVisits(0);
    setLoading(false);
  }, [visits, loading]);
  return <span>{visits}</span>;
}
`),
  },
  {
    ruleIds: [29631], name: 'BUG-31 random key',
    detects: f('components/todo-list.tsx', `export function TodoList({ todos }: { todos: Todo[] }) {
  return (
    <ul>
      {todos.map((todo) => (
        <li key={Math.random()}>{todo.title}</li>
      ))}
    </ul>
  );
}
`),
    ignores: f('components/todo-list.tsx', `export function TodoList({ todos }: { todos: Todo[] }) {
  return (
    <ul>
      {todos.map((todo) => (
        <li key={todo.id} data-seed={Math.random()}>{todo.title}</li>
      ))}
    </ul>
  );
}
`),
  },
  {
    ruleIds: [29632], name: 'BUG-32 index key on a deletable list of uncontrolled inputs',
    detects: f('components/guest-list.tsx', `'use client';
import { useState } from 'react';
export function GuestList() {
  const [guests, setGuests] = useState<Guest[]>([]);
  const remove = (i: number) => setGuests((prev) => prev.filter((_, j) => j !== i));
  return (
    <div>
      {guests.map((guest, i) => (
        <div key={i}>
          <input defaultValue={guest.name} />
          <button type="button" onClick={() => remove(i)}>Remove</button>
        </div>
      ))}
    </div>
  );
}
`),
    ignores: f('components/guest-list.tsx', `'use client';
import { useState } from 'react';
export function GuestList() {
  const [guests, setGuests] = useState<Guest[]>([]);
  const remove = (id: string) => setGuests((prev) => prev.filter((g) => g.id !== id));
  return (
    <div>
      {guests.map((guest, i) => (
        <div key={guest.id}>
          <span>{i + 1}.</span>
          <input defaultValue={guest.name} />
          <button type="button" onClick={() => remove(guest.id)}>Remove</button>
        </div>
      ))}
    </div>
  );
}
`),
  },
  {
    ruleIds: [29633], name: 'BUG-33 controlled input without onChange',
    detects: f('components/profile-form.tsx', `'use client';
import { useState } from 'react';
export function ProfileForm({ user }: { user: User }) {
  const [name, setName] = useState(user.name);
  return (
    <div>
      <input type="text" value={name} placeholder="Name" />
      <button type="button" onClick={() => save(name)} onFocus={() => setName(name)}>Save</button>
    </div>
  );
}
`),
    ignores: f('components/profile-form.tsx', `'use client';
import { useState } from 'react';
export function ProfileForm({ user }: { user: User }) {
  const [name, setName] = useState(user.name);
  return (
    <div>
      <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" />
      <input type="email" value={user.email} readOnly />
      <input type="hidden" name="id" value={user.id} />
      <input type="checkbox" value="yes" defaultChecked />
      <input {...register('bio')} value={name} />
      <button type="button" onClick={() => save(name)}>Save</button>
    </div>
  );
}
`),
  },
  {
    ruleIds: [29634], name: 'BUG-34 onSubmit fetch without preventDefault',
    detects: f('components/newsletter-form.tsx', `'use client';
import { useState } from 'react';
export function NewsletterForm() {
  const [email, setEmail] = useState('');
  async function handleSubmit() {
    await fetch('/api/subscribe', { method: 'POST', body: JSON.stringify({ email }) });
  }
  return (
    <form onSubmit={handleSubmit}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <button type="submit">Join</button>
    </form>
  );
}
`),
    ignores: f('components/newsletter-form.tsx', `'use client';
import { useState } from 'react';
export function NewsletterForm() {
  const [email, setEmail] = useState('');
  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    await fetch('/api/subscribe', { method: 'POST', body: JSON.stringify({ email }) });
  }
  return (
    <>
      <form onSubmit={handleSubmit}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} />
        <button type="submit">Join</button>
      </form>
      <form onSubmit={form.handleSubmit(onValid)}><button type="submit">Save</button></form>
    </>
  );
}
`),
  },
  {
    ruleIds: [29635], name: 'BUG-35 button without type inside a form',
    detects: f('components/edit-dialog.tsx', `'use client';
export function EditDialog({ onClose }: { onClose: () => void }) {
  return (
    <form action={updateProfile}>
      <input name="name" />
      <button onClick={onClose}>Cancel</button>
      <button type="submit">Save</button>
    </form>
  );
}
`),
    ignores: f('components/edit-dialog.tsx', `'use client';
export function EditDialog({ onClose }: { onClose: () => void }) {
  return (
    <form action={updateProfile}>
      <input name="name" />
      <button type="button" onClick={onClose}>Cancel</button>
      <button type="submit">Save</button>
    </form>
  );
}
`),
  },
  {
    ruleIds: [29636], name: 'BUG-36 payment button without pending guard',
    detects: f('components/checkout-button.tsx', `'use client';
export function CheckoutButton({ priceId }: { priceId: string }) {
  async function handleCheckout() {
    const res = await fetch('/api/checkout', { method: 'POST', body: JSON.stringify({ priceId }) });
    const { url } = await res.json();
    window.location.href = url;
  }
  return <button onClick={handleCheckout}>Buy now</button>;
}
`),
    ignores: f('components/checkout-button.tsx', `'use client';
import { useState } from 'react';
export function CheckoutButton({ priceId }: { priceId: string }) {
  const [pending, setPending] = useState(false);
  async function handleCheckout() {
    const res = await fetch('/api/checkout', { method: 'POST', body: JSON.stringify({ priceId }) });
    const { url } = await res.json();
    window.location.href = url;
  }
  async function loadPlans() {
    await fetch('/api/plans');
  }
  return (
    <>
      <button disabled={pending} onClick={async () => { setPending(true); await handleCheckout(); }}>Buy now</button>
      <button onClick={handleCheckout} disabled={pending}>Buy again</button>
      <button onClick={loadPlans}>Plans</button>
    </>
  );
}
`),
  },
  {
    ruleIds: [29637], name: 'BUG-37 cookies() / headers() without await on Next.js 16',
    detects: [NEXT16, { path: 'app/dashboard/page.tsx', content: `import { cookies, headers } from 'next/headers';
export default async function Dashboard() {
  const theme = cookies().get('theme')?.value;
  const h = headers();
  const ua = h.get('user-agent');
  return <main data-theme={theme}>{ua}</main>;
}
` }],
    ignores: [NEXT16, { path: 'app/dashboard/page.tsx', content: `import { cookies, headers } from 'next/headers';
export default async function Dashboard() {
  const theme = (await cookies()).get('theme')?.value;
  const h = await headers();
  const ua = h.get('user-agent');
  return <main data-theme={theme}>{ua}</main>;
}
` }],
  },
  {
    ruleIds: [29638], name: 'BUG-38 metadata exported from a client component',
    detects: f('app/pricing/page.tsx', `'use client';
import { useState } from 'react';
export const metadata = { title: 'Pricing' };
export default function PricingPage() {
  const [yearly, setYearly] = useState(false);
  return <button type="button" onClick={() => setYearly(!yearly)}>Toggle</button>;
}
`),
    ignores: f('app/pricing/page.tsx', `import { PricingToggle } from './pricing-toggle';
export const metadata = { title: 'Pricing' };
export default function PricingPage() {
  return <PricingToggle />;
}
`),
  },
  {
    ruleIds: [29639], name: 'BUG-39 async client component',
    detects: f('components/user-menu.tsx', `'use client';
import { useState } from 'react';
export default async function UserMenu() {
  const [open, setOpen] = useState(false);
  const user = await getUser();
  return <button type="button" onClick={() => setOpen(!open)}>{user.name}</button>;
}
`),
    ignores: f('components/user-menu.tsx', `'use client';
import { useState } from 'react';
export default function UserMenu({ user }: { user: User }) {
  const [open, setOpen] = useState(false);
  const logout = async () => { await fetch('/api/logout', { method: 'POST' }); };
  return <button type="button" onClick={() => { setOpen(!open); logout(); }}>{user.name}</button>;
}
`),
  },
  {
    ruleIds: [29640], name: 'BUG-40 server-only module in a client component',
    detects: f('components/settings-form.tsx', `'use client';
import { cookies } from 'next/headers';
import { revalidatePath } from 'next/cache';
import { useState } from 'react';
export function SettingsForm() {
  const [name, setName] = useState('');
  return <input value={name} onChange={(e) => setName(e.target.value)} />;
}
`),
    ignores: f('components/settings-form.tsx', `'use client';
import type { ReadonlyRequestCookies } from 'next/dist/server/web/spec-extension/adapters/request-cookies';
import { useState } from 'react';
import { saveSettings } from '@/app/actions';
export function SettingsForm() {
  const [name, setName] = useState('');
  return <input value={name} onChange={(e) => setName(e.target.value)} onBlur={() => saveSettings(name)} />;
}
`),
  },
  {
    ruleIds: [29641], name: 'BUG-41 redirect() in a client event handler',
    detects: f('components/logout-button.tsx', `'use client';
import { redirect } from 'next/navigation';
export function LogoutButton() {
  const handleLogout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    redirect('/login');
  };
  return <button type="button" onClick={handleLogout}>Log out</button>;
}
`),
    ignores: f('components/logout-button.tsx', `'use client';
import { redirect, useRouter } from 'next/navigation';
export function LogoutButton({ user }: { user: User | null }) {
  const router = useRouter();
  if (!user) redirect('/login');
  const handleLogout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    router.push('/login');
  };
  return <button type="button" onClick={handleLogout}>Log out</button>;
}
`),
  },
  {
    ruleIds: [29642], name: 'BUG-42 next/router in the app directory',
    detects: f('app/settings/page.tsx', `'use client';
import { useRouter } from 'next/router';
export default function SettingsPage() {
  const router = useRouter();
  return <button type="button" onClick={() => router.push('/')}>Home</button>;
}
`),
    ignores: f('app/settings/page.tsx', `'use client';
import { useRouter } from 'next/navigation';
export default function SettingsPage() {
  const router = useRouter();
  return <button type="button" onClick={() => router.push('/')}>Home</button>;
}
`),
  },
  {
    ruleIds: [29643], name: 'BUG-43 force-static route handler reads the request',
    detects: f('app/api/search/route.ts', `import { NextRequest } from 'next/server';
export const dynamic = 'force-static';
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  return Response.json(await search(q));
}
`),
    ignores: f('app/api/search/route.ts', `export const dynamic = 'force-static';
export async function GET() {
  return Response.json(await listCategories());
}
`),
  },
  {
    ruleIds: [29644], name: 'BUG-44 "use server" file exports a non-async value',
    detects: f('app/actions/todos.ts', `'use server';
import { z } from 'zod';
export const todoSchema = z.object({ title: z.string() });
export function formatTitle(t: string) { return t.trim(); }
export async function createTodo(formData: FormData) {
  await db.todo.create({ data: todoSchema.parse({ title: formData.get('title') }) });
}
`),
    ignores: f('app/actions/todos.ts', `'use server';
import { todoSchema } from './schema';
export type TodoInput = { title: string };
export async function createTodo(formData: FormData) {
  await db.todo.create({ data: todoSchema.parse({ title: formData.get('title') }) });
}
export const deleteTodo = async (id: string) => { await db.todo.delete({ where: { id } }); };
export const archiveTodo = withAuth(async (id: string) => { await db.todo.update({ where: { id }, data: { archived: true } }); });
`),
  },
  {
    ruleIds: [29645], name: 'BUG-45 directive after imports',
    detects: f('components/like-button.tsx', `import { useState } from 'react';
'use client';
export function LikeButton() {
  const [liked, setLiked] = useState(false);
  return <button type="button" onClick={() => setLiked(!liked)}>{liked ? 'Liked' : 'Like'}</button>;
}
`),
    ignores: f('components/like-button.tsx', `'use client';
import { useState } from 'react';
export function LikeButton() {
  const [liked, setLiked] = useState(false);
  return <button type="button" onClick={() => setLiked(!liked)}>{liked ? 'Liked' : 'Like'}</button>;
}
`),
  },
  {
    ruleIds: [29646], name: 'BUG-46 hooks / handlers in a Server Component page',
    detects: [
      { path: 'app/counter/page.tsx', content: `import { useState } from 'react';
export default function CounterPage() {
  const [count, setCount] = useState(0);
  return <button>{count}</button>;
}
` },
      { path: 'app/about/page.tsx', content: `export default function AboutPage() {
  return <button type="button" onClick={() => alert('hi')}>Say hi</button>;
}
` },
    ],
    ignores: [
      { path: 'app/counter/page.tsx', content: `import { Counter } from './counter';
export default function CounterPage() {
  return <Counter />;
}
` },
      { path: 'app/about/page.tsx', content: `export default function AboutPage() {
  return (
    <form action={async () => { 'use server'; await subscribe(); }}>
      <button type="submit">Subscribe</button>
    </form>
  );
}
` },
    ],
  },
  {
    ruleIds: [29647], name: 'BUG-47 error.tsx without use client',
    detects: f('app/dashboard/error.tsx', `export default function DashboardError({ error, reset }: { error: Error; reset: () => void }) {
  return <div><p>{error.message}</p><button onClick={() => reset()}>Retry</button></div>;
}
`),
    ignores: f('app/dashboard/error.tsx', `'use client';
export default function DashboardError({ error, reset }: { error: Error; reset: () => void }) {
  return <div><p>{error.message}</p><button onClick={() => reset()}>Retry</button></div>;
}
`),
  },
  {
    ruleIds: [29648], name: 'BUG-48 next/image fill without sizes',
    detects: f('components/product-card.tsx', `import Image from 'next/image';
export function ProductCard({ product }: { product: Product }) {
  return (
    <div className="relative aspect-square">
      <Image src={product.image} alt={product.name} fill className="object-cover" />
    </div>
  );
}
`),
    ignores: f('components/product-card.tsx', `import Image from 'next/image';
export function ProductCard({ product }: { product: Product }) {
  return (
    <div className="relative aspect-square">
      <Image src={product.image} alt={product.name} fill sizes="(max-width: 768px) 50vw, 25vw" className="object-cover" />
    </div>
  );
}
`),
  },
  {
    ruleIds: [29649], name: 'BUG-49 next/image fill with width, or URL src without size',
    detects: f('components/hero.tsx', `import Image from 'next/image';
export function Hero() {
  return (
    <section>
      <Image src="https://images.example.com/hero.jpg" alt="Hero" priority />
      <div className="relative h-64"><Image src="/team.jpg" alt="Team" fill width={1200} sizes="100vw" /></div>
    </section>
  );
}
`),
    ignores: f('components/hero.tsx', `import Image from 'next/image';
import team from '@/public/team.jpg';
export function Hero() {
  return (
    <section>
      <Image src="https://images.example.com/hero.jpg" alt="Hero" width={1600} height={900} priority />
      <Image src={team} alt="Team" />
      <div className="relative h-64"><Image src="/team.jpg" alt="Team" fill sizes="100vw" /></div>
    </section>
  );
}
`),
  },
  {
    ruleIds: [29650], name: 'BUG-50 text color equals background color',
    detects: f('components/banner.tsx', `export function Banner() {
  return <div className="rounded-lg bg-white p-4 text-white shadow">Your trial ends soon</div>;
}
`),
    ignores: f('components/banner.tsx', `export function Banner() {
  return <div className="rounded-lg bg-white p-4 text-gray-900 shadow dark:bg-gray-900 dark:text-white hover:bg-white/90">Your trial ends soon</div>;
}
`),
  },
  {
    ruleIds: [29651], name: 'BUG-51 fixed desktop width without breakpoint',
    detects: f('app/(marketing)/page.tsx', `export default function Home() {
  return (
    <main className="mx-auto w-[1200px] py-12">
      <h1>Welcome</h1>
    </main>
  );
}
`),
    ignores: f('app/(marketing)/page.tsx', `export default function Home() {
  return (
    <main className="mx-auto w-full max-w-[1200px] py-12">
      <h1>Welcome</h1>
      <div className="overflow-x-auto">
        <table className="min-w-[900px]"><tbody /></table>
      </div>
      <div className="lg:w-[1100px] w-[320px]" />
    </main>
  );
}
`),
  },
  {
    ruleIds: [29652], name: 'BUG-52 list.length && renders 0',
    detects: f('components/notifications.tsx', `export function Notifications({ items }: { items: Note[] }) {
  return (
    <div>
      {items.length && <ul>{items.map((n) => <li key={n.id}>{n.text}</li>)}</ul>}
    </div>
  );
}
`),
    ignores: f('components/notifications.tsx', `export function Notifications({ items }: { items: Note[] }) {
  return (
    <div>
      {items.length > 0 && <ul>{items.map((n) => <li key={n.id}>{n.text}</li>)}</ul>}
      {!items.length && <p>No notifications</p>}
    </div>
  );
}
`),
  },
  {
    ruleIds: [29653], name: 'BUG-53 state mutated then set with the same reference',
    detects: f('components/tag-editor.tsx', `'use client';
import { useState } from 'react';
export function TagEditor() {
  const [tags, setTags] = useState<string[]>([]);
  const addTag = (tag: string) => {
    tags.push(tag);
    setTags(tags);
  };
  return <button type="button" onClick={() => addTag('new')}>{tags.join(', ')}</button>;
}
`),
    ignores: f('components/tag-editor.tsx', `'use client';
import { useState } from 'react';
export function TagEditor() {
  const [tags, setTags] = useState<string[]>([]);
  const addTag = (tag: string) => {
    const next = [...tags];
    next.push(tag);
    setTags(next);
  };
  return <button type="button" onClick={() => addTag('new')}>{tags.join(', ')}</button>;
}
`),
  },
  {
    ruleIds: [29654], name: 'BUG-54 Pages Router API on the next/navigation router',
    detects: f('app/search/search-bar.tsx', `'use client';
import { useRouter } from 'next/navigation';
export function SearchBar() {
  const router = useRouter();
  const q = router.query.q as string;
  return <button type="button" onClick={() => router.push({ pathname: '/search', query: { q } })}>Search</button>;
}
`),
    ignores: f('app/search/search-bar.tsx', `'use client';
import { useRouter, useSearchParams } from 'next/navigation';
export function SearchBar() {
  const router = useRouter();
  const q = useSearchParams().get('q') ?? '';
  return <button type="button" onClick={() => router.push('/search?' + new URLSearchParams({ q }))}>Search</button>;
}
`),
  },
  {
    ruleIds: [29655], name: 'BUG-55 getServerSideProps in the app directory',
    detects: f('app/blog/page.tsx', `export async function getServerSideProps() {
  return { props: { posts: await getPosts() } };
}
export default function Blog({ posts }: { posts: Post[] }) {
  return <ul>{posts.map((p) => <li key={p.id}>{p.title}</li>)}</ul>;
}
`),
    ignores: f('pages/blog.tsx', `export async function getServerSideProps() {
  return { props: { posts: await getPosts() } };
}
export default function Blog({ posts }: { posts: Post[] }) {
  return <ul>{posts.map((p) => <li key={p.id}>{p.title}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29656], name: 'BUG-56 route handler with default export / (req, res)',
    detects: [
      { path: 'app/api/contact/route.ts', content: `export default async function handler(req: Request) {
  return Response.json({ ok: true });
}
` },
      { path: 'app/api/signup/route.ts', content: `export async function POST(req: any, res: any) {
  res.status(200).json({ ok: true });
}
` },
    ],
    ignores: f('app/api/contact/route.ts', `export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  return Response.json({ ok: true, id: (await params).id });
}
`),
  },
  {
    ruleIds: [29657], name: 'BUG-57 middleware inside app/',
    detects: f('app/middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function middleware(request: NextRequest) {
  if (!request.cookies.get('session')) return NextResponse.redirect(new URL('/login', request.url));
}
export const config = { matcher: ['/dashboard/:path*'] };
`),
    ignores: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function middleware(request: NextRequest) {
  if (!request.cookies.get('session')) return NextResponse.redirect(new URL('/login', request.url));
}
export const config = { matcher: ['/dashboard/:path*'] };
`),
  },
  {
    ruleIds: [29658], name: 'BUG-58 form action handler treats FormData as an event',
    detects: f('components/contact-form.tsx', `'use client';
export function ContactForm() {
  async function submit(e: any) {
    e.preventDefault();
    await fetch('/api/contact', { method: 'POST', body: new FormData(e.target) });
  }
  return (
    <form action={submit}>
      <input name="email" />
      <button type="submit">Send</button>
    </form>
  );
}
`),
    ignores: f('components/contact-form.tsx', `'use client';
export function ContactForm() {
  async function submit(formData: FormData) {
    await fetch('/api/contact', { method: 'POST', body: formData });
  }
  return (
    <form action={submit}>
      <input name="email" />
      <button type="submit">Send</button>
    </form>
  );
}
`),
  },
  {
    ruleIds: [29659], name: 'BUG-59 hook after early return / inside a condition',
    detects: f('components/account-panel.tsx', `'use client';
import { useEffect, useState } from 'react';
export function AccountPanel({ user }: { user: User | null }) {
  if (!user) return null;
  const [tab, setTab] = useState('profile');
  return <div onClick={() => setTab('billing')}>{tab}</div>;
}
export function Billing({ plan }: { plan?: Plan }) {
  if (plan) {
    useEffect(() => { track(plan.id); }, [plan]);
  }
  return <div>{plan?.name}</div>;
}
`),
    ignores: f('components/account-panel.tsx', `'use client';
import { useEffect, useState } from 'react';
export function AccountPanel({ user }: { user: User | null }) {
  const [tab, setTab] = useState('profile');
  useEffect(() => {
    if (!user) return;
    track(user.id);
  }, [user]);
  if (!user) return null;
  const rows = user.items.map((item) => {
    if (!item) return null;
    return <li key={item.id}>{item.name}</li>;
  });
  return <div onClick={() => setTab('billing')}>{tab}<ul>{rows}</ul></div>;
}
`),
  },
];
