import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const file = (path: string, content: string): CodeFile => ({ path, content });
const pkg = (deps: Record<string, string>) => file('package.json', JSON.stringify({ dependencies: deps }));
const NEXT = pkg({ next: '16.0.1', react: '19.2.0', 'react-dom': '19.2.0' });
const NEXT_CONFIG = file('next.config.ts', `const config = { images: { remotePatterns: [{ protocol: 'https', hostname: 'images.unsplash.com' }] } };
export default config;
`);
const HOME = file('app/page.tsx', 'export default function Home() { return <main>Home</main>; }\n');
const PRICING = file('app/(marketing)/pricing/page.tsx', 'export default function Pricing() { return <main>Pricing</main>; }\n');
const BLOG = file('app/blog/[slug]/page.tsx', 'export default async function Post() { return <article />; }\n');

export const CASES: RuleCase[] = [
  {
    ruleIds: [29758], name: 'BUG-125 import path differs only in case',
    detects: [NEXT, file('components/ui/Button.tsx', 'export function Button() { return <button />; }\n'),
      file('app/page.tsx', `import { Button } from '@/components/ui/button';
export default function Home() { return <Button />; }
`)],
    ignores: [NEXT, file('components/ui/Button.tsx', 'export function Button() { return <button />; }\n'),
      file('app/page.tsx', `import { Button } from '@/components/ui/Button';
import styles from './page.module.css';
export default function Home() { return <Button />; }
`)],
  },
  {
    ruleIds: [29759], name: 'BUG-126 link to a page that does not exist',
    detects: [NEXT, NEXT_CONFIG, HOME, PRICING, BLOG, file('components/nav.tsx', `import Link from 'next/link';
export function Nav() {
  return <nav><Link href="/pricing">Pricing</Link><Link href="/features">Features</Link></nav>;
}
`)],
    ignores: [NEXT, NEXT_CONFIG, HOME, PRICING, BLOG, file('components/nav.tsx', `import Link from 'next/link';
export function Nav() {
  return <nav><Link href="/pricing">Pricing</Link><Link href="/blog/hello-world">Blog</Link><Link href="/logo.svg">Logo</Link></nav>;
}
`)],
  },
  {
    ruleIds: [29760], name: 'BUG-127 next/image host missing from remotePatterns',
    detects: [NEXT, NEXT_CONFIG, file('components/avatar.tsx', `import Image from 'next/image';
export function Avatar() {
  return <Image src="https://avatars.githubusercontent.com/u/1" alt="" width={40} height={40} />;
}
`)],
    ignores: [NEXT, NEXT_CONFIG, file('components/avatar.tsx', `import Image from 'next/image';
export function Avatar() {
  return <Image src="https://images.unsplash.com/photo-1" alt="" width={40} height={40} />;
}
`)],
  },
  {
    ruleIds: [29761], name: 'BUG-128 static export with a server action',
    detects: [NEXT, file('next.config.mjs', "export default { output: 'export' };\n"), file('app/actions.ts', `'use server';
export async function subscribe(formData: FormData) { await save(formData.get('email')); }
`)],
    ignores: [NEXT, file('next.config.mjs', 'export default { reactStrictMode: true };\n'), file('app/actions.ts', `'use server';
export async function subscribe(formData: FormData) { await save(formData.get('email')); }
`)],
  },
  {
    ruleIds: [29762], name: 'BUG-129 useSearchParams page without Suspense',
    detects: [NEXT, file('app/search/page.tsx', `'use client';
import { useSearchParams } from 'next/navigation';
export default function Search() {
  const q = useSearchParams().get('q');
  return <p>{q}</p>;
}
`)],
    ignores: [NEXT, file('app/search/loading.tsx', 'export default function Loading() { return <p>Loading</p>; }\n'), file('app/search/page.tsx', `'use client';
import { useSearchParams } from 'next/navigation';
export default function Search() {
  const q = useSearchParams().get('q');
  return <p>{q}</p>;
}
`)],
  },
  {
    ruleIds: [29763], name: 'BUG-130 Zustand v5 selector returns a new object',
    detects: [pkg({ react: '19.0.0', zustand: '5.0.3' }), file('components/cart-badge.tsx', `import { useCartStore } from '@/store/cart';
export function CartBadge() {
  const { count, total } = useCartStore((s) => ({ count: s.count, total: s.total }));
  return <span>{count} / {total}</span>;
}
`)],
    ignores: [pkg({ react: '19.0.0', zustand: '5.0.3' }), file('components/cart-badge.tsx', `import { useShallow } from 'zustand/react/shallow';
import { useCartStore } from '@/store/cart';
export function CartBadge() {
  const { count, total } = useCartStore(useShallow((s) => ({ count: s.count, total: s.total })));
  const items = useCartStore((s) => s.items);
  return <span>{count} / {total} / {items.length}</span>;
}
`)],
  },
  {
    ruleIds: [29764], name: 'BUG-131 Expo env var without EXPO_PUBLIC_',
    detects: [pkg({ expo: '53.0.0', 'react-native': '0.79.0' }), file('lib/api.ts', `export async function getPosts() {
  return fetch(\`\${process.env.API_URL}/posts\`).then((r) => r.json());
}
`)],
    ignores: [pkg({ expo: '53.0.0', 'react-native': '0.79.0' }), file('lib/api.ts', `export async function getPosts() {
  if (process.env.NODE_ENV === 'development') console.log('dev');
  return fetch(\`\${process.env.EXPO_PUBLIC_API_URL}/posts\`).then((r) => r.json());
}
`)],
  },
  {
    ruleIds: [29765], name: 'BUG-132 defaultProps on a function component in React 19',
    detects: [pkg({ react: '19.1.0' }), file('components/badge.tsx', `export function Badge({ size, label }: { size?: string; label: string }) {
  return <span className={size}>{label}</span>;
}
Badge.defaultProps = { size: 'md' };
`)],
    ignores: [pkg({ react: '18.3.1' }), file('components/badge.tsx', `export function Badge({ size, label }: { size?: string; label: string }) {
  return <span className={size}>{label}</span>;
}
Badge.defaultProps = { size: 'md' };
`)],
  },
];
