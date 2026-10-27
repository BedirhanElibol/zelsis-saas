import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const C = 'components/Widget.tsx';

export const CASES: RuleCase[] = [
  {
    ruleIds: [30000], name: 'UXG-01 aria-label hides the visible text',
    detects: f(C, `export const CloseButton = ({ onClose }: { onClose: () => void }) => (
  <button aria-label="Close dialog" onClick={onClose}>Cancel</button>
);
`),
    ignores: f(C, `export const CloseButton = ({ onClose }: { onClose: () => void }) => (
  <button aria-label="Cancel and close dialog" onClick={onClose}>Cancel</button>
);
`),
  },
  {
    ruleIds: [30001], name: 'UXG-02 select navigates on change',
    detects: f(C, `'use client';
import { useRouter } from 'next/navigation';
export function LangPicker() {
  const router = useRouter();
  return (
    <select onChange={(e) => router.push(e.target.value)}>
      <option value="/en">English</option>
      <option value="/tr">Türkçe</option>
    </select>
  );
}
`),
    ignores: f(C, `'use client';
import { useState } from 'react';
export function LangPicker({ onApply }: { onApply: (v: string) => void }) {
  const [v, setV] = useState('/en');
  return (
    <form onSubmit={(e) => { e.preventDefault(); onApply(v); }}>
      <select value={v} onChange={(e) => setV(e.target.value)}>
        <option value="/en">English</option>
      </select>
      <button type="submit">Apply</button>
    </form>
  );
}
`),
  },
  {
    ruleIds: [30002], name: 'UXG-03 analytics loaded beforeInteractive',
    detects: f('app/layout.tsx', `import Script from 'next/script';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Script src="https://www.googletagmanager.com/gtag/js?id=G-123" strategy="beforeInteractive" />
      </body>
    </html>
  );
}
`),
    ignores: f('app/layout.tsx', `import Script from 'next/script';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Script src="https://www.googletagmanager.com/gtag/js?id=G-123" strategy="afterInteractive" />
        <Script src="/consent-mode.js" strategy="beforeInteractive" />
      </body>
    </html>
  );
}
`),
  },
  {
    ruleIds: [30003], name: 'UXG-04 dynamic icon lookup bundles every icon',
    detects: f(C, `import * as Icons from 'lucide-react';
export function DynamicIcon({ name }: { name: string }) {
  const Icon = (Icons as any)[name];
  return <Icon />;
}
`),
    ignores: f(C, `import { Home, User } from 'lucide-react';
const ICONS = { home: Home, user: User };
export function DynamicIcon({ name }: { name: keyof typeof ICONS }) {
  const Icon = ICONS[name];
  return <Icon />;
}
`),
  },
  {
    ruleIds: [30004], name: 'UXG-05 whole lodash in a component',
    detects: f(C, `import _ from 'lodash';
export const Total = ({ values }: { values: number[] }) => <span>{_.sum(values)}</span>;
`),
    ignores: f(C, `import sum from 'lodash/sum';
export const Total = ({ values }: { values: number[] }) => <span>{sum(values)}</span>;
`),
  },
  {
    ruleIds: [30005], name: 'UXG-06 priority on every mapped image',
    detects: f(C, `import Image from 'next/image';
export const Gallery = ({ items }: { items: { src: string }[] }) => (
  <div>{items.map((it) => <Image key={it.src} src={it.src} alt="" width={300} height={200} priority />)}</div>
);
`),
    ignores: f(C, `import Image from 'next/image';
export const Gallery = ({ items }: { items: { src: string }[] }) => (
  <div>{items.map((it, i) => <Image key={it.src} src={it.src} alt="" width={300} height={200} priority={i === 0} />)}</div>
);
`),
  },
  {
    ruleIds: [30006], name: 'UXG-07 carousel without pause',
    detects: f(C, `'use client';
import { useEffect, useState } from 'react';
export function Hero({ slides }: { slides: string[] }) {
  const [current, setCurrent] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setCurrent((p) => (p + 1) % slides.length), 4000);
    return () => clearInterval(t);
  }, [slides.length]);
  return <img src={slides[current]} alt="" />;
}
`),
    ignores: f(C, `'use client';
import { useEffect, useState } from 'react';
export function Hero({ slides }: { slides: string[] }) {
  const [current, setCurrent] = useState(0);
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => setCurrent((p) => (p + 1) % slides.length), 4000);
    return () => clearInterval(t);
  }, [paused, slides.length]);
  return <div><img src={slides[current]} alt="" /><button onClick={() => setPaused((x) => !x)}>Pause</button></div>;
}
`),
  },
  {
    ruleIds: [30007], name: 'UXG-08 button nested inside a link',
    detects: f(C, `export const Card = ({ href, onDelete }: { href: string; onDelete: () => void }) => (
  <a href={href} className="card">
    <h3>Project</h3>
    <button onClick={onDelete}>Delete</button>
  </a>
);
`),
    ignores: f(C, `import Link from 'next/link';
import { Button } from '@/components/ui/button';
export const Card = ({ href, onDelete }: { href: string; onDelete: () => void }) => (
  <div className="card">
    <Button asChild><Link href={href}>Open</Link></Button>
    <button onClick={onDelete}>Delete</button>
  </div>
);
`),
  },
  {
    ruleIds: [30009], name: 'UXG-10 hover-only tooltip',
    detects: f(C, `'use client';
import { useState } from 'react';
export function Hint() {
  const [open, setOpen] = useState(false);
  return <span onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>?{open && <div role="tooltip">Help</div>}</span>;
}
`),
    ignores: f(C, `'use client';
import { useState } from 'react';
export function Hint() {
  const [open, setOpen] = useState(false);
  return <span tabIndex={0} onMouseEnter={() => setOpen(true)} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}>?{open && <div role="tooltip">Help</div>}</span>;
}
`),
  },
  {
    ruleIds: [30009], name: 'UXG-10 hover pause with onFocus after an arrow onMouseLeave',
    detects: f(C, `export function Panel() {
  const [paused, setPaused] = useState(false);
  return <div onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}>{paused ? 'Paused' : 'Playing'}</div>;
}
`),
    ignores: f(C, `export function Panel() {
  const [paused, setPaused] = useState(false);
  return <div onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} onFocus={() => setPaused(true)} onBlur={() => setPaused(false)}>{paused ? 'Paused' : 'Playing'}</div>;
}
`),
  },
  {
    ruleIds: [30012], name: 'UXG-13 list fetched in useEffect with no loading, error or empty state',
    detects: f('components/Invoices.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Invoices() {
  const [invoices, setInvoices] = useState<{ id: string; total: number }[]>([]);
  useEffect(() => {
    fetch('/api/invoices').then((r) => r.json()).then(setInvoices);
  }, []);
  return <ul>{invoices.map((inv) => <li key={inv.id}>{inv.total}</li>)}</ul>;
}
`),
    ignores: f('components/Invoices.tsx', `'use client';
import { useEffect, useState } from 'react';
export function Invoices() {
  const [invoices, setInvoices] = useState<{ id: string; total: number }[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    fetch('/api/invoices').then((r) => r.json()).then(setInvoices).catch(() => setFailed(true));
  }, []);
  if (failed) return <p>Could not load invoices. <button onClick={() => location.reload()}>Retry</button></p>;
  if (!invoices) return <InvoiceSkeleton />;
  if (invoices.length === 0) return <p>No invoices yet. Create your first one.</p>;
  return <ul>{invoices.map((inv) => <li key={inv.id}>{inv.total}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [30010], name: 'UXG-11 Intl formatter per row',
    detects: f(C, `export const Prices = ({ rows }: { rows: { id: string; v: number }[] }) => (
  <ul>{rows.map((r) => <li key={r.id}>{new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(r.v)}</li>)}</ul>
);
`),
    ignores: f(C, `const usd = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });
export const Prices = ({ rows }: { rows: { id: string; v: number }[] }) => (
  <ul>{rows.map((r) => <li key={r.id}>{usd.format(r.v)}</li>)}</ul>
);
`),
  },
  {
    ruleIds: [30011], name: 'UXG-12 stack trace rendered',
    detects: f('app/error.tsx', `'use client';
export default function ErrorPage({ error }: { error: Error }) {
  return <pre>{error.stack}</pre>;
}
`),
    ignores: f('app/error.tsx', `'use client';
export default function ErrorPage({ error, reset }: { error: Error; reset: () => void }) {
  return <div><p>Something went wrong.</p><button onClick={reset}>Try again</button></div>;
}
`),
  },
];
