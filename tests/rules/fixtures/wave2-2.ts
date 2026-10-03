import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// ─── UI interaction (lib/rules/interaction-rules.ts) ────────────────────────
const INTERACTION: RuleCase[] = [
  {
    ruleIds: [1201, 1202, 1203], name: 'UI-INTERACT-01/02/03 hand-rolled modal: no backdrop close, no Escape, no focus trap',
    detects: f('components/invite-modal.tsx', `'use client';
export function InviteModal({ open, onClose, onInvite }: InviteModalProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div role="dialog" aria-modal="true" className="w-full max-w-md rounded-lg bg-white p-6">
        <h2 className="text-lg font-semibold">Invite teammate</h2>
        <input name="name" placeholder="Name" />
        <input name="email" type="email" placeholder="Email" />
        <input name="team" placeholder="Team" />
        <button onClick={onClose}>Cancel</button>
        <button onClick={onInvite}>Send invite</button>
      </div>
    </div>
  );
}
`),
    ignores: f('components/invite-modal.tsx', `'use client';
import { useEffect } from 'react';
import FocusTrap from 'focus-trap-react';
export function InviteModal({ open, onClose, onInvite }: InviteModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <FocusTrap>
        <div role="dialog" aria-modal="true" className="w-full max-w-md rounded-lg bg-white p-6">
          <h2 className="text-lg font-semibold">Invite teammate</h2>
          <input name="name" placeholder="Name" />
          <input name="email" type="email" placeholder="Email" />
          <input name="team" placeholder="Team" />
          <button onClick={onClose}>Cancel</button>
          <button onClick={onInvite}>Send invite</button>
        </div>
      </FocusTrap>
    </div>
  );
}
`)
  },
  {
    ruleIds: [1201, 1202, 1203], name: 'UI-INTERACT-01/02/03 stay quiet on the shadcn/Radix dialog primitive',
    detects: f('components/invite-modal.tsx', `export function InviteModal({ onClose }: Props) {
  return (
    <div className="fixed inset-0 bg-black/50">
      <div role="dialog" className="rounded bg-white p-6">
        <input name="a" /><input name="b" /><input name="c" />
        <button onClick={onClose}>Close</button>
      </div>
    </div>
  );
}
`),
    ignores: f('components/ui/dialog.tsx', `'use client';
import * as DialogPrimitive from '@radix-ui/react-dialog';
export const DialogOverlay = (props: DialogPrimitive.DialogOverlayProps) => (
  <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/80" {...props} />
);
export const DialogContent = ({ children }: { children: React.ReactNode }) => (
  <DialogPrimitive.Portal>
    <DialogOverlay />
    <DialogPrimitive.Content role="dialog" className="fixed left-1/2 top-1/2 z-50">{children}</DialogPrimitive.Content>
  </DialogPrimitive.Portal>
);
`)
  },
  {
    ruleIds: [1204], name: 'UI-INTERACT-04 autoFocus on a settings form field',
    detects: f('app/settings/profile-form.tsx', `export function ProfileForm({ user }: { user: User }) {
  return (
    <form action={updateProfile}>
      <input name="displayName" defaultValue={user.name} autoFocus />
      <textarea name="bio" defaultValue={user.bio} />
      <button type="submit">Save</button>
    </form>
  );
}
`),
    ignores: f('app/settings/profile-form.tsx', `export function ProfileForm({ user }: { user: User }) {
  return (
    <form action={updateProfile}>
      <input name="displayName" defaultValue={user.name} />
      <textarea name="bio" defaultValue={user.bio} />
      <button type="submit">Save</button>
    </form>
  );
}
`)
  },
  {
    ruleIds: [1205], name: 'UI-INTERACT-05 z-[9999] escalation',
    detects: f('components/announcement-bar.tsx', `export function AnnouncementBar({ text }: { text: string }) {
  return <div className="sticky top-0 z-[9999] bg-indigo-600 px-4 py-2 text-white">{text}</div>;
}
`),
    ignores: f('components/announcement-bar.tsx', `export function AnnouncementBar({ text }: { text: string }) {
  return <div className="sticky top-0 z-40 bg-indigo-600 px-4 py-2 text-white">{text}</div>;
}
`)
  },
  {
    ruleIds: [1206], name: 'UI-INTERACT-06 button swaps label for spinner without a fixed min width',
    detects: f('components/save-button.tsx', `export function SaveButton({ isPending }: { isPending: boolean }) {
  return (
    <button type="submit" className="rounded bg-black px-4 py-2 text-white" disabled={isPending}>
      {isPending ? <Spinner /> : 'Save changes'}
    </button>
  );
}
`),
    ignores: f('components/save-button.tsx', `export function SaveButton({ isPending }: { isPending: boolean }) {
  return (
    <button type="submit" className="min-w-32 rounded bg-black px-4 py-2 text-white" disabled={isPending}>
      {isPending ? <Spinner /> : 'Save changes'}
    </button>
  );
}
`)
  },
  {
    ruleIds: [1207], name: 'UI-INTERACT-07 w-screen section overflows next to the scrollbar',
    detects: f('components/hero.tsx', `export function Hero() {
  return <section className="w-screen bg-slate-900 py-24 text-white"><h1>Ship faster</h1></section>;
}
`),
    ignores: f('components/hero.tsx', `export function Hero() {
  return <section className="w-full bg-slate-900 py-24 text-white"><h1>Ship faster</h1></section>;
}
`)
  },
  {
    ruleIds: [1208], name: 'UI-INTERACT-08 typeof window branch during render',
    detects: f('components/theme-label.tsx', `export function ThemeLabel() {
  const theme = typeof window !== 'undefined' ? localStorage.getItem('theme') : 'light';
  return <span className="text-xs">{theme}</span>;
}
`),
    ignores: f('components/theme-label.tsx', `'use client';
import { useEffect, useState } from 'react';
export function ThemeLabel() {
  const [theme, setTheme] = useState('light');
  useEffect(() => { setTheme(localStorage.getItem('theme') ?? 'light'); }, []);
  return <span className="text-xs">{theme}</span>;
}
`)
  },
  {
    ruleIds: [1210], name: 'UI-INTERACT-10 body scroll lock without scrollbar compensation',
    detects: f('components/sheet.tsx', `'use client';
import { useEffect } from 'react';
export function useLockBody() {
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);
}
`),
    ignores: f('components/sheet.tsx', `'use client';
import { useEffect } from 'react';
export function useLockBody() {
  useEffect(() => {
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.paddingRight = scrollbarWidth + 'px';
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; document.body.style.paddingRight = ''; };
  }, []);
}
`)
  },
  {
    ruleIds: [1211], name: 'UI-INTERACT-11 submit button stays enabled while the mutation runs',
    detects: f('app/projects/new/project-form.tsx', `'use client';
export function ProjectForm() {
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    await createProject(new FormData(e.currentTarget));
  }
  return (
    <form onSubmit={onSubmit}>
      <input name="name" required />
      <button type="submit">Create project</button>
    </form>
  );
}
`),
    ignores: f('app/projects/new/project-form.tsx', `'use client';
import { useTransition } from 'react';
export function ProjectForm() {
  const [isPending, startTransition] = useTransition();
  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    startTransition(() => createProject(data));
  }
  return (
    <form onSubmit={onSubmit}>
      <input name="name" required />
      <button type="submit" disabled={isPending}>Create project</button>
    </form>
  );
}
`)
  },
  {
    ruleIds: [1212], name: 'UI-INTERACT-12 custom accordion trigger without aria-expanded',
    detects: f('components/faq-accordion.tsx', `'use client';
import { useState } from 'react';
export function FaqAccordion({ items }: { items: { q: string; a: string }[] }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="accordion divide-y">
      {items.map((item, i) => (
        <div key={item.q}>
          <button className="w-full py-3 text-left" onClick={() => setOpen(open === i ? null : i)}>{item.q}</button>
          {open === i && <p className="pb-3">{item.a}</p>}
        </div>
      ))}
    </div>
  );
}
`),
    ignores: f('components/faq-accordion.tsx', `'use client';
import { useState } from 'react';
export function FaqAccordion({ items }: { items: { q: string; a: string }[] }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="accordion divide-y">
      {items.map((item, i) => (
        <div key={item.q}>
          <button className="w-full py-3 text-left" aria-expanded={open === i} onClick={() => setOpen(open === i ? null : i)}>{item.q}</button>
          {open === i && <p className="pb-3">{item.a}</p>}
        </div>
      ))}
    </div>
  );
}
`)
  },
  {
    ruleIds: [1214], name: 'UI-INTERACT-14 code editor textarea captures Tab with no Escape release',
    detects: f('components/snippet-editor.tsx', `'use client';
export function SnippetEditor({ code, setCode }: EditorProps) {
  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') { e.preventDefault(); setCode(code + '  '); }
  };
  return <textarea className="font-mono" value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={onKeyDown} />;
}
`),
    ignores: f('components/snippet-editor.tsx', `'use client';
import { useRef } from 'react';
export function SnippetEditor({ code, setCode }: EditorProps) {
  const trapTab = useRef(true);
  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Escape') { trapTab.current = false; return; }
    if (e.key === 'Tab' && trapTab.current) { e.preventDefault(); setCode(code + '  '); }
  };
  return <textarea className="font-mono" value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={onKeyDown} onFocus={() => { trapTab.current = true; }} />;
}
`)
  },
  {
    ruleIds: [1216], name: 'UI-INTERACT-16 custom dropdown never closes on outside click',
    detects: f('components/user-menu-dropdown.tsx', `'use client';
import { useState } from 'react';
export function UserMenuDropdown({ user }: { user: User }) {
  const [isOpen, setIsOpen] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setIsOpen(!isOpen)}>{user.name}</button>
      {isOpen && (
        <ul className="absolute right-0 mt-2 w-48 rounded border bg-white">
          <li><a href="/settings">Settings</a></li>
          <li><a href="/logout">Log out</a></li>
        </ul>
      )}
    </div>
  );
}
`),
    ignores: f('components/user-menu-dropdown.tsx', `'use client';
import { useEffect, useRef, useState } from 'react';
export function UserMenuDropdown({ user }: { user: User }) {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onPointer = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setIsOpen(false); };
    document.addEventListener('mousedown', onPointer);
    return () => document.removeEventListener('mousedown', onPointer);
  }, []);
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setIsOpen(!isOpen)}>{user.name}</button>
      {isOpen && (
        <ul className="absolute right-0 mt-2 w-48 rounded border bg-white">
          <li><a href="/settings">Settings</a></li>
          <li><a href="/logout">Log out</a></li>
        </ul>
      )}
    </div>
  );
}
`)
  },
  {
    ruleIds: [1220, 1222], name: 'UI-INTERACT-20/22 custom toast: no live region, dismissed after 2s',
    detects: f('components/toast.tsx', `'use client';
import { useEffect } from 'react';
export function Toast({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  useEffect(() => {
    const id = setTimeout(onDismiss, 2000);
    return () => clearTimeout(id);
  }, [onDismiss]);
  return <div className="fixed bottom-4 right-4 rounded bg-slate-900 px-4 py-3 text-white">{message}</div>;
}
`),
    ignores: f('components/toast.tsx', `'use client';
import { useEffect } from 'react';
export function Toast({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  useEffect(() => {
    const id = setTimeout(onDismiss, 6000);
    return () => clearTimeout(id);
  }, [onDismiss]);
  return <div role="status" aria-live="polite" className="fixed bottom-4 right-4 rounded bg-slate-900 px-4 py-3 text-white">{message}</div>;
}
`)
  },
  {
    ruleIds: [1220], name: 'UI-INTERACT-20 stays quiet on a sonner Toaster wrapper',
    detects: f('components/toast.tsx', `export function Toast({ message }: { message: string }) {
  return <div className="rounded bg-slate-900 px-4 py-3 text-white">{message}</div>;
}
`),
    ignores: f('components/toast.tsx', `'use client';
import { Toaster as Sonner } from 'sonner';
export function Toaster() {
  return <Sonner position="bottom-right" richColors />;
}
`)
  },
  {
    ruleIds: [1221], name: 'UI-INTERACT-21 copy button with no confirmation',
    detects: f('components/share-link.tsx', `'use client';
export function ShareLink({ url }: { url: string }) {
  return <button onClick={() => navigator.clipboard.writeText(url)}>Copy link</button>;
}
`),
    ignores: f('components/share-link.tsx', `'use client';
import { useState } from 'react';
export function ShareLink({ url }: { url: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 4000); };
  return <button onClick={copy}>{copied ? 'Link copied' : 'Copy link'}</button>;
}
`)
  },
  {
    ruleIds: [1223], name: 'UI-INTERACT-23 button nested inside a card link',
    detects: f('components/project-card.tsx', `export function ProjectCard({ project, onArchive }: CardProps) {
  return (
    <a href={\`/projects/\${project.id}\`} className="block rounded border p-4">
      <h3>{project.name}</h3>
      <button onClick={(e) => { e.preventDefault(); onArchive(project.id); }}>Archive</button>
    </a>
  );
}
`),
    ignores: f('components/project-card.tsx', `export function ProjectCard({ project, onArchive }: CardProps) {
  return (
    <div className="relative rounded border p-4">
      <a href={\`/projects/\${project.id}\`} className="block"><h3>{project.name}</h3></a>
      <button onClick={() => onArchive(project.id)}>Archive</button>
    </div>
  );
}
`)
  },
  {
    ruleIds: [1225], name: 'UI-INTERACT-25 file input without accept filter',
    detects: f('components/avatar-upload.tsx', `export function AvatarUpload({ onUpload }: Props) {
  return <input type="file" onChange={(e) => onUpload(e.target.files?.[0])} />;
}
`),
    ignores: f('components/avatar-upload.tsx', `export function AvatarUpload({ onUpload }: Props) {
  return <input type="file" onChange={(e) => onUpload(e.target.files?.[0])} accept="image/png,image/jpeg,image/webp" />;
}
`)
  },
  {
    ruleIds: [1229], name: 'UI-INTERACT-29 custom tablist without arrow-key navigation',
    detects: f('components/plan-tabs.tsx', `'use client';
export function PlanTabs({ tabs, active, setActive }: TabsProps) {
  return (
    <div role="tablist" className="flex gap-2">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id} onClick={() => setActive(t.id)}>{t.label}</button>
      ))}
    </div>
  );
}
`),
    ignores: f('components/plan-tabs.tsx', `'use client';
export function PlanTabs({ tabs, active, setActive }: TabsProps) {
  const move = (dir: number) => {
    const i = tabs.findIndex((t) => t.id === active);
    setActive(tabs[(i + dir + tabs.length) % tabs.length].id);
  };
  return (
    <div role="tablist" className="flex gap-2" onKeyDown={(e) => { if (e.key === 'ArrowRight') move(1); if (e.key === 'ArrowLeft') move(-1); }}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id} tabIndex={active === t.id ? 0 : -1} onClick={() => setActive(t.id)}>{t.label}</button>
      ))}
    </div>
  );
}
`)
  },
  {
    ruleIds: [1231], name: 'UI-INTERACT-31 range slider without an accessible name',
    detects: f('components/volume-control.tsx', `export function VolumeControl({ volume, setVolume }: Props) {
  return <input type="range" min={0} max={100} value={volume} onChange={(e) => setVolume(Number(e.target.value))} />;
}
`),
    ignores: f('components/volume-control.tsx', `export function VolumeControl({ volume, setVolume }: Props) {
  return <input type="range" min={0} max={100} value={volume} onChange={(e) => setVolume(Number(e.target.value))} aria-label="Volume" aria-valuetext={\`\${volume}%\`} />;
}
`)
  },
  {
    ruleIds: [1232], name: 'UI-INTERACT-32 hero video autoplays with sound',
    detects: f('components/demo-video.tsx', `export function DemoVideo() {
  return <video src="/demo.mp4" autoPlay loop playsInline className="rounded-xl" />;
}
`),
    ignores: f('components/demo-video.tsx', `export function DemoVideo() {
  return <video src="/demo.mp4" autoPlay muted loop playsInline className="rounded-xl" />;
}
`)
  },
  {
    ruleIds: [1235], name: 'UI-INTERACT-35 checkbox label not associated with its input',
    detects: f('app/login/remember-me.tsx', `export function RememberMe() {
  return (
    <div className="flex items-center gap-2">
      <label className="text-sm">Remember me</label>
      <input type="checkbox" name="remember" />
    </div>
  );
}
`),
    ignores: f('app/login/remember-me.tsx', `export function RememberMe() {
  return (
    <div className="flex items-center gap-2">
      <label htmlFor="remember" className="text-sm">Remember me</label>
      <input type="checkbox" id="remember" name="remember" />
    </div>
  );
}
`)
  },
  {
    ruleIds: [1240], name: 'UI-INTERACT-40 chart with no text alternative',
    detects: f('components/revenue-chart.tsx', `'use client';
import { Bar, BarChart, ResponsiveContainer, XAxis } from 'recharts';
export function RevenueChart({ data }: { data: { month: string; revenue: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data}><XAxis dataKey="month" /><Bar dataKey="revenue" /></BarChart>
    </ResponsiveContainer>
  );
}
`),
    ignores: f('components/revenue-chart.tsx', `'use client';
import { Bar, BarChart, ResponsiveContainer, XAxis } from 'recharts';
export function RevenueChart({ data }: { data: { month: string; revenue: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart accessibilityLayer data={data}><XAxis dataKey="month" /><Bar dataKey="revenue" /></BarChart>
    </ResponsiveContainer>
  );
}
`)
  },
  {
    ruleIds: [1241], name: 'UI-INTERACT-41 dnd-kit board with pointer-only sensors',
    detects: f('components/kanban-board.tsx', `'use client';
import { DndContext, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
export function KanbanBoard({ columns, onDragEnd }: BoardProps) {
  const sensors = useSensors(useSensor(PointerSensor));
  return <DndContext sensors={sensors} onDragEnd={onDragEnd}>{columns.map((c) => <Column key={c.id} column={c} />)}</DndContext>;
}
`),
    ignores: f('components/kanban-board.tsx', `'use client';
import { DndContext, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { sortableKeyboardCoordinates } from '@dnd-kit/sortable';
export function KanbanBoard({ columns, onDragEnd }: BoardProps) {
  const sensors = useSensors(useSensor(PointerSensor), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  return <DndContext sensors={sensors} onDragEnd={onDragEnd}>{columns.map((c) => <Column key={c.id} column={c} />)}</DndContext>;
}
`)
  },
  {
    ruleIds: [1243], name: 'UI-INTERACT-43 controlled input rewrites its value on every keystroke',
    detects: f('components/phone-input.tsx', `'use client';
import { useState } from 'react';
export function PhoneInput() {
  const [value, setValue] = useState('');
  return <input name="phone" value={value} onChange={(e) => setValue(e.target.value.replace(/[^0-9+]/g, ''))} />;
}
`),
    ignores: f('components/phone-input.tsx', `'use client';
import { useState } from 'react';
export function PhoneInput() {
  const [value, setValue] = useState('');
  return <input name="phone" type="tel" inputMode="tel" pattern="[0-9+]*" value={value} onChange={(e) => setValue(e.target.value)} />;
}
`)
  },
  {
    ruleIds: [1244], name: 'UI-INTERACT-44 Next.js viewport disables pinch zoom',
    detects: f('app/layout.tsx', `import type { Viewport } from 'next';
export const viewport: Viewport = { width: 'device-width', initialScale: 1, maximumScale: 1, userScalable: false };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
`),
    ignores: f('app/layout.tsx', `import type { Viewport } from 'next';
export const viewport: Viewport = { width: 'device-width', initialScale: 1 };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
`)
  },
  {
    ruleIds: [1247], name: 'UI-INTERACT-47 count-up animation frame never cancelled on unmount',
    detects: f('components/count-up.tsx', `'use client';
import { useEffect, useState } from 'react';
export function CountUp({ target }: { target: number }) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 1200);
      setValue(Math.round(target * progress));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target]);
  return <span>{value}</span>;
}
`),
    ignores: f('components/count-up.tsx', `'use client';
import { useEffect, useState } from 'react';
export function CountUp({ target }: { target: number }) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    const start = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 1200);
      setValue(Math.round(target * progress));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target]);
  return <span>{value}</span>;
}
`)
  },
];

// ─── Privacy / legal (lib/rules/compliance-rules.ts) ───────────────────────
const COMPLIANCE: RuleCase[] = [
  {
    ruleIds: [2001], name: 'COMPL-01 footer Privacy / Terms links point nowhere',
    detects: f('components/site-footer.tsx', `import Link from 'next/link';
export function SiteFooter() {
  return (
    <footer className="border-t py-8 text-sm">
      <Link href="/pricing">Pricing</Link>
      <a href="#">Privacy Policy</a>
      <a href="#">Terms of Service</a>
    </footer>
  );
}
`),
    ignores: f('components/site-footer.tsx', `import Link from 'next/link';
export function SiteFooter() {
  return (
    <footer className="border-t py-8 text-sm">
      <Link href="/pricing">Pricing</Link>
      <Link href="/privacy">Privacy Policy</Link>
      <Link href="/terms">Terms of Service</Link>
      <a href="#">Back to top</a>
    </footer>
  );
}
`)
  },
  {
    ruleIds: [2003], name: 'COMPL-03 cookie banner offers Accept but no Reject',
    detects: f('components/cookie-banner.tsx', `'use client';
import { useState } from 'react';
export function CookieBanner() {
  const [visible, setVisible] = useState(true);
  const acceptAll = () => { localStorage.setItem('cookie-consent', 'all'); setVisible(false); };
  if (!visible) return null;
  return (
    <div className="fixed inset-x-0 bottom-0 bg-white p-4 shadow">
      <p>We use cookies to improve your experience.</p>
      <button onClick={acceptAll}>Accept all</button>
      <a href="/cookies" className="underline">Manage preferences</a>
    </div>
  );
}
`),
    ignores: f('components/cookie-banner.tsx', `'use client';
import { useState } from 'react';
export function CookieBanner() {
  const [visible, setVisible] = useState(true);
  const choose = (value: 'all' | 'essential') => { localStorage.setItem('cookie-consent', value); setVisible(false); };
  if (!visible) return null;
  return (
    <div className="fixed inset-x-0 bottom-0 bg-white p-4 shadow">
      <p>We use cookies to improve your experience.</p>
      <button onClick={() => choose('essential')}>Reject all</button>
      <button onClick={() => choose('all')}>Accept all</button>
    </div>
  );
}
`)
  },
  {
    ruleIds: [2005], name: 'COMPL-05 email address pushed into the URL query string',
    detects: f('app/signup/signup-form.tsx', `'use client';
import { useRouter } from 'next/navigation';
export function SignupForm() {
  const router = useRouter();
  async function onSubmit(formData: FormData) {
    const email = String(formData.get('email'));
    await signUp(email, String(formData.get('password')));
    router.push(\`/verify-email?email=\${email}\`);
  }
  return <form action={onSubmit}>{/* fields */}</form>;
}
`),
    ignores: f('app/signup/signup-form.tsx', `'use client';
import { useRouter } from 'next/navigation';
export function SignupForm() {
  const router = useRouter();
  async function onSubmit(formData: FormData) {
    const email = String(formData.get('email'));
    await signUp(email, String(formData.get('password')));
    sessionStorage.setItem('pendingVerification', email);
    router.push('/verify-email');
  }
  return <form action={onSubmit}>{/* fields */}</form>;
}
`)
  },
  {
    ruleIds: [2006], name: 'COMPL-06 raw card number / CVC inputs in the app DOM',
    detects: f('components/checkout-form.tsx', `'use client';
export function CheckoutForm({ onPay }: { onPay: (data: FormData) => void }) {
  return (
    <form action={onPay}>
      <input name="card_number" inputMode="numeric" placeholder="1234 1234 1234 1234" />
      <input name="cvc" inputMode="numeric" placeholder="CVC" />
      <button type="submit">Pay</button>
    </form>
  );
}
`),
    ignores: f('components/checkout-form.tsx', `'use client';
import { PaymentElement, useElements, useStripe } from '@stripe/react-stripe-js';
export function CheckoutForm() {
  const stripe = useStripe();
  const elements = useElements();
  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!stripe || !elements) return;
    await stripe.confirmPayment({ elements, confirmParams: { return_url: window.location.origin + '/thanks' } });
  }
  return (
    <form onSubmit={onSubmit}>
      <PaymentElement />
      <button type="submit">Pay</button>
    </form>
  );
}
`)
  },
  {
    ruleIds: [2010], name: 'COMPL-10 consent cookie kept for two years',
    detects: f('app/api/consent/route.ts', `import { cookies } from 'next/headers';
export async function POST(req: Request) {
  const { choice } = await req.json();
  (await cookies()).set('cookie_consent', choice, { maxAge: 60 * 60 * 24 * 730, sameSite: 'lax', path: '/' });
  return Response.json({ ok: true });
}
`),
    ignores: [
      { path: 'app/api/consent/route.ts', content: `import { cookies } from 'next/headers';
export async function POST(req: Request) {
  const { choice } = await req.json();
  (await cookies()).set('cookie_consent', choice, { maxAge: 60 * 60 * 24 * 365, sameSite: 'lax', path: '/' });
  return Response.json({ ok: true });
}
` },
      // Express maxAge is in milliseconds: one year expressed in ms is within the cap.
      { path: 'src/routes/consent.ts', content: `router.post('/consent', (req, res) => {
  res.cookie('consent', req.body.choice, { maxAge: 365 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ ok: true });
});
` }
    ]
  },
  {
    ruleIds: [2014], name: 'COMPL-14 temporary password sent in the welcome email',
    detects: f('lib/email/send-welcome.ts', `import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);
export async function sendWelcomeEmail(user: { email: string }, tempPassword: string) {
  await resend.emails.send({
    from: 'Acme <hello@acme.dev>',
    to: user.email,
    subject: 'Your new account',
    react: WelcomeEmail({ email: user.email, password: tempPassword }),
  });
}
`),
    ignores: f('lib/email/send-welcome.ts', `import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);
export async function sendWelcomeEmail(user: { email: string }, setPasswordUrl: string) {
  await resend.emails.send({
    from: 'Acme <hello@acme.dev>',
    to: user.email,
    subject: 'Your new account',
    react: WelcomeEmail({ email: user.email, setPasswordUrl }),
  });
}
`)
  },
];

// ─── LLM cost (lib/rules/llm-cost-governance-rules.ts) ─────────────────────
const LLM_COST: RuleCase[] = [
  {
    ruleIds: [8073], name: 'LLM-COST-03 one embeddings request per chunk',
    detects: f('lib/ai/index-docs.ts', `import OpenAI from 'openai';
const openai = new OpenAI();
export async function indexDocument(docId: string, chunks: string[]) {
  for (const chunk of chunks) {
    const res = await openai.embeddings.create({ model: 'text-embedding-3-small', input: chunk });
    await db.insert(embeddings).values({ docId, content: chunk, embedding: res.data[0].embedding });
  }
}
`),
    ignores: f('lib/ai/index-docs.ts', `import OpenAI from 'openai';
const openai = new OpenAI();
export async function indexDocument(docId: string, chunks: string[]) {
  const res = await openai.embeddings.create({ model: 'text-embedding-3-small', input: chunks });
  await db.insert(embeddings).values(res.data.map((d, i) => ({ docId, content: chunks[i], embedding: d.embedding })));
}
`)
  },
  {
    ruleIds: [8076], name: 'LLM-COST-06 retry loop hammers the provider with no delay',
    detects: f('lib/ai/summarize.ts', `import OpenAI from 'openai';
const openai = new OpenAI();
export async function summarize(text: string) {
  let attempts = 0;
  while (attempts < 3) {
    try {
      const res = await openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 300, messages: [{ role: 'user', content: text }] });
      return res.choices[0].message.content;
    } catch (err) {
      attempts++;
    }
  }
  throw new Error('summarize failed');
}
`),
    ignores: f('lib/ai/summarize.ts', `import OpenAI from 'openai';
const openai = new OpenAI();
export async function summarize(text: string) {
  let attempts = 0;
  while (attempts < 3) {
    try {
      const res = await openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 300, messages: [{ role: 'user', content: text }] });
      return res.choices[0].message.content;
    } catch (err) {
      attempts++;
      await new Promise((r) => setTimeout(r, 2 ** attempts * 500 + Math.random() * 250));
    }
  }
  throw new Error('summarize failed');
}
`)
  },
];

// ─── AI comment hygiene (lib/rules/ai-comment-rules.ts) ────────────────────
const AI_COMMENT: RuleCase[] = [
  {
    ruleIds: [27221], name: 'CLICHE-AI-COMMENT-01 pasted chat transcript header left in source',
    detects: f('lib/billing/proration.ts', `// Generated by ChatGPT - model output: proration helper
export function prorate(amountCents: number, daysUsed: number, daysInPeriod: number) {
  return Math.round(amountCents * (1 - daysUsed / daysInPeriod));
}
`),
    ignores: f('lib/billing/proration.ts', `// Credit for the unused part of the billing period, in cents.
export function prorate(amountCents: number, daysUsed: number, daysInPeriod: number) {
  return Math.round(amountCents * (1 - daysUsed / daysInPeriod));
}
`)
  },
  {
    ruleIds: [27223], name: 'CLICHE-AI-COMMENT-03 placeholder shipped instead of the implementation',
    detects: f('lib/auth/verify-email.ts', `export async function verifyEmailToken(token: string) {
  // TODO: implement token signature and expiry check
  return { valid: true, userId: token.split('.')[0] };
}
`),
    ignores: f('lib/auth/verify-email.ts', `import { jwtVerify } from 'jose';
export async function verifyEmailToken(token: string) {
  const { payload } = await jwtVerify(token, new TextEncoder().encode(process.env.EMAIL_TOKEN_SECRET!), { maxTokenAge: '1h' });
  return { valid: true, userId: String(payload.sub) };
}
`)
  },
];

// ─── Data stores, brokers, search (pgvector / message-broker / search-engine) ──
const DATA_INFRA: RuleCase[] = [
  {
    ruleIds: [10305], name: 'PG-05 batch row lock without ORDER BY',
    detects: f('lib/billing/reserve-seats.ts', `export async function reserveSeats(client: PoolClient, seatIds: string[]) {
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT id, status FROM seats WHERE id = ANY($1) FOR UPDATE', [seatIds]);
  await client.query("UPDATE seats SET status = 'held' WHERE id = ANY($1)", [seatIds]);
  await client.query('COMMIT');
  return rows;
}
`),
    ignores: f('lib/billing/reserve-seats.ts', `export async function reserveSeats(client: PoolClient, seatIds: string[]) {
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT id, status FROM seats WHERE id = ANY($1) ORDER BY id FOR UPDATE', [seatIds]);
  await client.query("UPDATE seats SET status = 'held' WHERE id = ANY($1)", [seatIds]);
  const job = await client.query('SELECT id FROM jobs WHERE status = $1 LIMIT 1 FOR UPDATE SKIP LOCKED', ['queued']);
  const account = await client.query('SELECT balance FROM accounts WHERE id = $1 FOR UPDATE', [rows[0]?.id]);
  await client.query('COMMIT');
  return { rows, job, account };
}
`)
  },
  {
    ruleIds: [12502], name: 'MQ-02 consumer with unlimited prefetch',
    detects: f('src/workers/email-worker.ts', `export async function startEmailWorker(conn: amqp.Connection) {
  const channel = await conn.createChannel();
  await channel.assertQueue('emails', { durable: true });
  channel.prefetch(0);
  channel.consume('emails', async (msg) => { if (msg) { await sendEmail(JSON.parse(msg.content.toString())); channel.ack(msg); } });
}
`),
    ignores: f('src/workers/email-worker.ts', `export async function startEmailWorker(conn: amqp.Connection) {
  const channel = await conn.createChannel();
  await channel.assertQueue('emails', { durable: true });
  channel.prefetch(20);
  channel.consume('emails', async (msg) => { if (msg) { await sendEmail(JSON.parse(msg.content.toString())); channel.ack(msg); } });
}
`)
  },
  {
    ruleIds: [12503], name: 'MQ-03 pika consumer unpickles message bodies',
    detects: f('workers/report_consumer.py', `import pickle
import pika

def on_report(ch, method, properties, body):
    job = pickle.loads(body)
    build_report(job["account_id"], job["period"])
    ch.basic_ack(delivery_tag=method.delivery_tag)

channel = pika.BlockingConnection(pika.URLParameters(AMQP_URL)).channel()
channel.basic_consume(queue="reports", on_message_callback=on_report)
channel.start_consuming()
`),
    ignores: f('workers/report_consumer.py', `import json
import pika
from pydantic import BaseModel

class ReportJob(BaseModel):
    account_id: str
    period: str

def on_report(ch, method, properties, body):
    job = ReportJob.model_validate(json.loads(body))
    build_report(job.account_id, job.period)
    ch.basic_ack(delivery_tag=method.delivery_tag)

channel = pika.BlockingConnection(pika.URLParameters(AMQP_URL)).channel()
channel.basic_consume(queue="reports", on_message_callback=on_report)
channel.start_consuming()
`)
  },
  {
    ruleIds: [12504], name: 'MQ-04 confirm channel whose confirms are ignored',
    detects: f('src/events/publisher.ts', `export async function publishOrderPlaced(conn: amqp.Connection, order: Order) {
  const channel = await conn.createConfirmChannel();
  channel.publish('orders', 'order.placed', Buffer.from(JSON.stringify(order)), { persistent: true });
}
`),
    ignores: f('src/events/publisher.ts', `export async function publishOrderPlaced(conn: amqp.Connection, order: Order) {
  const channel = await conn.createConfirmChannel();
  channel.publish('orders', 'order.placed', Buffer.from(JSON.stringify(order)), { persistent: true });
  await channel.waitForConfirms();
}
`)
  },
  {
    ruleIds: [13002], name: 'SEARCH-02 user term wrapped in a leading wildcard',
    detects: f('lib/search/products.ts', `export async function searchProducts(q: string) {
  return es.search({
    index: 'products',
    query: { wildcard: { name: { value: \`*\${q.toLowerCase()}*\` } } },
  });
}
`),
    ignores: f('lib/search/products.ts', `export async function searchProducts(q: string) {
  return es.search({
    index: 'products',
    query: { match: { 'name.ngram': q.toLowerCase() } },
  });
}
`)
  },
  {
    ruleIds: [13004], name: 'SEARCH-04 fielddata enabled on an analyzed text field',
    detects: f('lib/search/create-index.ts', `export async function createTicketsIndex() {
  await es.indices.create({
    index: 'tickets',
    mappings: {
      properties: {
        subject: { type: 'text', fielddata: true },
        status: { type: 'keyword' },
      },
    },
  });
}
`),
    ignores: f('lib/search/create-index.ts', `export async function createTicketsIndex() {
  await es.indices.create({
    index: 'tickets',
    mappings: {
      properties: {
        subject: { type: 'text', fields: { raw: { type: 'keyword' } } },
        status: { type: 'keyword' },
      },
    },
  });
}
`)
  },
];

// ─── Cloud posture / container hardening (cspm / linux-kernel) ─────────────
const CLOUD: RuleCase[] = [
  {
    ruleIds: [14801], name: 'CSPM-01 uploads bucket writable by anyone',
    detects: f('infra/terraform/storage.tf', `resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read-write"
}
`),
    ignores: f('infra/terraform/storage.tf', `resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`)
  },
  {
    ruleIds: [14802], name: 'CSPM-02 IAM policy allowing every action',
    detects: f('infra/terraform/iam.tf', `resource "aws_iam_role_policy" "worker" {
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
`),
    ignores: f('infra/terraform/iam.tf', `resource "aws_iam_role_policy" "worker" {
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "\${aws_s3_bucket.uploads.arn}/*"
    }, {
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
`)
  },
  {
    ruleIds: [14804], name: 'CSPM-04 SSH open to the internet',
    detects: f('infra/terraform/network.tf', `resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`),
    ignores: f('infra/terraform/network.tf', `resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)
  },
  {
    ruleIds: [14805], name: 'CSPM-05 single-region CloudTrail',
    detects: f('infra/terraform/audit.tf', `resource "aws_cloudtrail" "main" {
  name           = "org-trail"
  s3_bucket_name = aws_s3_bucket.trail.id
  enable_log_file_validation = true
}
`),
    ignores: f('infra/terraform/audit.tf', `resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
`)
  },
  {
    ruleIds: [15702], name: 'KERN-SEC-02 pod opts out of seccomp',
    detects: f('k8s/worker-deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: Unconfined
      containers:
        - name: worker
          image: ghcr.io/acme/worker:1.4.2
`),
    ignores: f('k8s/worker-deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: worker
          image: ghcr.io/acme/worker:1.4.2
`)
  },
  {
    ruleIds: [15704], name: 'KERN-SEC-04 node tuning turns BPF JIT hardening off',
    detects: f('k8s/node-sysctl.yaml', `apiVersion: v1
kind: ConfigMap
metadata:
  name: node-sysctl
data:
  99-tuning.conf: |
    net.core.somaxconn = 4096
    net.core.bpf_jit_harden = 0
`),
    ignores: f('k8s/node-sysctl.yaml', `apiVersion: v1
kind: ConfigMap
metadata:
  name: node-sysctl
data:
  99-tuning.conf: |
    net.core.somaxconn = 4096
    net.core.bpf_jit_harden = 2
`)
  },
  {
    ruleIds: [15705], name: 'KERN-SEC-05 node boot args disable page table isolation',
    detects: f('k8s/talos/controlplane.yaml', `machine:
  install:
    disk: /dev/sda
    extraKernelArgs:
      - console=ttyS0
      - pti=off
`),
    ignores: f('k8s/talos/controlplane.yaml', `machine:
  install:
    disk: /dev/sda
    extraKernelArgs:
      - console=ttyS0
`)
  },
  {
    ruleIds: [15701], name: 'KERN-SEC-01 reports the privileged line, not line 1',
    detects: f('docker-compose.yml', `services:
  app:
    image: app:1.0
    privileged: true
`),
    ignores: f('docker-compose.yml', `services:
  app:
    image: app:1.0
    cap_drop: [ALL]
    read_only: true
`)
  },
];

// ─── Payments / PCI (lib/rules/fintech-compliance-rules.ts) ────────────────
const FINTECH: RuleCase[] = [
  {
    ruleIds: [9701], name: 'FINTECH-01 CVV column in the payments table',
    detects: f('supabase/migrations/20260101_payment_methods.sql', `create table public.payment_methods (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  card_last4 varchar(4) not null,
  cvv varchar(4) not null,
  created_at timestamptz default now()
);
`),
    ignores: f('supabase/migrations/20260101_payment_methods.sql', `create table public.payment_methods (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  stripe_payment_method_id text not null,
  card_last4 varchar(4) not null,
  created_at timestamptz default now()
);
`)
  },
  {
    ruleIds: [9701], name: 'FINTECH-01 stays quiet on a checkout form that only collects the CVC field label',
    detects: f('lib/db/save-card.ts', `export async function saveCard(userId: string, card: CardInput) {
  return db.from('cards').insert({ user_id: userId, number: card.number, cvv: card.cvv });
}
`),
    ignores: f('app/checkout/labels.ts', `export const CHECKOUT_LABELS = { cvv: 'Security code (CVC)', number: 'Card number' };
export const migrationNote = 'db.cards stores the Stripe payment method id only';
`)
  },
  {
    ruleIds: [9702], name: 'FINTECH-02 full card number rendered in the billing page',
    detects: f('app/billing/card-summary.tsx', `export function CardSummary({ card }: { card: SavedCard }) {
  return (
    <div className="rounded border p-4">
      <p className="font-mono">{card.cardNumber}</p>
      <p>Expires {card.expMonth}/{card.expYear}</p>
    </div>
  );
}
`),
    ignores: f('app/billing/card-summary.tsx', `export function CardSummary({ card }: { card: SavedCard }) {
  return (
    <div className="rounded border p-4">
      <p className="font-mono">{maskPan(card.cardNumber)}</p>
      <p>Expires {card.expMonth}/{card.expYear}</p>
    </div>
  );
}
`)
  },
  {
    ruleIds: [9703], name: 'FINTECH-03 immediate charge without an idempotency key',
    detects: f('app/api/orders/pay/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const { orderId, paymentMethodId, customerId, amount } = await req.json();
  const intent = await stripe.paymentIntents.create({
    amount, currency: 'usd', customer: customerId, payment_method: paymentMethodId, confirm: true, off_session: true,
    metadata: { orderId },
  });
  return Response.json({ status: intent.status });
}
`),
    ignores: f('app/api/orders/pay/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const { orderId, paymentMethodId, customerId, amount } = await req.json();
  const intent = await stripe.paymentIntents.create({
    amount, currency: 'usd', customer: customerId, payment_method: paymentMethodId, confirm: true, off_session: true,
    metadata: { orderId },
  }, { idempotencyKey: \`order-\${orderId}-pay\` });
  const draft = await stripe.paymentIntents.create({ amount, currency: 'usd', customer: customerId });
  return Response.json({ status: intent.status, draft: draft.id });
}
`)
  },
  {
    ruleIds: [9705], name: 'FINTECH-05 card number written to the logs',
    detects: f('app/api/cards/route.ts', `export async function POST(req: Request) {
  const { cardNumber, expMonth, expYear } = await req.json();
  console.log('tokenizing card', cardNumber, expMonth, expYear);
  return Response.json(await tokenize({ cardNumber, expMonth, expYear }));
}
`),
    ignores: f('app/api/cards/route.ts', `export async function POST(req: Request) {
  const { cardNumber, expMonth, expYear } = await req.json();
  console.log('tokenizing card ending', String(cardNumber).slice(-4));
  console.info('card added to wallet');
  return Response.json(await tokenize({ cardNumber, expMonth, expYear }));
}
`)
  },
];

// ─── Rust / C (rust-systems / cpp-memory) ─────────────────────────────────
const NATIVE: RuleCase[] = [
  {
    ruleIds: [9601], name: 'RUST-01 unsafe block with no SAFETY comment',
    detects: f('src/buffer.rs', `pub fn first_byte(buf: &[u8]) -> u8 {
    assert!(!buf.is_empty());
    unsafe { *buf.get_unchecked(0) }
}
`),
    ignores: f('src/buffer.rs', `pub fn first_byte(buf: &[u8]) -> u8 {
    assert!(!buf.is_empty());
    // SAFETY: the assert above guarantees index 0 is in bounds.
    unsafe { *buf.get_unchecked(0) }
}
`)
  },
  {
    ruleIds: [9602], name: 'RUST-02 thread::sleep inside an async handler',
    detects: f('src/handlers/retry.rs', `pub async fn fetch_with_retry(client: &reqwest::Client, url: &str) -> reqwest::Result<String> {
    for attempt in 0..3 {
        match client.get(url).send().await {
            Ok(resp) => return resp.text().await,
            Err(_) if attempt < 2 => std::thread::sleep(std::time::Duration::from_millis(500)),
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

pub fn warm_cache() {
    std::thread::sleep(std::time::Duration::from_millis(50));
}
`),
    ignores: f('src/handlers/retry.rs', `pub async fn fetch_with_retry(client: &reqwest::Client, url: &str) -> reqwest::Result<String> {
    for attempt in 0..3 {
        match client.get(url).send().await {
            Ok(resp) => return resp.text().await,
            Err(_) if attempt < 2 => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

pub fn warm_cache() {
    std::thread::sleep(std::time::Duration::from_millis(50));
}
`)
  },
  {
    ruleIds: [9604], name: 'RUST-04 unwrap inside Drop',
    detects: f('src/lockfile.rs', `pub struct LockFile { path: std::path::PathBuf }

impl Drop for LockFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}
`),
    ignores: f('src/lockfile.rs', `pub struct LockFile { path: std::path::PathBuf }

impl Drop for LockFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            eprintln!("failed to remove lock file: {e}");
        }
    }
}

pub fn open(path: &str) -> std::fs::File {
    std::fs::File::open(path).unwrap()
}
`)
  },
  {
    ruleIds: [9605], name: 'RUST-05 SQL built with format!',
    detects: f('src/repo/users.rs', `pub async fn find_user(pool: &PgPool, email: &str) -> sqlx::Result<User> {
    let sql = format!("SELECT id, email FROM users WHERE email = '{}'", email);
    sqlx::query_as::<_, User>(&sql).fetch_one(pool).await
}
`),
    ignores: f('src/repo/users.rs', `pub async fn find_user(pool: &PgPool, email: &str) -> sqlx::Result<User> {
    sqlx::query_as::<_, User>("SELECT id, email FROM users WHERE email = $1").bind(email).fetch_one(pool).await
}
`)
  },
  {
    ruleIds: [10001], name: 'CPP-SEC-01 strcpy of a request field into a fixed buffer',
    detects: f('src/http/headers.c', `#include <string.h>
void set_user_agent(struct request *req, const char *value) {
    char buf[64];
    strcpy(buf, value);
    req->user_agent = strdup(buf);
}
`),
    ignores: f('src/http/headers.c', `#include <stdio.h>
#include <string.h>
void set_user_agent(struct request *req, const char *value) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", value);
    req->user_agent = strdup(buf);
}
`)
  },
  {
    ruleIds: [10002], name: 'CPP-SEC-02 list node used after free',
    detects: f('src/list.c', `#include <stdlib.h>
void list_free(struct node *head) {
    struct node *node = head;
    while (node) {
        free(node);
        node = node->next;
    }
}
`),
    ignores: f('src/list.c', `#include <stdlib.h>
void list_free(struct node *head) {
    struct node *node = head;
    while (node) {
        struct node *next = node->next;
        free(node);
        node = next;
    }
}
`)
  },
  {
    ruleIds: [10003], name: 'CPP-SEC-03 buffer freed again on the error path',
    detects: f('src/parser.c', `#include <stdlib.h>
int parse_config(const char *path) {
    char *buf = read_file(path);
    if (!validate(buf)) {
        free(buf);
        log_error("invalid config");
    }
    free(buf);
    return 0;
}
`),
    ignores: f('src/parser.c', `#include <stdlib.h>
int parse_config(const char *path) {
    char *buf = read_file(path);
    if (!validate(buf)) {
        free(buf);
        buf = NULL;
        log_error("invalid config");
    }
    free(buf);
    return 0;
}
`)
  },
  {
    ruleIds: [10004], name: 'CPP-SEC-04 malloc(count * size) without overflow check',
    detects: f('src/image.c', `#include <stdlib.h>
pixel_t *alloc_pixels(size_t width, size_t height) {
    size_t count = width * height;
    return malloc(count * stride);
}
`),
    ignores: f('src/image.c', `#include <stdlib.h>
pixel_t *alloc_pixels(size_t width, size_t height) {
    size_t count = width * height;
    return calloc(count, stride);
}
`)
  },
];

export const CASES: RuleCase[] = [...INTERACTION, ...COMPLIANCE, ...LLM_COST, ...AI_COMMENT, ...DATA_INFRA, ...CLOUD, ...FINTECH, ...NATIVE];
