import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28601], name: 'A11Y-01 img without alt',
    detects: f('components/team-card.tsx', `export function TeamCard({ member }: { member: Member }) {
  return (
    <div className="flex items-center gap-3">
      <img src={member.avatarUrl} className="h-10 w-10 rounded-full" />
      <p>{member.name}</p>
    </div>
  );
}
`),
    ignores: f('components/team-card.tsx', `export function TeamCard({ member }: { member: Member }) {
  return (
    <div className="flex items-center gap-3">
      <img src={member.avatarUrl} alt={member.name} className="h-10 w-10 rounded-full" />
      <p>{member.name}</p>
    </div>
  );
}
`)
  },
  {
    ruleIds: [28602], name: 'A11Y-02 icon-only close button without accessible name',
    detects: f('components/settings-dialog.tsx', `import { X } from 'lucide-react';
export function DialogHeader({ onClose }: { onClose: () => void }) {
  return (
    <div className="flex justify-between">
      <h2>Settings</h2>
      <button onClick={onClose} className="rounded p-1.5 hover:bg-white/10">
        <X size={18} />
      </button>
    </div>
  );
}
`),
    ignores: f('components/settings-dialog.tsx', `import { X } from 'lucide-react';
export function DialogHeader({ onClose }: { onClose: () => void }) {
  return (
    <div className="flex justify-between">
      <h2>Settings</h2>
      <Button variant="ghost" size="icon" onClick={onClose}>
        <X className="h-4 w-4" />
        <span className="sr-only">Close</span>
      </Button>
      <button onClick={onClose} aria-label="Close settings" className="rounded p-1.5 hover:bg-white/10">
        <X size={18} aria-hidden="true" />
      </button>
    </div>
  );
}
`)
  },
  {
    ruleIds: [28603], name: 'A11Y-03 positive tabIndex',
    detects: f('app/signup/form.tsx', `export function SignupForm() {
  return (
    <form>
      <input id="email" name="email" type="email" tabIndex={1} />
      <button type="submit" tabIndex={2}>Sign up</button>
    </form>
  );
}
`),
    ignores: f('app/signup/form.tsx', `export function SignupForm() {
  return (
    <form>
      <input id="email" name="email" type="email" />
      <button type="submit">Sign up</button>
    </form>
  );
}
`)
  },
  {
    ruleIds: [28604], name: 'A11Y-04 aria-hidden on focusable element',
    detects: f('components/carousel.tsx', `export function CarouselNav({ next }: { next: () => void }) {
  return <button type="button" aria-hidden="true" onClick={next}>Next slide</button>;
}
`),
    ignores: f('components/carousel.tsx', `export function CarouselNav({ next }: { next: () => void }) {
  return <button type="button" onClick={next}>Next slide</button>;
}
`)
  },
  {
    ruleIds: [28605], name: 'A11Y-05 misspelled aria-labeledby',
    detects: f('components/pricing-table.tsx', `export function PricingTable() {
  return (
    <section aria-labeledby="pricing-title">
      <h2 id="pricing-title">Pricing</h2>
    </section>
  );
}
`),
    ignores: f('components/pricing-table.tsx', `export function PricingTable() {
  return (
    <section aria-labelledby="pricing-title">
      <h2 id="pricing-title">Pricing</h2>
    </section>
  );
}
`)
  },
  {
    ruleIds: [28606], name: 'A11Y-06 invalid ARIA role value',
    detects: f('components/sidebar.tsx', `export function Sidebar({ children }: { children: React.ReactNode }) {
  return <div role="sidebar" className="w-64 border-r">{children}</div>;
}
`),
    ignores: f('components/sidebar.tsx', `export function Sidebar({ children }: { children: React.ReactNode }) {
  return <aside className="w-64 border-r">{children}</aside>;
}
`)
  },
  {
    ruleIds: [28607], name: 'A11Y-07 anchor with href="#" used as button',
    detects: f('components/account-menu.tsx', `export function AccountMenu({ onSignOut }: { onSignOut: () => void }) {
  return (
    <a href="#" onClick={(e) => { e.preventDefault(); onSignOut(); }} className="text-sm">
      Sign out
    </a>
  );
}
`),
    ignores: f('components/account-menu.tsx', `export function AccountMenu({ onSignOut }: { onSignOut: () => void }) {
  return (
    <button type="button" onClick={onSignOut} className="text-sm">
      Sign out
    </button>
  );
}
`)
  },
  {
    ruleIds: [28608], name: 'A11Y-08 iframe without title',
    detects: f('app/product-tour/page.tsx', `export default function ProductTourPage() {
  return <iframe src="https://www.youtube.com/embed/abc123" className="aspect-video w-full" allowFullScreen />;
}
`),
    ignores: f('app/product-tour/page.tsx', `export default function ProductTourPage() {
  return <iframe src="https://www.youtube.com/embed/abc123" title="Product demo video" className="aspect-video w-full" allowFullScreen />;
}
`)
  },
  {
    ruleIds: [28609], name: 'A11Y-09 password field with autocomplete off',
    detects: f('app/login/login-form.tsx', `export function LoginForm() {
  return (
    <form action={login}>
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" autoComplete="off" required />
    </form>
  );
}
`),
    ignores: f('app/login/login-form.tsx', `export function LoginForm() {
  return (
    <form action={login}>
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" autoComplete="current-password" required />
    </form>
  );
}
`)
  },
  {
    ruleIds: [28610], name: 'A11Y-10 paste blocked on confirm field',
    detects: f('app/signup/confirm-email.tsx', `export function ConfirmEmail() {
  return (
    <input
      id="confirm-email"
      type="email"
      onPaste={(e) => e.preventDefault()}
    />
  );
}
`),
    ignores: f('app/signup/confirm-email.tsx', `export function ConfirmEmail() {
  return (
    <input
      id="confirm-email"
      type="email"
      autoComplete="email"
    />
  );
}
`)
  },
  {
    ruleIds: [28611], name: 'A11Y-11 marquee element',
    detects: f('public/announcement.html', `<div class="banner">
  <marquee>Black Friday: 50% off all plans</marquee>
</div>
`),
    ignores: f('public/announcement.html', `<div class="banner">
  <p>Black Friday: 50% off all plans</p>
</div>
`)
  },
  {
    ruleIds: [28612], name: 'A11Y-12 label not associated with its input',
    detects: f('components/profile-form.tsx', `export function ProfileForm() {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium">Display name</label>
      <input id="display-name" name="displayName" className="border px-2" />
    </div>
  );
}
`),
    ignores: f('components/profile-form.tsx', `export function ProfileForm() {
  return (
    <div className="grid gap-2">
      <label htmlFor="display-name" className="text-sm font-medium">Display name</label>
      <input id="display-name" name="displayName" className="border px-2" />
    </div>
  );
}
`)
  },
  {
    ruleIds: [28614], name: 'A11Y-14 role=button without tabIndex',
    detects: f('components/plan-picker.tsx', `export function PlanOption({ onSelect }: { onSelect: () => void }) {
  return (
    <div role="button" onClick={onSelect} onKeyDown={(e) => e.key === 'Enter' && onSelect()} className="card">
      Pro plan
    </div>
  );
}
`),
    ignores: f('components/plan-picker.tsx', `export function PlanOption({ onSelect }: { onSelect: () => void }) {
  return (
    <button type="button" onClick={onSelect} className="card">
      Pro plan
    </button>
  );
}
`)
  },
  {
    ruleIds: [28615], name: 'A11Y-15 role=button clickable without key handler',
    detects: f('components/plan-picker.tsx', `export function PlanOption({ onSelect }: { onSelect: () => void }) {
  return (
    <div role="button" tabIndex={0} onClick={onSelect} className="card">
      Pro plan
    </div>
  );
}
`),
    ignores: f('components/plan-picker.tsx', `export function PlanOption({ onSelect }: { onSelect: () => void }) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelect(); }}
      className="card"
    >
      Pro plan
    </div>
  );
}
`)
  },
  {
    ruleIds: [28616], name: 'A11Y-16 svg role=img without name',
    detects: f('components/logo.tsx', `export function Logo() {
  return (
    <svg role="img" viewBox="0 0 24 24" className="h-6 w-6">
      <path d="M12 2L2 22h20L12 2z" />
    </svg>
  );
}
`),
    ignores: f('components/logo.tsx', `export function Logo() {
  return (
    <svg role="img" aria-label="Acme" viewBox="0 0 24 24" className="h-6 w-6">
      <path d="M12 2L2 22h20L12 2z" />
    </svg>
  );
}
`)
  },
  {
    ruleIds: [28617], name: 'A11Y-17 invalid autocomplete token',
    detects: f('app/checkout/address-form.tsx', `export function AddressForm() {
  return (
    <form>
      <input id="email" type="email" autoComplete="email-address" />
      <input id="zip" autoComplete="zip" />
    </form>
  );
}
`),
    ignores: f('app/checkout/address-form.tsx', `export function AddressForm() {
  return (
    <form>
      <input id="email" type="email" autoComplete="email" />
      <input id="zip" autoComplete="shipping postal-code" />
    </form>
  );
}
`)
  },
  {
    ruleIds: [28618], name: 'A11Y-18 meta refresh with delay',
    detects: f('public/moved.html', `<!doctype html>
<html lang="en">
<head>
  <meta http-equiv="refresh" content="5; url=https://example.com/new-home">
</head>
<body><p>This page has moved.</p></body>
</html>
`),
    ignores: f('public/moved.html', `<!doctype html>
<html lang="en">
<head>
  <meta http-equiv="refresh" content="0; url=https://example.com/new-home">
</head>
<body><p>This page has moved.</p></body>
</html>
`)
  },
  {
    ruleIds: [28619], name: 'A11Y-19 "click here" link text',
    detects: f('app/billing/page.tsx', `import Link from 'next/link';
export default function BillingPage() {
  return (
    <p>
      To change your plan, <Link href="/pricing">click here</Link>.
    </p>
  );
}
`),
    ignores: f('app/billing/page.tsx', `import Link from 'next/link';
export default function BillingPage() {
  return (
    <p>
      You can <Link href="/pricing">change your plan on the pricing page</Link>.
    </p>
  );
}
`)
  },
  {
    ruleIds: [28620], name: 'A11Y-20 aria-label on generic div',
    detects: f('components/rating.tsx', `export function Rating({ value }: { value: number }) {
  return <div aria-label={\`Rated \${value} out of 5\`} className="flex">{'★'.repeat(value)}</div>;
}
`),
    ignores: f('components/rating.tsx', `export function Rating({ value }: { value: number }) {
  return <div role="img" aria-label={\`Rated \${value} out of 5\`} className="flex">{'★'.repeat(value)}</div>;
}
`)
  },
  {
    ruleIds: [28621], name: 'A11Y-21 autoplaying audio without controls',
    detects: f('components/welcome-sound.tsx', `export function WelcomeSound() {
  return <audio src="/sounds/welcome.mp3" autoPlay />;
}
`),
    ignores: f('components/welcome-sound.tsx', `export function WelcomeSound() {
  return <audio src="/sounds/welcome.mp3" controls />;
}
`)
  },
  {
    ruleIds: [28622], name: 'A11Y-22 invalid html lang value',
    detects: f('app/layout.tsx', `export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="english">
      <body>{children}</body>
    </html>
  );
}
`),
    ignores: f('app/layout.tsx', `export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
`)
  },
  {
    ruleIds: [28623], name: 'A11Y-23 onBlur refocus keyboard trap',
    detects: f('components/coupon-input.tsx', `export function CouponInput({ isValid }: { isValid: (v: string) => boolean }) {
  return (
    <input
      id="coupon"
      onBlur={(e) => { if (!isValid(e.target.value)) e.target.focus(); }}
    />
  );
}
`),
    ignores: f('components/coupon-input.tsx', `export function CouponInput({ isValid }: { isValid: (v: string) => boolean }) {
  const [invalid, setInvalid] = useState(false);
  return (
    <input
      id="coupon"
      aria-invalid={invalid}
      onBlur={(e) => setInvalid(!isValid(e.target.value))}
    />
  );
}
`)
  },
];
