import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [276],
    name: 'CLICHE-76 starter template title and lorem ipsum vs real metadata',
    detects: f('app/layout.tsx', "export const metadata = { title: 'Create Next App', description: 'Lorem ipsum dolor sit amet' };\nexport default function Root({ children }: { children: React.ReactNode }) { return <html><body>{children}</body></html>; }\n"),
    ignores: f('app/layout.tsx', "export const metadata = { title: 'Invoicely | Invoices that chase themselves', description: 'Send invoices and get paid on time.' };\nexport default function Root({ children }: { children: React.ReactNode }) { return <html><body>{children}</body></html>; }\n"),
  },
  {
    ruleIds: [276],
    name: 'CLICHE-76 Title Case placeholder heading vs prose that mentions lorem ipsum and a company name',
    detects: f('components/Footer.tsx', "export const Footer = () => <footer><h2>Your Company Name</h2></footer>;\n"),
    ignores: f('components/Problems.tsx', "export const Problems = () => <ul><li>The page still says lorem ipsum</li><li>PDF report with your company name and logo</li></ul>;\n"),
  },
  {
    ruleIds: [210],
    name: 'CLICHE-10 typed-in "10,000+ developers" vs a count read from data',
    detects: f('components/Stats.tsx', 'export const Stats = () => <p className="text-sm">Trusted by 10,000+ developers</p>;\n'),
    ignores: f('components/Stats.tsx', "export const Stats = ({ stats }: { stats: { users: number } }) => <p className=\"text-sm\">Used by {stats.users.toLocaleString('en-US')} developers</p>;\n"),
  },
  {
    ruleIds: [253],
    name: 'CLICHE-53 bare 4.9/5 rating vs one with a review count and source',
    detects: f('components/Rating.tsx', 'export const Rating = () => <p>Rated 4.9/5 by our customers</p>;\n'),
    ignores: f('components/Rating.tsx', 'export const Rating = () => <a href="https://www.g2.com/products/invoicely/reviews">Rated 4.9/5 from 212 reviews on G2</a>;\n'),
  },
  {
    ruleIds: [228],
    name: 'CLICHE-28 hardcoded "12 people viewing" vs presence from a live channel',
    detects: f('components/Viewers.tsx', 'export const Viewers = () => <span className="flex gap-1"><span className="animate-ping" />12 people are viewing this plan</span>;\n'),
    ignores: f('components/Viewers.tsx', "export function Viewers({ room }: { room: string }) {\n  const count = usePresence(supabase.channel(room));\n  return <span>{count} people are viewing this plan</span>;\n}\n"),
  },
  {
    ruleIds: [229],
    name: 'CLICHE-29 testimonial from "CEO at Acme Corp" vs a real attributed quote',
    detects: f('components/Testimonials.tsx', "const testimonials = [{ quote: 'This changed how we ship.', name: 'Sarah Lee', role: 'CEO at Acme Corp' }];\nexport const Testimonials = () => <ul>{testimonials.map((t) => <li key={t.name}>{t.quote} {t.name}, {t.role}</li>)}</ul>;\n"),
    ignores: f('components/Testimonials.tsx', "const testimonials = [{ quote: 'We caught a double charge before it shipped.', name: 'Maya Ortiz', role: 'CTO at Fernway' }];\nexport const Testimonials = () => <ul>{testimonials.map((t) => <li key={t.name}>{t.quote} {t.name}, {t.role}</li>)}</ul>;\n"),
  },
  {
    ruleIds: [232],
    name: 'CLICHE-32 countdown that restarts for every visitor vs a fixed end date',
    detects: f('components/OfferBanner.tsx', "export function OfferBanner() {\n  const end = new Date(Date.now() + 15 * 60 * 1000);\n  return <p>Offer ends in {format(end)}</p>;\n}\n"),
    ignores: f('components/OfferBanner.tsx', "import { offer } from '@/lib/offer';\nexport function OfferBanner() {\n  const end = new Date(offer.endsAt);\n  return <p>Offer ends on {format(end)}</p>;\n}\n"),
  },
  {
    ruleIds: [241],
    name: 'CLICHE-41 typed-in Product Hunt claim vs a badge linking to the listing',
    detects: f('components/Hero.tsx', "export const Badge = () => <span className=\"badge\">#1 Product of the Day</span>;\n"),
    ignores: f('components/Hero.tsx', "export const Badge = () => <a href=\"https://www.producthunt.com/posts/invoicely\">#1 Product of the Day</a>;\n"),
  },
];
