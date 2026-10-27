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
