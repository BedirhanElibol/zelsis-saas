/**
 * Public incidents that match a rule exactly, each with a source we opened and read (2026-10-20).
 * Shown on a finding as "This has happened before". Only what the source says goes in `what`; no figure is added
 * that the source does not give, and a claim nobody verified says so. A rule with no matching incident shows nothing.
 */
import { isSecretRuleId } from '@/lib/scanner/text';

export interface Incident {
  id: string;
  title: string;
  year: number;
  /** One or two sentences, in our words, of what the source reports. */
  what: string;
  source: { label: string; url: string };
  matches: (ruleId: number) => boolean;
}

const ids = (...list: number[]) => {
  const set = new Set(list);
  return (ruleId: number) => set.has(ruleId);
};

export const INCIDENTS: Incident[] = [
  {
    id: 'first-american-2019',
    title: 'First American Financial: documents reachable by changing a number in the link',
    year: 2019,
    what: 'About 885 million title-insurance files, including bank statements and Social Security numbers, could be opened without logging in by changing a digit in a document URL.',
    source: { label: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/2019/05/first-american-financial-corp-leaked-hundreds-of-millions-of-title-insurance-records/' },
    matches: ids(17, 9106, 29301),
  },
  {
    id: 'lovable-rls-2025',
    title: 'Apps built on Lovable shipped Supabase tables without Row Level Security',
    year: 2025,
    what: 'CVE-2025-48757: generated sites let unauthenticated visitors read or write database tables because the RLS policy was missing or too broad. Lovable disputes the CVE and says each app owner is responsible for its data.',
    source: { label: 'NVD, CVE-2025-48757', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-48757' },
    matches: ids(3, 45, 3001, 6010, 28801, 28817),
  },
  {
    id: 'tea-app-2025',
    title: 'Tea app: verification selfies and IDs in an open storage bucket',
    year: 2025,
    what: 'About 72,000 images, including roughly 13,000 verification selfies and photo IDs, were taken from a storage bucket that reportedly required no authentication.',
    source: { label: 'The Record', url: 'https://therecord.media/tea-app-data-breach-stolen-ids-leaked' },
    matches: ids(3012, 3018, 14801, 18043, 28411, 28802, 28803, 29201),
  },
  {
    id: 'toyota-github-key-2022',
    title: 'Toyota: a server access key sat in a public GitHub repository for about five years',
    year: 2022,
    what: 'A subcontractor pushed part of the T-Connect source code, including an access key to the data server, to a public repository. 296,019 customer email addresses were exposed until the key was changed.',
    source: { label: 'TechCrunch', url: 'https://techcrunch.com/2022/10/12/toyota-customer-email-addresses-exposed/' },
    matches: (ruleId) => isSecretRuleId(ruleId),
  },
  {
    id: 'starbucks-race-2015',
    title: 'Starbucks gift cards: one balance transferred twice by racing two requests',
    year: 2015,
    what: 'A researcher sent the same gift card transfer from two sessions at the same moment; both went through, turning $15 of balance into $20.',
    source: { label: 'Egor Homakov, Sakurity', url: 'https://sakurity.com/blog/2015/05/21/starbucks.html' },
    matches: ids(10101, 29666, 30307),
  },
  {
    id: 'twitter-sms-pumping-2023',
    title: 'Twitter: SMS verification codes triggered by bots',
    year: 2023,
    what: 'Elon Musk said Twitter was paying about $60 million a year for fake 2FA text messages that bot accounts triggered. This is his figure; it was not independently verified.',
    source: { label: 'Gigazine, citing Commsrisk', url: 'https://gigazine.net/gsc_news/en/20230221-twitter-lost-60-million-dollars-2fa-sms' },
    matches: ids(30312),
  },
];

/** The incident that matches this rule, if any. */
export function incidentFor(ruleId: number): Incident | null {
  return INCIDENTS.find((i) => i.matches(ruleId)) ?? null;
}
