/**
 * Public contact address for support, billing, privacy, legal and security requests.
 * Set NEXT_PUBLIC_CONTACT_EMAIL to a mailbox that receives mail; the default only works
 * once the zelsis.com domain and its mail routing are live.
 */
export const CONTACT_EMAIL = process.env.NEXT_PUBLIC_CONTACT_EMAIL?.trim() || 'contact@zelsis.com';

export const contactMailto = (subject?: string): string =>
  `mailto:${CONTACT_EMAIL}${subject ? `?subject=${encodeURIComponent(subject)}` : ''}`;
