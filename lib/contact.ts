/**
 * Public contact address for support, billing, privacy, legal and security requests.
 * NEXT_PUBLIC_CONTACT_EMAIL overrides it; the default is the live contact@zelsis.com mailbox.
 */
export const CONTACT_EMAIL = process.env.NEXT_PUBLIC_CONTACT_EMAIL?.trim() || 'contact@zelsis.com';

export const contactMailto = (subject?: string): string =>
  `mailto:${CONTACT_EMAIL}${subject ? `?subject=${encodeURIComponent(subject)}` : ''}`;
