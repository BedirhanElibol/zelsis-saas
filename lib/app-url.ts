/** Production host used when neither the browser origin nor NEXT_PUBLIC_APP_URL is available. */
const FALLBACK_APP_URL = 'https://shipguard-saas.vercel.app';

/**
 * Public origin of this deployment, for links and copy-paste snippets (CI workflows, curl, badges).
 * Browser: the current origin. Server: NEXT_PUBLIC_APP_URL. Moving to a custom domain only needs that variable.
 */
export function getPublicAppUrl(): string {
  if (typeof window !== 'undefined' && window.location?.origin) return window.location.origin;
  return getConfiguredAppUrl();
}

/** Same on server and client (no window lookup): use in server-rendered markup to avoid hydration mismatches. */
export function getConfiguredAppUrl(): string {
  const configured = process.env.NEXT_PUBLIC_APP_URL?.trim();
  if (configured) {
    try {
      return new URL(configured.startsWith('http') ? configured : `https://${configured}`).origin;
    } catch {
      // fall through to the default host
    }
  }
  return FALLBACK_APP_URL;
}
