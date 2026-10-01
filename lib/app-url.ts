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

/**
 * Canonical public origin, the same on server and client (no window lookup): use it in metadata,
 * sitemaps and server-rendered markup. Order: NEXT_PUBLIC_APP_URL, then Vercel's production domain
 * (follows a custom domain once it is attached), then the default host. Never the per-deployment
 * VERCEL_URL, which would make crawlers index a throwaway preview host.
 */
export function getConfiguredAppUrl(): string {
  const candidates = [
    process.env.NEXT_PUBLIC_APP_URL,
    process.env.NEXT_PUBLIC_VERCEL_PROJECT_PRODUCTION_URL,
    process.env.VERCEL_PROJECT_PRODUCTION_URL,
  ];
  for (const raw of candidates) {
    const value = raw?.trim();
    if (!value) continue;
    try {
      return new URL(value.startsWith('http') ? value : `https://${value}`).origin;
    } catch {
      // try the next candidate
    }
  }
  return FALLBACK_APP_URL;
}
