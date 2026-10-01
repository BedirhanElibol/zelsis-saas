import { getSupabase } from '@/lib/supabase';

const POLAR_PURCHASES_URL = 'https://polar.sh/purchases';

/**
 * Opens the signed-in user's Polar customer portal in a new tab.
 * Falls back to Polar's generic purchases page when no session or billing account exists.
 */
export async function openCustomerPortal(): Promise<void> {
  // Open the tab synchronously inside the click handler so popup blockers allow it.
  const popup = window.open('about:blank', '_blank');
  let target = POLAR_PURCHASES_URL;
  try {
    const { data } = (await getSupabase()?.auth.getSession()) ?? { data: { session: null } };
    const accessToken = data.session?.access_token;
    if (accessToken) {
      const res = await fetch('/api/v1/customer-portal', {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (res.ok) {
        const body: { url?: string } = await res.json();
        if (body.url) target = body.url;
      }
    }
  } catch (err) {
    console.warn('[Billing Portal] Falling back to Polar purchases page:', err);
  }
  if (popup) {
    popup.opener = null;
    popup.location.href = target;
  } else {
    window.location.href = target;
  }
}
