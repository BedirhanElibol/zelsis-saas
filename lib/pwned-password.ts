const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** True when `suffix` appears with a non-zero count in a Pwned Passwords range response. */
export function rangeContainsSuffix(rangeBody: string, suffix: string): boolean {
  return rangeBody.split('\n').some(line => {
    const [hashSuffix, count] = line.trim().split(':');
    return hashSuffix?.toUpperCase() === suffix && Number(count) > 0;
  });
}

/**
 * Checks a password against Have I Been Pwned with k-anonymity: only the first 5 hex chars of its
 * SHA-1 hash leave the browser. Returns null when the service can't be reached, so callers fail open
 * instead of blocking sign-up on a third-party outage.
 */
export async function isPwnedPassword(password: string, timeoutMs = 4000): Promise<boolean | null> {
  try {
    const hash = await sha1Hex(password);
    const res = await fetch(PWNED_RANGE_URL + hash.slice(0, 5), {
      headers: { 'Add-Padding': 'true' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    return rangeContainsSuffix(await res.text(), hash.slice(5));
  } catch {
    return null;
  }
}
