/** Which bot-protection layer answered a live scan instead of the site (client-safe, no Node APIs). */
export type ChallengeProvider = 'vercel' | 'cloudflare';

/** User-facing explanation and the concrete fix for the provider that blocked the scan. */
export function botChallengeMessage(url: string, provider: ChallengeProvider | undefined): string {
  if (provider === 'vercel') {
    return `"${url}" is behind Vercel's Security Checkpoint, so Zelsis could not read it. In Vercel → Project → Firewall, `
      + 'turn off Attack Challenge Mode or Bot Protection if you do not need them, or add a Bypass rule for the Zelsis scanner '
      + '(User-Agent contains "Zelsis-Release-Gate-Scanner"). Vercel also challenges an IP for a few minutes after a burst of '
      + 'requests, so retry later if you just scanned. You can scan the GitHub repository instead.';
  }
  if (provider === 'cloudflare') {
    return `"${url}" answered with a Cloudflare bot challenge, so Zelsis could not read it. In Cloudflare → Security → WAF, `
      + 'add a Skip rule for the Zelsis scanner (User-Agent contains "Zelsis-Release-Gate-Scanner"), or scan the GitHub repository instead.';
  }
  return `"${url}" answered with a bot-protection challenge (Vercel or Cloudflare), so Zelsis could not read it. Allow the Zelsis `
    + 'scanner (User-Agent contains "Zelsis-Release-Gate-Scanner") in your firewall, or scan the GitHub repository instead.';
}
