import { NextResponse } from 'next/server';
import { getRequestUserId } from '@/lib/request-user';
import { githubAppSlug, isGithubAppConfigured, isGithubOAuthConfigured, signInstallState } from '@/lib/github/installations';
import { getConfiguredAppUrl } from '@/lib/app-url';

/** Returns the GitHub App install URL for the signed-in user, with a signed state the setup callback verifies. */
export async function POST(req: Request) {
  if (!isGithubAppConfigured()) {
    return NextResponse.json({ error: 'GitHub connection is not available yet.' }, { status: 503 });
  }
  const userId = await getRequestUserId(req);
  if (!userId) return NextResponse.json({ error: 'Sign in first.' }, { status: 401 });
  const state = signInstallState(userId);
  const clientId = process.env.GITHUB_APP_CLIENT_ID?.trim();
  // Already installed (another browser, another Zelsis account): GitHub verifies the user and /github/callback links it
  const linkUrl = clientId && isGithubOAuthConfigured()
    ? `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(`${getConfiguredAppUrl()}/github/callback`)}`
    : null;
  return NextResponse.json({ url: `https://github.com/apps/${githubAppSlug()}/installations/new?state=${encodeURIComponent(state)}`, linkUrl });
}
