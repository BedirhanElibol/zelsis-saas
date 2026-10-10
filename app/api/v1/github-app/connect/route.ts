import { NextResponse } from 'next/server';
import { getRequestUserId } from '@/lib/request-user';
import { githubAppSlug, isGithubAppConfigured, signInstallState } from '@/lib/github/installations';

/** Returns the GitHub App install URL for the signed-in user, with a signed state the setup callback verifies. */
export async function POST(req: Request) {
  if (!isGithubAppConfigured()) {
    return NextResponse.json({ error: 'GitHub connection is not available yet.' }, { status: 503 });
  }
  const userId = await getRequestUserId(req);
  if (!userId) return NextResponse.json({ error: 'Sign in first.' }, { status: 401 });
  const state = signInstallState(userId);
  return NextResponse.json({ url: `https://github.com/apps/${githubAppSlug()}/installations/new?state=${encodeURIComponent(state)}` });
}
