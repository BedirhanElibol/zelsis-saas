import { NextResponse } from 'next/server';
import { getRequestUserId } from '@/lib/request-user';
import { isGithubAppConfigured, listConnectedRepos } from '@/lib/github/installations';

/** Repositories the signed-in user shared with the Zelsis GitHub App (for the "pick a repository" list). */
export async function GET(req: Request) {
  if (!isGithubAppConfigured()) return NextResponse.json({ configured: false, repos: [] });
  const userId = await getRequestUserId(req);
  if (!userId) return NextResponse.json({ error: 'Sign in first.' }, { status: 401 });
  const { repos, errors } = await listConnectedRepos(userId);
  return NextResponse.json({ configured: true, repos, errors }, { headers: { 'Cache-Control': 'no-store' } });
}
