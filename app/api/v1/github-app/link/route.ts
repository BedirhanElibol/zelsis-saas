import { NextResponse } from 'next/server';
import { getRequestUserId } from '@/lib/request-user';
import { isGithubOAuthConfigured, linkInstallationsFromOAuthCode } from '@/lib/github/installations';

/** Links the GitHub App installations behind an OAuth code (from /github/callback) to the signed-in user. */
export async function POST(req: Request) {
  if (!isGithubOAuthConfigured()) return NextResponse.json({ error: 'GitHub sign-in is not configured.' }, { status: 503 });
  const userId = await getRequestUserId(req);
  if (!userId) return NextResponse.json({ error: 'Sign in first.' }, { status: 401 });
  const body = (await req.json().catch(() => ({}))) as { code?: unknown };
  const code = typeof body.code === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(body.code) ? body.code : null;
  if (!code) return NextResponse.json({ error: 'Missing or invalid code.' }, { status: 400 });
  const linked = await linkInstallationsFromOAuthCode(userId, code);
  return NextResponse.json({ linked }, { status: linked > 0 ? 200 : 422 });
}
