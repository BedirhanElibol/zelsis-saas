import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';
import { isValidUnsubscribeToken } from '@/lib/lifecycle-emails';

export const dynamic = 'force-dynamic';

/**
 * Unsubscribe from product (lifecycle) emails. GET is the link in the email, POST is RFC 8058 one-click
 * from the mail client. The HMAC token binds the link to one account; alerts and invites are not affected.
 */
async function optOut(req: Request): Promise<{ ok: boolean }> {
  const url = new URL(req.url);
  const userId = url.searchParams.get('u') || '';
  if (!isValidUnsubscribeToken(userId, url.searchParams.get('t'))) return { ok: false };
  const admin = getSupabaseAdmin();
  if (!admin) return { ok: false };
  const { data } = await admin.auth.admin.getUserById(userId);
  if (!data?.user) return { ok: false };
  const { error } = await admin.auth.admin.updateUserById(userId, {
    app_metadata: { ...(data.user.app_metadata ?? {}), email_opt_out: true },
  });
  if (error) {
    logger.error('[Unsubscribe] Could not record opt-out:', error.message);
    return { ok: false };
  }
  return { ok: true };
}

const page = (title: string, body: string, status: number) =>
  new NextResponse(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head>` +
      `<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0A0A0A;color:#EDEDED;font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:16px">` +
      `<main style="max-width:420px;text-align:center"><h1 style="font-size:20px">${title}</h1><p style="color:#A1A1AA;font-size:14px">${body}</p>` +
      `<p><a href="/" style="color:#34D399">Back to Zelsis</a></p></main></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }
  );

export async function GET(req: Request) {
  const { ok } = await optOut(req);
  return ok
    ? page("You're unsubscribed", 'You will not get product emails from Zelsis any more. Security alerts you turned on and team invites still arrive.', 200)
    : page('Link not valid', 'This unsubscribe link is invalid or expired. Reply to any Zelsis email and we will remove you.', 400);
}

export async function POST(req: Request) {
  const { ok } = await optOut(req);
  return NextResponse.json({ ok }, { status: ok ? 200 : 400 });
}
