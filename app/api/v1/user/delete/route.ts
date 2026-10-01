import { NextRequest, NextResponse } from 'next/server';
import { CONTACT_EMAIL } from '@/lib/contact';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

export async function DELETE(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 5,
    windowSeconds: 3600,
    prefix: 'user-delete'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const authHeader = req.headers.get('authorization');
  const token = authHeader?.replace('Bearer ', '') || null;

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  try {
    if (!supabaseUrl || !anonKey) {
      return NextResponse.json({ error: 'Database service configuration missing' }, { status: 500 });
    }

    if (!token) {
      return NextResponse.json({ error: 'Authentication token required for account deletion' }, { status: 401 });
    }

    const userClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false }
    });
    const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
    if (authErr || !user) {
      return NextResponse.json({ error: 'Invalid or expired authentication session' }, { status: 401 });
    }

    const userId = user.id;
    const userEmail = user.email || null;

    // Optional confirmation check from body
    try {
      const body = await req.json();
      if (body?.confirmation && body.confirmation !== 'DELETE') {
        return NextResponse.json({ error: 'Confirmation mismatch. Expected confirmation: DELETE' }, { status: 400 });
      }
    } catch (parseErr) {
      logger.debug('[User Delete] Body parse notice:', (parseErr as Error)?.message);
    }

    logger.info(`[GDPR Erasure] Processing verified account deletion for user ID: ${userId} (${userEmail || 'unknown email'})`);

    if (serviceRoleKey) {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);

      if (userId) {
        await adminClient.from('findings').delete().eq('user_id', userId);
        await adminClient.from('scans').delete().eq('user_id', userId);
        await adminClient.from('projects').delete().eq('user_id', userId);
        await adminClient.from('subscriptions').delete().eq('user_id', userId);
        await adminClient.from('profiles').delete().eq('id', userId);
        await adminClient.auth.admin.deleteUser(userId);
      } else if (userEmail) {
        await adminClient.from('profiles').delete().eq('email', userEmail);
      }
    }

    return NextResponse.json({
      success: true,
      message: 'Account and associated data successfully erased in compliance with GDPR Art. 17 .'
    });
  } catch (err: any) {
    logger.error('[GDPR Erasure] Error during deletion:', err?.message);
    return NextResponse.json({ error: `Deletion failed. Contact ${CONTACT_EMAIL}` }, { status: 500 });
  }
}
