import { NextRequest, NextResponse } from 'next/server';
import { createPolar } from '@polar-sh/sdk/2026-10';
import { createClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';

export const dynamic = 'force-dynamic';

/**
 * Creates a Polar customer portal session for the authenticated caller only.
 * The portal URL carries a session token, so it is never derived from a
 * client-supplied email and never cached.
 */
export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 10,
    windowSeconds: 60,
    prefix: 'customer-portal'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const noStore = { 'Cache-Control': 'no-store' };
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!token || !supabaseUrl || !anonKey) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401, headers: noStore });
  }

  try {
    const authClient = createClient(supabaseUrl, anonKey);
    const { data: authData, error: authError } = await authClient.auth.getUser(token);
    const email = authData?.user?.email?.toLowerCase().trim();
    if (authError || !email) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401, headers: noStore });
    }

    if (!process.env.POLAR_ACCESS_TOKEN) {
      return NextResponse.json({ error: 'Billing portal is not configured' }, { status: 500, headers: noStore });
    }

    const polar = createPolar({
      accessToken: process.env.POLAR_ACCESS_TOKEN,
    });

    const customers = await polar.customers.list({
      email,
    });

    if (!customers.items || customers.items.length === 0) {
      return NextResponse.json({ error: 'No billing account found for this user' }, { status: 404, headers: noStore });
    }

    const session = await polar.customerSessions.create({
      customer_id: customers.items[0].id,
    });

    return NextResponse.json({ url: session.customer_portal_url }, { headers: noStore });
  } catch (error) {
    logger.error('[Customer Portal] Error creating customer portal session:', error instanceof Error ? error.message : String(error));
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500, headers: noStore });
  }
}
