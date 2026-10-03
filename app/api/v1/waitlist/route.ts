import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey } from '@/lib/supabase';
import { sendWaitlistWelcomeEmail } from '@/lib/email';

export const dynamic = 'force-dynamic';

function getWaitlistSupabase() {
  const url = getEffectiveSupabaseUrl();
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || getEffectiveSupabaseAnonKey();
  if (!url || !serviceKey) return null;
  return createClient(url, serviceKey, { auth: { persistSession: false } });
}

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 20,
    windowSeconds: 60,
    prefix: 'waitlist'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // Enforce Content-Type validation
  const contentType = req.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return NextResponse.json({ error: 'Invalid Content-Type, must be application/json' }, { status: 415 });
  }

  // Enforce optional API secret verification if configured
  const validToken = process.env.API_SECRET_TOKEN || process.env.WAITLIST_API_KEY;
  if (validToken) {
    const authHeader = req.headers.get('authorization');
    const token = authHeader?.replace('Bearer ', '').trim();
    if (token && token !== validToken) {
      return NextResponse.json({ error: 'Forbidden: Invalid token' }, { status: 403 });
    }
  }

  try {
    const body = await req.json();
    const { email, framework_interest, source } = body;

    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    const supabase = getWaitlistSupabase();
    if (!supabase) {
      return NextResponse.json({ error: 'Database service unavailable' }, { status: 503 });
    }

    const { data, error } = await supabase
      .from('waitlist')
      .insert([
        {
          email,
          framework_interest: framework_interest || null,
          source: source || 'direct',
        }
      ]);

    if (error) {
      // Handle unique constraint violation gracefully
      if (error.code === '23505') {
        return NextResponse.json({ success: true, message: 'Already on waitlist' });
      }
      console.error('Waitlist insert error:', error);
      return NextResponse.json({ error: 'Failed to join waitlist' }, { status: 500 });
    }

    // Fire welcome email asynchronously without blocking response
    void sendWaitlistWelcomeEmail(email, framework_interest).catch((err) => {
      console.warn('[Waitlist] Welcome email sending error:', err);
    });

    return NextResponse.json({ success: true });
  } catch (err) {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }
}
