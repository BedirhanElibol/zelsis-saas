import { NextRequest, NextResponse } from 'next/server';
import { createPolar } from '@polar-sh/sdk/2026-10';
import crypto from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const email = req.nextUrl.searchParams.get('email');
    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    const etag = `"${crypto.createHash('md5').update(email).digest('hex')}"`;
    if (req.headers.get('if-none-match') === etag) {
      return new NextResponse(null, { status: 304 });
    }

    if (!process.env.POLAR_ACCESS_TOKEN) {
      return NextResponse.json({ error: 'Missing POLAR_ACCESS_TOKEN' }, { status: 500 });
    }

    const polar = createPolar({
      accessToken: process.env.POLAR_ACCESS_TOKEN,
    });

    // 1. Find customer by email
    const customers = await polar.customers.list({
      email,
    });

    if (!customers.items || customers.items.length === 0) {
      return NextResponse.json({ error: 'Customer not found' }, { status: 404 });
    }

    const customerId = customers.items[0].id;

    // 2. Create a customer session
    const session = await polar.customerSessions.create({
      customer_id: customerId,
    });

    // Redirect to the customer portal
    const res = NextResponse.redirect(session.customer_portal_url);
    res.headers.set('ETag', etag);
    res.headers.set('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    return res;
  } catch (error) {
    console.error('Error creating customer portal session:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
