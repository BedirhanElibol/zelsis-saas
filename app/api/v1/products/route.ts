import { NextRequest, NextResponse } from 'next/server';
import { createPolar } from '@polar-sh/sdk/2026-10';
import crypto from 'crypto';

export async function GET(req: NextRequest) {
  try {
    if (!process.env.POLAR_ACCESS_TOKEN) {
      return NextResponse.json({ error: 'Missing POLAR_ACCESS_TOKEN' }, { status: 500 });
    }

    const polar = createPolar({
      accessToken: process.env.POLAR_ACCESS_TOKEN,
    });

    const response = await polar.products.list({
      is_archived: false,
    });

    const bodyString = JSON.stringify(response.items);
    const etag = `"${crypto.createHash('md5').update(bodyString).digest('hex')}"`;

    if (req.headers.get('if-none-match') === etag) {
      return new NextResponse(null, { status: 304 });
    }

    const res = NextResponse.json(response.items);
    res.headers.set('ETag', etag);
    res.headers.set('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    return res;
  } catch (error) {
    console.error('Error fetching Polar products:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
