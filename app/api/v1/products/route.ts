import { NextRequest, NextResponse } from 'next/server';
import { createPolar } from '@polar-sh/sdk/2026-10';

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

    return NextResponse.json(response.items);
  } catch (error) {
    console.error('Error fetching Polar products:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
