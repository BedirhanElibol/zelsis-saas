import { Checkout } from '@polar-sh/nextjs';
import { getConfiguredAppUrl } from '@/lib/app-url';

const isProduction = process.env.NODE_ENV === 'production';
// Buyers land here after paying: in production it must be the public site, never localhost
const appUrl = isProduction ? getConfiguredAppUrl() : 'http://localhost:3000';

export const GET = Checkout({
  accessToken: process.env.POLAR_ACCESS_TOKEN || '',
  environment: isProduction ? 'production' : 'sandbox',
  successUrl: `${appUrl}/dashboard?checkout=success`,
});
