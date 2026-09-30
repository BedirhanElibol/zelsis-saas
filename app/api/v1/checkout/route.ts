import { Checkout } from '@polar-sh/nextjs';

export const GET = Checkout({
  accessToken: process.env.POLAR_ACCESS_TOKEN || '',
  environment: process.env.NODE_ENV === 'production' ? 'production' : 'sandbox',
  successUrl: process.env.NEXT_PUBLIC_APP_URL ? `${process.env.NEXT_PUBLIC_APP_URL}/dashboard?checkout=success` : 'http://localhost:3000/dashboard?checkout=success',
});
