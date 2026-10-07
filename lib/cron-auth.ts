import { timingSafeEqual } from 'crypto';

/** Vercel Cron sends `Authorization: Bearer $CRON_SECRET`; anything else (or no secret configured) is rejected. */
export function isAuthorizedCron(header: string | null): boolean {
  const secret = process.env.CRON_SECRET?.trim();
  if (!secret || !header) return false;
  const expected = Buffer.from(`Bearer ${secret}`);
  const received = Buffer.from(header);
  return expected.length === received.length && timingSafeEqual(expected, received);
}
