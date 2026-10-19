import { NextResponse } from 'next/server';
import { isAuthorizedCron } from '@/lib/cron-auth';
import { sendWeeklySummaries } from '@/lib/weekly-summary-job';

export const maxDuration = 60;
export const dynamic = 'force-dynamic';

/** Fridays: what the PR / CI gate did this week, to each account that had gate runs and did not opt out. */
export async function GET(req: Request) {
  if (!isAuthorizedCron(req.headers.get('authorization'))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return sendWeeklySummaries();
}
