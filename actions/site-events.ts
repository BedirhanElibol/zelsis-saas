'use server';

import { headers } from 'next/headers';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase-admin';

// Anonymous, cookieless counts of page views and CTA clicks. Nothing that identifies a visitor is read or stored:
// no IP address, no user agent, no cookie. Visitors who send Do Not Track or Global Privacy Control are not counted.

const BOT = /bot|crawl|spider|slurp|headless|preview|lighthouse|monitor|uptime|curl|wget|python-requests|node-fetch|axios|go-http/i;

const EventSchema = z.object({
  kind: z.enum(['view', 'cta']),
  path: z.string().max(120).regex(/^\/[a-zA-Z0-9\-_/]*$/),
  source: z.string().max(60).regex(/^[a-z0-9.\-_]*$/),
  label: z.string().max(40).regex(/^[a-zA-Z0-9\-_/:#. ]*$/),
});

// Dashboards and sign-in pages are not marketing pages; leave them out.
const SKIPPED_PREFIXES = ['/dashboard', '/auth', '/api', '/admin'];

export async function recordSiteEvent(input: z.input<typeof EventSchema>): Promise<void> {
  const parsed = EventSchema.safeParse(input);
  if (!parsed.success) return;
  const { kind, path, source, label } = parsed.data;
  if (SKIPPED_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`))) return;

  const h = await headers();
  if (h.get('dnt') === '1' || h.get('sec-gpc') === '1') return;
  const ua = h.get('user-agent') ?? '';
  if (!ua || BOT.test(ua)) return;

  const admin = getSupabaseAdmin();
  if (!admin) return;
  await admin.rpc('bump_site_event', { p_kind: kind, p_path: path, p_source: source, p_label: label });
}
