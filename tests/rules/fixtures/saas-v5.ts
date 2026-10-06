import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29401], name: 'SAAS5-01 OpenAI key behind NEXT_PUBLIC_ in a client component',
    detects: f('components/Chat.tsx', `'use client';
import OpenAI from 'openai';
const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
export function Chat() { return null; }
`),
    ignores: f('app/api/chat/route.ts', `import OpenAI from 'openai';
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
export const posthogKey = process.env.NEXT_PUBLIC_POSTHOG_KEY;
export async function POST() { return Response.json({}); }
`),
  },
  {
    ruleIds: [29401], name: 'SAAS5-01 Vite Anthropic key in .env.example',
    detects: f('.env.example', `VITE_SUPABASE_URL=
VITE_ANTHROPIC_API_KEY=
`),
    ignores: f('.env.example', `VITE_SUPABASE_URL=
VITE_SUPABASE_ANON_KEY=
ANTHROPIC_API_KEY=
`),
  },
  {
    ruleIds: [29402], name: 'SAAS5-02 Clerk webhook without svix verification',
    detects: f('app/api/webhooks/clerk/route.ts', `import { db } from '@/lib/db';
export async function POST(req: Request) {
  const evt = await req.json();
  if (evt.type === 'user.created') {
    await db.user.create({ data: { clerkId: evt.data.id, role: evt.data.public_metadata.role } });
  }
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/clerk/route.ts', `import { Webhook } from 'svix';
import { headers } from 'next/headers';
import { db } from '@/lib/db';
export async function POST(req: Request) {
  const body = await req.text();
  const h = await headers();
  const evt = new Webhook(process.env.CLERK_WEBHOOK_SECRET!).verify(body, {
    'svix-id': h.get('svix-id')!, 'svix-timestamp': h.get('svix-timestamp')!, 'svix-signature': h.get('svix-signature')!,
  }) as { type: string; data: { id: string } };
  if (evt.type === 'user.created') await db.user.create({ data: { clerkId: evt.data.id } });
  return new Response('ok');
}
`),
  },
  {
    ruleIds: [29403], name: 'SAAS5-03 productionBrowserSourceMaps',
    detects: f('next.config.js', `module.exports = {
  reactStrictMode: true,
  productionBrowserSourceMaps: true,
};
`),
    ignores: f('next.config.js', `module.exports = {
  reactStrictMode: true,
  productionBrowserSourceMaps: false,
};
`),
  },
];
