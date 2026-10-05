import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const PRISMA_SCHEMA = {
  path: 'prisma/schema.prisma',
  content: `datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id           String   @id @default(cuid())
  email        String   @unique
  name         String?
  image        String?
  passwordHash String
  totpSecret   String?
  createdAt    DateTime @default(now())
  posts        Post[]
}

model Post {
  id       String @id @default(cuid())
  title    String
  authorId String
  author   User   @relation(fields: [authorId], references: [id])
}
`
};

const PROFILE_FORM = {
  path: 'components/profile-form.tsx',
  content: `'use client';

import { useState } from 'react';

type Props = { user: { id: string; name: string | null; email: string } };

export function ProfileForm({ user }: Props) {
  const [name, setName] = useState(user.name ?? '');
  return (
    <form>
      <input value={name} onChange={(e) => setName(e.target.value)} />
      <p>{user.email}</p>
    </form>
  );
}
`
};

export const CASES: RuleCase[] = [
  // ---------------------------------------------------------------- NEXTAI-01
  {
    ruleIds: [28751],
    name: 'NEXTAI-01 unstable_cache closes over the signed-in user id without keying on it',
    detects: f('app/dashboard/orders/page.tsx', `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

export default async function OrdersPage() {
  const session = await auth();
  const userId = session?.user?.id;

  const getOrders = unstable_cache(
    async () => {
      return db.order.findMany({ where: { userId }, orderBy: { createdAt: 'desc' } });
    },
    ['dashboard-orders'],
    { revalidate: 300, tags: ['orders'] }
  );

  const orders = await getOrders();
  return <ul>{orders.map((o) => <li key={o.id}>{o.total}</li>)}</ul>;
}
`),
    ignores: f('app/dashboard/orders/page.tsx', `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

const getOrders = unstable_cache(
  async (userId: string) => {
    return db.order.findMany({ where: { userId }, orderBy: { createdAt: 'desc' } });
  },
  ['dashboard-orders'],
  { revalidate: 300, tags: ['orders'] }
);

export default async function OrdersPage() {
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) return null;

  const orders = await getOrders(userId);
  return <ul>{orders.map((o) => <li key={o.id}>{o.total}</li>)}</ul>;
}
`)
  },
  {
    ruleIds: [28751],
    name: 'NEXTAI-01 unstable_cache reads the team id from cookies() outside the key',
    detects: f('app/(app)/settings/billing/page.tsx', `import { cookies } from 'next/headers';
import { unstable_cache } from 'next/cache';
import { getInvoices } from '@/lib/billing';

export default async function BillingPage() {
  const cookieStore = await cookies();
  const teamId = cookieStore.get('current_team')?.value ?? '';

  const invoices = await unstable_cache(async () => getInvoices(teamId), ['billing-invoices'], { revalidate: 600 })();

  return <pre>{JSON.stringify(invoices)}</pre>;
}
`),
    ignores: f('app/(app)/settings/billing/page.tsx', `import { cookies } from 'next/headers';
import { unstable_cache } from 'next/cache';
import { getInvoices } from '@/lib/billing';

export default async function BillingPage() {
  const cookieStore = await cookies();
  const teamId = cookieStore.get('current_team')?.value ?? '';

  const invoices = await unstable_cache(async () => getInvoices(teamId), ['billing-invoices', teamId], { revalidate: 600 })();

  return <pre>{JSON.stringify(invoices)}</pre>;
}
`)
  },
  // ---------------------------------------------------------------- NEXTAI-02
  {
    ruleIds: [28752],
    name: 'NEXTAI-02 full Prisma user row (passwordHash) passed to a client component',
    detects: [
      PRISMA_SCHEMA,
      PROFILE_FORM,
      {
        path: 'app/settings/profile/page.tsx',
        content: `import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { prisma } from '@/lib/prisma';
import { ProfileForm } from '@/components/profile-form';

export default async function ProfilePage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const user = await prisma.user.findUnique({ where: { id: session.user.id } });
  if (!user) redirect('/login');

  return (
    <main className="mx-auto max-w-xl">
      <h1>Profile</h1>
      <ProfileForm user={user} />
    </main>
  );
}
`
      }
    ],
    ignores: [
      PRISMA_SCHEMA,
      PROFILE_FORM,
      {
        path: 'app/settings/profile/page.tsx',
        content: `import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { prisma } from '@/lib/prisma';
import { ProfileForm } from '@/components/profile-form';

export default async function ProfilePage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { id: true, name: true, email: true },
  });
  if (!user) redirect('/login');

  return (
    <main className="mx-auto max-w-xl">
      <h1>Profile</h1>
      <ProfileForm user={user} />
    </main>
  );
}
`
      }
    ]
  },
  {
    ruleIds: [28752],
    name: 'NEXTAI-02 Supabase select(*) row with an API key column spread into a client component',
    detects: [
      { path: 'supabase/migrations/20250101000000_init.sql', content: `create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  openai_api_key text,
  created_at timestamptz default now()
);
alter table public.workspaces enable row level security;
` },
      { path: 'app/w/[id]/workspace-header.tsx', content: `"use client";
export default function WorkspaceHeader({ name }: { name: string }) {
  return <header>{name}</header>;
}
` },
      { path: 'app/w/[id]/page.tsx', content: `import { createClient } from '@/lib/supabase/server';
import WorkspaceHeader from './workspace-header';

export default async function WorkspacePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: workspace } = await supabase.from('workspaces').select('*').eq('id', id).single();
  if (!workspace) return null;
  return <WorkspaceHeader {...workspace} />;
}
` }
    ],
    ignores: [
      { path: 'supabase/migrations/20250101000000_init.sql', content: `create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  openai_api_key text,
  created_at timestamptz default now()
);
alter table public.workspaces enable row level security;
` },
      { path: 'app/w/[id]/workspace-header.tsx', content: `"use client";
export default function WorkspaceHeader({ name }: { name: string }) {
  return <header>{name}</header>;
}
` },
      { path: 'app/w/[id]/page.tsx', content: `import { createClient } from '@/lib/supabase/server';
import WorkspaceHeader from './workspace-header';

export default async function WorkspacePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: workspace } = await supabase.from('workspaces').select('id, name').eq('id', id).single();
  if (!workspace) return null;
  return <WorkspaceHeader {...workspace} />;
}
` }
    ]
  },
  // ---------------------------------------------------------------- NEXTAI-03
  {
    ruleIds: [28753],
    name: 'NEXTAI-03 AI SDK tool deletes records without needsApproval',
    detects: f('app/api/chat/route.ts', `import { openai } from '@ai-sdk/openai';
import { streamText, tool } from 'ai';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { auth } from '@/auth';

export async function POST(req: Request) {
  const session = await auth();
  const { messages } = await req.json();
  const result = streamText({
    model: openai('gpt-4o'),
    messages,
    tools: {
      deleteProject: tool({
        description: 'Delete a project and all of its documents',
        inputSchema: z.object({ projectId: z.string() }),
        execute: async ({ projectId }) => {
          await prisma.project.delete({ where: { id: projectId, ownerId: session!.user.id } });
          return { deleted: projectId };
        },
      }),
    },
  });
  return result.toUIMessageStreamResponse();
}
`),
    ignores: f('app/api/chat/route.ts', `import { openai } from '@ai-sdk/openai';
import { streamText, tool } from 'ai';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { auth } from '@/auth';

export async function POST(req: Request) {
  const session = await auth();
  const { messages } = await req.json();
  const result = streamText({
    model: openai('gpt-4o'),
    messages,
    tools: {
      deleteProject: tool({
        description: 'Delete a project and all of its documents',
        inputSchema: z.object({ projectId: z.string() }),
        needsApproval: true,
        execute: async ({ projectId }) => {
          await prisma.project.delete({ where: { id: projectId, ownerId: session!.user.id } });
          return { deleted: projectId };
        },
      }),
    },
  });
  return result.toUIMessageStreamResponse();
}
`)
  },
  {
    ruleIds: [28753],
    name: 'NEXTAI-03 MCP tool issues Stripe refunds without approval',
    detects: f('src/mcp/billing-server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import Stripe from 'stripe';
import { z } from 'zod';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export const server = new McpServer({ name: 'billing', version: '1.0.0' });

server.tool(
  'refund_charge',
  'Refund a customer charge',
  { chargeId: z.string(), amount: z.number().int() },
  async ({ chargeId, amount }) => {
    const refund = await stripe.refunds.create({ charge: chargeId, amount });
    return { content: [{ type: 'text', text: refund.id }] };
  }
);
`),
    ignores: f('src/mcp/billing-server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import Stripe from 'stripe';
import { z } from 'zod';
import { db } from '../db';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export const server = new McpServer({ name: 'billing', version: '1.0.0' });

server.tool(
  'request_refund',
  'Queue a refund for a support agent to approve',
  { chargeId: z.string(), amount: z.number().int() },
  async ({ chargeId, amount }) => {
    const pending = await db.refundRequest.create({ data: { chargeId, amount, status: 'pending_approval' } });
    return { content: [{ type: 'text', text: pending.id }] };
  }
);
`)
  },
  // ---------------------------------------------------------------- AI-APP-05 (MCP resources)
  {
    ruleIds: [28205],
    name: 'AI-APP-05 MCP resource handler reads the requested file:// URI from disk',
    detects: f('src/server.ts', `import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const DOCS_ROOT = path.resolve('docs');
const server = new Server({ name: 'docs', version: '1.0.0' }, { capabilities: { resources: {} } });

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;
  const filePath = path.join(DOCS_ROOT, uri.replace('docs://', ''));
  const text = await readFile(filePath, 'utf8');
  return { contents: [{ uri, mimeType: 'text/markdown', text }] };
});
`),
    ignores: f('src/server.ts', `import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const DOCS_ROOT = path.resolve('docs');
const server = new Server({ name: 'docs', version: '1.0.0' }, { capabilities: { resources: {} } });

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;
  const filePath = path.resolve(DOCS_ROOT, uri.replace('docs://', ''));
  if (!filePath.startsWith(DOCS_ROOT + path.sep)) throw new Error('Resource not found');
  const text = await readFile(filePath, 'utf8');
  return { contents: [{ uri, mimeType: 'text/markdown', text }] };
});
`)
  },
  {
    ruleIds: [28205],
    name: 'AI-APP-05 MCP resource template variable joined into a file path',
    detects: f('src/mcp.ts', `import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import fs from 'node:fs/promises';
import path from 'node:path';

const server = new McpServer({ name: 'notes', version: '1.0.0' });

server.registerResource(
  'note',
  new ResourceTemplate('notes://{name}', { list: undefined }),
  { title: 'Note', mimeType: 'text/plain' },
  async (uri, { name }) => ({
    contents: [{ uri: uri.href, text: await fs.readFile(path.join('notes', String(name)), 'utf8') }],
  })
);
`),
    ignores: f('src/mcp.ts', `import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import fs from 'node:fs/promises';
import path from 'node:path';

const server = new McpServer({ name: 'notes', version: '1.0.0' });

server.registerResource(
  'note',
  new ResourceTemplate('notes://{name}', { list: undefined }),
  { title: 'Note', mimeType: 'text/plain' },
  async (uri, { name }) => ({
    contents: [{ uri: uri.href, text: await fs.readFile(path.join('notes', path.basename(String(name))), 'utf8') }],
  })
);
`)
  },
];
