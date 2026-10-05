import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29301], name: 'AST-01 IDOR: signed-in route loads invoice by URL id through a helper',
    detects: f('app/api/invoices/[id]/route.ts', `import { auth } from '@/auth';
import { prisma } from '@/lib/prisma';

async function loadInvoice(invoiceId: string) {
  return prisma.invoice.findUnique({ where: { id: invoiceId }, include: { lines: true } });
}

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user) return new Response(null, { status: 401 });
  const { id } = await params;
  const invoice = await loadInvoice(id);
  return Response.json(invoice);
}
`),
    ignores: f('app/api/invoices/[id]/route.ts', `import { auth } from '@/auth';
import { prisma } from '@/lib/prisma';

async function loadInvoice(invoiceId: string) {
  return prisma.invoice.findUnique({ where: { id: invoiceId }, include: { lines: true } });
}

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user) return new Response(null, { status: 401 });
  const { id } = await params;
  const invoice = await loadInvoice(id);
  if (!invoice || invoice.userId !== session.user.id) return new Response(null, { status: 404 });
  return Response.json(invoice);
}
`),
  },
  {
    ruleIds: [29301], name: 'AST-01 IDOR: protected tRPC mutation deletes a project by input id',
    detects: f('src/server/api/routers/project.ts', `import { z } from 'zod';
import { createTRPCRouter, protectedProcedure } from '@/server/api/trpc';

export const projectRouter = createTRPCRouter({
  delete: protectedProcedure
    .input(z.object({ projectId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const { projectId } = input;
      return ctx.db.project.delete({ where: { id: projectId } });
    }),
});
`),
    ignores: f('src/server/api/routers/project.ts', `import { z } from 'zod';
import { createTRPCRouter, protectedProcedure } from '@/server/api/trpc';

export const projectRouter = createTRPCRouter({
  delete: protectedProcedure
    .input(z.object({ projectId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const { projectId } = input;
      return ctx.db.project.delete({ where: { id: projectId, ownerId: ctx.session.user.id } });
    }),
});
`),
  },
  {
    ruleIds: [29301], name: 'AST-01 IDOR: Server Action updates a document with the service-role client',
    detects: f('app/documents/actions.ts', `'use server';
import { createClient } from '@/utils/supabase/server';
import { supabaseAdmin } from '@/utils/supabase/admin';

export async function archiveDocument(formData: FormData) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Not signed in');
  const documentId = String(formData.get('documentId'));
  await supabaseAdmin.from('documents').update({ archived: true }).eq('id', documentId);
}
`),
    ignores: f('app/documents/actions.ts', `'use server';
import { createClient } from '@/utils/supabase/server';
import { supabaseAdmin } from '@/utils/supabase/admin';

export async function archiveDocument(formData: FormData) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Not signed in');
  const documentId = String(formData.get('documentId'));
  await supabaseAdmin.from('documents').update({ archived: true }).eq('id', documentId).eq('owner_id', user.id);
}
`),
  },
  {
    ruleIds: [29301], name: 'AST-01 IDOR: Express route behind auth middleware deletes a note by id',
    detects: f('src/routes/notes.js', `const express = require('express');
const Note = require('../models/note');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.delete('/notes/:id', requireAuth, async (req, res) => {
  const noteId = req.params.id;
  const note = await Note.findByIdAndDelete(noteId);
  res.json({ deleted: Boolean(note) });
});

module.exports = router;
`),
    ignores: f('src/routes/notes.js', `const express = require('express');
const Note = require('../models/note');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.delete('/notes/:id', requireAuth, async (req, res) => {
  const noteId = req.params.id;
  const note = await Note.findOneAndDelete({ _id: noteId, owner: req.user.id });
  res.json({ deleted: Boolean(note) });
});

module.exports = router;
`),
  },
  {
    ruleIds: [29302], name: 'AST-02 Server Action deletes a membership with no auth',
    detects: f('app/settings/team/actions.ts', `'use server';
import { db } from '@/lib/db';
import { revalidatePath } from 'next/cache';

export async function removeMember(formData: FormData) {
  const memberId = formData.get('memberId') as string;
  await db.membership.delete({ where: { id: memberId } });
  revalidatePath('/settings/team');
}
`),
    ignores: f('app/settings/team/actions.ts', `'use server';
import { auth } from '@/auth';
import { db } from '@/lib/db';
import { revalidatePath } from 'next/cache';

export async function removeMember(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  const memberId = formData.get('memberId') as string;
  await db.membership.delete({ where: { id: memberId, team: { ownerId: session.user.id } } });
  revalidatePath('/settings/team');
}
`),
  },
  {
    ruleIds: [29302], name: 'AST-02 PATCH route updates a post (Drizzle) with no auth',
    detects: f('app/api/posts/[id]/route.ts', `import { db } from '@/db';
import { posts } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { title } = await req.json();
  await db.update(posts).set({ title }).where(eq(posts.id, id));
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/posts/[id]/route.ts', `import { db } from '@/db';
import { posts } from '@/db/schema';
import { and, eq } from 'drizzle-orm';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response(null, { status: 401 });
  const { id } = await params;
  const { title } = await req.json();
  await db.update(posts).set({ title }).where(and(eq(posts.id, id), eq(posts.authorId, session.user.id)));
  return Response.json({ ok: true });
}
`),
  },
  {
    ruleIds: [29303], name: 'AST-03 SQL injection: query fragment built in a helper from searchParams',
    detects: f('app/api/orders/route.ts', `import { prisma } from '@/lib/prisma';

function buildFilter(field: string, value: string) {
  return \`WHERE \${field} = '\${value}'\`;
}

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams;
  const status = query.get('status') ?? 'open';
  const where = buildFilter('status', status);
  const rows = await prisma.$queryRawUnsafe(\`SELECT id, total FROM "Order" \${where}\`);
  return Response.json(rows);
}
`),
    ignores: f('app/api/orders/route.ts', `import { prisma } from '@/lib/prisma';

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams;
  const status = query.get('status') ?? 'open';
  const rows = await prisma.$queryRaw\`SELECT id, total FROM "Order" WHERE status = \${status}\`;
  return Response.json(rows);
}
`),
  },
  {
    ruleIds: [29304], name: 'AST-04 command injection: command line joined from request body',
    detects: f('app/api/repos/clone/route.ts', `import { execSync } from 'child_process';

export async function POST(req: Request) {
  const body = await req.json();
  const repo = body.repository.trim();
  const target = \`/tmp/clones/\${Date.now()}\`;
  const cmd = ['git clone', repo, target].join(' ');
  execSync(cmd);
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/repos/clone/route.ts', `import { execFileSync } from 'child_process';

export async function POST(req: Request) {
  const body = await req.json();
  const repo = body.repository.trim();
  const target = \`/tmp/clones/\${Date.now()}\`;
  execFileSync('git', ['clone', '--', repo, target]);
  return Response.json({ ok: true });
}
`),
  },
  {
    ruleIds: [29305], name: 'AST-05 path traversal: docs page path built from a query parameter',
    detects: f('app/api/docs/route.ts', `import { readFile } from 'fs/promises';
import path from 'path';
import type { NextRequest } from 'next/server';

const DOCS_DIR = path.join(process.cwd(), 'docs');

export async function GET(req: NextRequest) {
  const slug = req.nextUrl.searchParams.get('page') ?? 'index';
  const file = path.join(DOCS_DIR, \`\${slug}.md\`);
  const markdown = await readFile(file, 'utf8');
  return new Response(markdown);
}
`),
    ignores: f('app/api/docs/route.ts', `import { readFile } from 'fs/promises';
import path from 'path';
import type { NextRequest } from 'next/server';

const DOCS_DIR = path.join(process.cwd(), 'docs');

export async function GET(req: NextRequest) {
  const slug = req.nextUrl.searchParams.get('page') ?? 'index';
  const file = path.join(DOCS_DIR, \`\${path.basename(slug)}.md\`);
  const markdown = await readFile(file, 'utf8');
  return new Response(markdown);
}
`),
  },
  {
    ruleIds: [29306], name: 'AST-06 SSRF: feed URL from the body fetched server side',
    detects: f('app/api/feeds/preview/route.ts', `export async function POST(req: Request) {
  const { feedUrl } = await req.json();
  const target = new URL(feedUrl);
  const res = await fetch(target.toString(), { headers: { accept: 'application/rss+xml' } });
  return new Response(await res.text(), { headers: { 'content-type': 'text/xml' } });
}
`),
    ignores: f('app/api/feeds/preview/route.ts', `const ALLOWED_HOSTS = new Set(['feeds.example.com', 'rss.example.org']);

export async function POST(req: Request) {
  const { feedUrl } = await req.json();
  const target = new URL(feedUrl);
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) return new Response(null, { status: 400 });
  const res = await fetch(target.toString(), { headers: { accept: 'application/rss+xml' } });
  return new Response(await res.text(), { headers: { 'content-type': 'text/xml' } });
}
`),
  },
  {
    ruleIds: [29307], name: 'AST-07 open redirect: returnTo resolved against the request URL',
    detects: f('app/api/session/route.ts', `import { NextResponse, type NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const returnTo = searchParams.get('returnTo') || '/dashboard';
  const response = NextResponse.redirect(new URL(returnTo, request.url));
  response.cookies.set('seen', '1');
  return response;
}
`),
    ignores: f('app/api/session/route.ts', `import { NextResponse, type NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const returnTo = searchParams.get('returnTo') || '/dashboard';
  const target = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/dashboard';
  const response = NextResponse.redirect(new URL(target, request.url));
  response.cookies.set('seen', '1');
  return response;
}
`),
  },
  {
    ruleIds: [29308], name: 'AST-08 DOM XSS: search term from the URL rendered as HTML',
    detects: f('components/search-summary.tsx', `'use client';
import { useSearchParams } from 'next/navigation';

export function SearchSummary() {
  const params = useSearchParams();
  const term = params.get('q') ?? '';
  const html = \`Results for <b>\${term}</b>\`;
  return <p className="text-sm" dangerouslySetInnerHTML={{ __html: html }} />;
}
`),
    ignores: f('components/search-summary.tsx', `'use client';
import { useSearchParams } from 'next/navigation';

export function SearchSummary() {
  const params = useSearchParams();
  const term = params.get('q') ?? '';
  return <p className="text-sm">Results for <b>{term}</b></p>;
}
`),
  },
];
