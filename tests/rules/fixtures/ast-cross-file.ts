import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

// Cross-file auth: helpers exported from another module, and Next.js middleware.ts coverage.

const TEAM_HELPER: CodeFile = {
  path: 'lib/team.ts',
  content: `import { auth } from '@/auth';
import { redirect } from 'next/navigation';
import { prisma } from '@/lib/db';

export async function currentTeam() {
  const session = await auth();
  if (!session) redirect('/login');
  return prisma.team.findFirst({ where: { ownerId: session.user.id } });
}
`,
};

const GUARD_HELPER: CodeFile = {
  path: 'src/lib/guards.ts',
  content: `import { getServerSession } from 'next-auth';
import { authOptions } from './auth-options';

async function loadSession() {
  const session = await getServerSession(authOptions);
  if (!session) throw new Error('Unauthorized');
  return session;
}

export const assertSignedIn = async () => {
  await loadSession();
};
`,
};

const DELETE_NOTE = `import { prisma } from '@/lib/db';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await prisma.note.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [29301], name: 'AST-01 IDOR once an imported helper (lib/team.ts) authenticates the caller',
    detects: [TEAM_HELPER, {
      path: 'app/api/invoices/[id]/route.ts',
      content: `import { currentTeam } from '@/lib/team';
import { prisma } from '@/lib/db';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const team = await currentTeam();
  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });
  return Response.json(invoice);
}
`,
    }],
    ignores: [TEAM_HELPER, {
      path: 'app/api/invoices/[id]/route.ts',
      content: `import { currentTeam } from '@/lib/team';
import { prisma } from '@/lib/db';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const team = await currentTeam();
  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, teamId: team.id } });
  return Response.json(invoice);
}
`,
    }],
  },
  {
    ruleIds: [29302], name: 'AST-02 suppressed when an imported helper (two hops, src/lib) authenticates',
    detects: [GUARD_HELPER, { path: 'src/app/api/notes/[id]/route.ts', content: DELETE_NOTE }],
    ignores: [GUARD_HELPER, {
      path: 'src/app/api/notes/[id]/route.ts',
      content: `import { prisma } from '@/lib/db';
import { assertSignedIn } from '@/lib/guards';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await assertSignedIn();
  await prisma.note.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`,
    }],
  },
  {
    ruleIds: [29302], name: 'AST-02 suppressed only when middleware.ts covers the route',
    // middleware authenticates, but its matcher does not include /api
    detects: [
      { path: 'middleware.ts', content: `export { default } from 'next-auth/middleware';
export const config = { matcher: ['/dashboard/:path*'] };
` },
      { path: 'app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
    ignores: [
      { path: 'middleware.ts', content: `export { default } from 'next-auth/middleware';
export const config = { matcher: ['/dashboard/:path*', '/api/notes/:path*'] };
` },
      { path: 'app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
  },
  {
    ruleIds: [29302], name: 'AST-02 kept for routes Clerk marks public',
    detects: [
      { path: 'src/middleware.ts', content: `import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

const isPublicRoute = createRouteMatcher(['/', '/api/notes(.*)']);

export default clerkMiddleware(async (auth, req) => {
  if (!isPublicRoute(req)) await auth.protect();
});

export const config = {
  matcher: ['/((?!_next|[^?]*\\\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)', '/(api|trpc)(.*)'],
};
` },
      { path: 'src/app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
    ignores: [
      { path: 'src/middleware.ts', content: `import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

const isPublicRoute = createRouteMatcher(['/', '/sign-in(.*)']);

export default clerkMiddleware(async (auth, req) => {
  if (!isPublicRoute(req)) await auth.protect();
});

export const config = {
  matcher: ['/((?!_next|[^?]*\\\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)', '/(api|trpc)(.*)'],
};
` },
      { path: 'src/app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
  },
  {
    ruleIds: [29302], name: 'AST-02 middleware is not trusted on a next@ pinned to a CVE-2025-29927 release',
    detects: [
      { path: 'package.json', content: '{ "dependencies": { "next": "15.1.0", "next-auth": "4.24.7" } }' },
      { path: 'middleware.ts', content: `export { default } from 'next-auth/middleware';
export const config = { matcher: ['/api/notes/:path*'] };
` },
      { path: 'app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
    ignores: [
      { path: 'package.json', content: '{ "dependencies": { "next": "15.2.3", "next-auth": "4.24.7" } }' },
      { path: 'middleware.ts', content: `export { default } from 'next-auth/middleware';
export const config = { matcher: ['/api/notes/:path*'] };
` },
      { path: 'app/api/notes/[id]/route.ts', content: DELETE_NOTE },
    ],
  },
];
