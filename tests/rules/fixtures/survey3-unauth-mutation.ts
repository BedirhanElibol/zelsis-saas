import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [15],
    name: 'SEC-15 unauthenticated DELETE route vs requireAdminRequest helper and public auth routes',
    detects: f('app/api/posts/route.ts', `import { db } from '@/lib/db';

export async function DELETE(req: Request) {
  await db.post.deleteMany();
  return Response.json({ ok: true });
}
`),
    ignores: [
      ...f('app/api/admin/tenants/route.ts', `import { requireAdminRequest } from '@/lib/admin';
import { db } from '@/lib/db';

export async function POST(request: Request) {
  await requireAdminRequest(request);
  const body = await request.json();
  return Response.json(await db.tenant.create({ data: { name: body.name } }));
}

export async function PATCH(request: Request) {
  await requireAdminRequest(request);
  const body = await request.json();
  return Response.json(await db.tenant.update({ where: { id: body.id }, data: { name: body.name } }));
}
`),
      ...f('src/app/api/forgot-password/reset/route.ts', `import { db } from '@/lib/db';

export async function POST(request: Request) {
  const { email } = await request.json();
  await db.passwordReset.create({ data: { email } });
  return Response.json({ sent: true });
}
`),
      ...f('src/app/api/auth/register/route.ts', `import { db } from '@/lib/db';

export async function POST(request: Request) {
  const { email } = await request.json();
  await db.user.create({ data: { email } });
  return Response.json({ created: true });
}
`),
      ...f('src/app/api/verify-email/route.ts', `import { db } from '@/lib/db';

export async function POST(request: Request) {
  const { code } = await request.json();
  await db.verification.deleteMany({ where: { code } });
  return Response.json({ verified: true });
}
`)
    ]
  }
];
