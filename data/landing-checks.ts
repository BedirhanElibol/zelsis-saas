/**
 * Showcase cards for the landing page. Each `bad` snippet must trigger `ruleId` and each `good`
 * snippet must not: tests/unit/landing-checks.test.ts scans them, so the page never advertises a
 * check the engine does not actually perform.
 */
export interface LandingCheck {
  title: string;
  description: string;
  ruleId: number;
  code: string;
  path: string;
  bad: string;
  good: string;
}

export const LANDING_CHECKS: LandingCheck[] = [
  {
    title: 'Service-role key in a Server Action',
    description: 'A Server Action writes with the Supabase service-role client (which bypasses RLS) without checking who is calling.',
    ruleId: 28001,
    code: 'NEXT-SB-01',
    path: 'app/dashboard/projects/actions.ts',
    bad: `'use server';
import { createClient } from '@supabase/supabase-js';

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  await admin.from('projects').delete().eq('id', projectId);
}
`,
    good: `'use server';
import { createClient } from '@supabase/supabase-js';
import { createClient as createServerClient } from '@/utils/supabase/server';

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;
  await admin.from('projects').delete().eq('id', projectId).eq('owner_id', user.id);
}
`,
  },
  {
    title: 'Cached data served to the wrong user',
    description: 'unstable_cache reads the signed-in user from the surrounding scope but keys the cache without it, so one user\'s data is served to everyone.',
    ruleId: 28751,
    code: 'NEXTAI-01',
    path: 'app/dashboard/orders/page.tsx',
    bad: `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

export default async function OrdersPage() {
  const userId = (await auth())?.user?.id;
  const getOrders = unstable_cache(
    async () => db.order.findMany({ where: { userId } }),
    ['dashboard-orders']
  );
  return <OrderList orders={await getOrders()} />;
}
`,
    good: `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

const getOrders = unstable_cache(
  async (userId: string) => db.order.findMany({ where: { userId } }),
  ['dashboard-orders']
);

export default async function OrdersPage() {
  const userId = (await auth())?.user?.id;
  return <OrderList orders={await getOrders(userId!)} />;
}
`,
  },
  {
    title: 'Webhook that pays out twice',
    description: 'Stripe and Polar retry deliveries. A handler that adds credits without recording the event id grants them again on every retry.',
    ruleId: 28702,
    code: 'SAAS3-02',
    path: 'app/api/stripe/webhook/route.ts',
    bad: `export async function POST(req: Request) {
  const evt = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  if (evt.type === 'checkout.session.completed') {
    await prisma.user.update({
      where: { id: evt.data.object.metadata.userId },
      data: { credits: { increment: 100 } },
    });
  }
  return new Response('ok');
}
`,
    good: `export async function POST(req: Request) {
  const evt = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  if (evt.type === 'checkout.session.completed') {
    await prisma.$transaction(async (tx) => {
      if (await tx.processedWebhook.findUnique({ where: { id: evt.id } })) return;
      await tx.processedWebhook.create({ data: { id: evt.id } });
      await tx.user.update({
        where: { id: evt.data.object.metadata.userId },
        data: { credits: { increment: 100 } },
      });
    });
  }
  return new Response('ok');
}
`,
  },
  {
    title: 'Admin check on a token nobody verified',
    description: 'Express middleware reads the role from jwt.decode(), which only base64-decodes the token. Anyone can sign their own token with role "admin".',
    ruleId: 39,
    code: 'RULE-39',
    path: 'src/middleware/auth.js',
    bad: `const jwt = require('jsonwebtoken');

module.exports = function requireAdmin(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
  const user = jwt.decode(token);
  if (user.role !== 'admin') return res.status(403).end();
  req.user = user;
  next();
};
`,
    good: `const jwt = require('jsonwebtoken');

module.exports = function requireAdmin(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
  const user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  if (user.role !== 'admin') return res.status(403).end();
  req.user = user;
  next();
};
`,
  },
  {
    title: 'Delete endpoint anyone can call',
    description: 'A FastAPI DELETE route with a database session but no user dependency: anyone who can reach the API can delete any project by id.',
    ruleId: 28838,
    code: 'GAP-38',
    path: 'app/api/routes/projects.py',
    bad: `from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Project

router = APIRouter()

@router.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    db.query(Project).filter(Project.id == project_id).delete()
    db.commit()
`,
    good: `from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.auth import get_current_user
from app.models import Project, User

router = APIRouter()

@router.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db.query(Project).filter(Project.id == project_id, Project.owner_id == current_user.id).delete()
    db.commit()
`,
  },
  {
    title: 'MCP server launched from a request',
    description: 'An endpoint that starts an MCP stdio server with a command taken from the request lets anyone run programs on your server.',
    ruleId: 28304,
    code: 'LLM-V2-04',
    path: 'server/mcp-proxy.ts',
    bad: `app.get('/connect', async (req, res) => {
  const transport = new StdioClientTransport({
    command: req.query.command as string,
    args: (req.query.args as string).split(' '),
  });
  await client.connect(transport);
});
`,
    good: `app.get('/connect', async (req, res) => {
  const server = SERVERS[String(req.query.server)];
  if (!server) return res.status(404).end();
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args,
  });
  await client.connect(transport);
});
`,
  },
  {
    title: 'Users who can make themselves admin',
    description: 'permit! lets the request set every column, so a user updating their profile can also send admin=true (Rails mass assignment).',
    ruleId: 18032,
    code: 'RUBY-SEC-02',
    path: 'app/controllers/users_controller.rb',
    bad: `class UsersController < ApplicationController
  def update
    @user = current_user
    @user.update(params.require(:user).permit!)
    redirect_to @user
  end
end
`,
    good: `class UsersController < ApplicationController
  def update
    @user = current_user
    @user.update(params.require(:user).permit(:name, :email, :avatar))
    redirect_to @user
  end
end
`,
  },
  {
    title: 'SQL built from a query string',
    description: 'A Go handler formats the request value into the SQL text, so a crafted email reads or changes any row in the database.',
    ruleId: 24101,
    code: 'CORE-01',
    path: 'handlers/users.go',
    bad: `package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func FindUser(c *gin.Context) {
	email := c.Query("email")
	rows, _ := db.Query(fmt.Sprintf("SELECT id, name FROM users WHERE email = '%s'", email))
	defer rows.Close()
	c.JSON(200, rows)
}
`,
    good: `package handlers

import "github.com/gin-gonic/gin"

func FindUser(c *gin.Context) {
	email := c.Query("email")
	rows, _ := db.Query("SELECT id, name FROM users WHERE email = $1", email)
	defer rows.Close()
	c.JSON(200, rows)
}
`,
  },
];
