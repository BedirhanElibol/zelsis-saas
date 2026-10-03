import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/** Built at runtime so secret scanners do not flag this fixture file. */
const djangoKey = ['n8v2kq5x', '7r1t4y6u0e3w9zpa'].join('');

/**
 * Wave 3-1: database/ORM, Python, zero-trust, k8s, crypto, web-vitals, Postgres, Terraform and PHP rules that were
 * narrowed (or downgraded) instead of removed. Every `ignores` is the idiomatic fix of the same code.
 */
export const CASES: RuleCase[] = [
  // ─── Database / ORM ───────────────────────────────────────────────────
  {
    ruleIds: [6001],
    name: 'DB-PERF-01: Prisma query awaited once per loop element',
    detects: f('lib/posts.ts', `import { prisma } from './db';

export async function getAuthors(postIds: string[]) {
  const authors = [];
  for (const id of postIds) {
    const post = await prisma.post.findUnique({ where: { id }, include: { author: true } });
    authors.push(post?.author);
  }
  return authors;
}
`),
    ignores: f('lib/posts.ts', `import { prisma } from './db';

export async function getAuthors(postIds: string[]) {
  const posts = await prisma.post.findMany({ where: { id: { in: postIds } }, include: { author: true } });
  return posts.map((post) => post.author);
}
`),
  },
  {
    ruleIds: [6003],
    name: 'DB-PERF-03: deep offset pagination',
    detects: f('lib/archive.ts', `import { Post } from './models/post';

export async function loadArchive() {
  return Post.find().sort({ createdAt: -1 }).skip(10000).limit(50);
}
`),
    ignores: f('lib/archive.ts', `import { Post } from './models/post';

export async function loadArchive(cursor: Date) {
  return Post.find({ createdAt: { $lt: cursor } }).sort({ createdAt: -1 }).limit(50);
}
`),
  },
  {
    ruleIds: [6010],
    name: 'DB-PERF-10: Supabase public table without RLS',
    detects: f('supabase/migrations/20260101_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);
`),
    ignores: f('supabase/migrations/20260101_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all using (auth.uid() = user_id);
`),
  },
  {
    ruleIds: [6017],
    name: 'DB-PERF-17: single-column index made redundant by a composite on the same table',
    detects: f('db/migrations/20260101_order_indexes.sql', `CREATE INDEX idx_orders_user_id ON orders (user_id);
CREATE INDEX idx_orders_user_id_created_at ON orders (user_id, created_at);
`),
    ignores: f('db/migrations/20260101_order_indexes.sql', `CREATE INDEX idx_orders_user_id_created_at ON orders (user_id, created_at);
`),
  },

  // ─── Python ───────────────────────────────────────────────────────────
  {
    ruleIds: [8803],
    name: 'PY-SEC-03: shell=True with an interpolated command',
    detects: f('app/services/backup.py', `import subprocess


def archive_upload(filename):
    subprocess.run(f"tar -czf /backups/{filename}.tgz /uploads/{filename}", shell=True, check=True)
`),
    ignores: f('app/services/backup.py', `import subprocess


def archive_upload(filename):
    subprocess.run(["tar", "-czf", f"/backups/{filename}.tgz", f"/uploads/{filename}"], check=True)
`),
  },
  {
    ruleIds: [8804],
    name: 'PY-SEC-04: f-string value interpolated into executed SQL',
    detects: f('app/repositories/users.py', `def find_user(cursor, email):
    cursor.execute(f"SELECT id, email FROM users WHERE email = '{email}'")
    return cursor.fetchone()
`),
    ignores: f('app/repositories/users.py', `def find_user(cursor, email):
    cursor.execute("SELECT id, email FROM users WHERE email = %s", (email,))
    return cursor.fetchone()
`),
  },
  {
    ruleIds: [8805],
    name: 'PY-SEC-05: DEBUG = True in Django settings',
    detects: f('mysite/settings.py', `import os

DEBUG = True
ALLOWED_HOSTS = ["example.com"]
`),
    ignores: f('mysite/settings.py', `import os

DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"
ALLOWED_HOSTS = ["example.com"]
`),
  },
  {
    ruleIds: [8809],
    name: 'PY-SEC-09: Django SECRET_KEY committed as a literal',
    detects: f('mysite/settings.py', `import os

SECRET_KEY = "${djangoKey}"
`),
    ignores: f('mysite/settings.py', `import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
`),
  },
  {
    ruleIds: [8812],
    name: 'PY-SEC-12: password hashed with MD5',
    detects: f('app/auth/passwords.py', `import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
`),
    ignores: f('app/auth/passwords.py', `import bcrypt


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
`),
  },
  {
    ruleIds: [8817],
    name: 'PY-SEC-17: csrf_exempt on a cookie-authenticated form view',
    detects: f('app/views.py', `from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def update_profile(request):
    request.user.profile.bio = request.POST["bio"]
    request.user.profile.save()
    return JsonResponse({"ok": True})
`),
    ignores: f('app/views.py', `from django.http import JsonResponse


def update_profile(request):
    request.user.profile.bio = request.POST["bio"]
    request.user.profile.save()
    return JsonResponse({"ok": True})
`),
  },
  {
    ruleIds: [8822],
    name: 'PY-SEC-22: session cookie readable from JavaScript',
    detects: f('mysite/settings.py', `SESSION_COOKIE_HTTPONLY = False
`),
    ignores: f('mysite/settings.py', `SESSION_COOKIE_HTTPONLY = True
`),
  },
  {
    ruleIds: [8824],
    name: 'PY-SEC-24: authorization enforced with assert',
    detects: f('app/api/admin.py', `def delete_account(user, account_id):
    assert user.is_admin, "admin only"
    Account.objects.filter(id=account_id).delete()
`),
    ignores: f('app/api/admin.py', `def delete_account(user, account_id):
    if not user.is_admin:
        raise PermissionDenied("admin only")
    Account.objects.filter(id=account_id).delete()
`),
  },
  {
    ruleIds: [8829],
    name: 'PY-SEC-29: redirect to the ?next= parameter',
    detects: f('app/routes/auth.py', `@app.route("/login", methods=["POST"])
def login():
    login_user(authenticate(request.form["email"], request.form["password"]))
    return redirect(request.args.get("next"))
`),
    ignores: f('app/routes/auth.py', `@app.route("/login", methods=["POST"])
def login():
    login_user(authenticate(request.form["email"], request.form["password"]))
    return redirect(url_for("dashboard"))
`),
  },
  {
    ruleIds: [8833],
    name: 'PY-SEC-33: nested quantifier regex',
    detects: f('app/validators.py', `import re

USERNAME_RE = re.compile(r"^([a-z0-9]+)*$")
`),
    ignores: f('app/validators.py', `import re

USERNAME_RE = re.compile(r"^[a-z0-9]+$")
`),
  },
  {
    ruleIds: [8835],
    name: 'PY-SEC-35: bare except that passes',
    detects: f('app/tasks.py', `def send_digest(user):
    try:
        mailer.send(user.email, render_digest(user))
    except:
        pass
`),
    ignores: f('app/tasks.py', `def send_digest(user):
    try:
        mailer.send(user.email, render_digest(user))
    except Exception:
        logger.exception("digest failed")
`),
  },
  {
    ruleIds: [8836],
    name: 'PY-SEC-36: HSTS explicitly disabled',
    detects: f('mysite/settings.py', `SECURE_HSTS_SECONDS = 0
`),
    ignores: f('mysite/settings.py', `SECURE_HSTS_SECONDS = 31536000
`),
  },
  {
    ruleIds: [8845],
    name: 'PY-SEC-45: requests call without a timeout',
    detects: f('app/clients/github.py', `import requests


def fetch_profile(username):
    resp = requests.get(f"https://api.github.com/users/{username}")
    return resp.json()
`),
    ignores: f('app/clients/github.py', `import requests


def fetch_profile(username):
    resp = requests.get(f"https://api.github.com/users/{username}", timeout=10)
    return resp.json()
`),
  },
  {
    ruleIds: [8849],
    name: 'PY-SEC-49: session cookie lives for a year',
    detects: f('mysite/settings.py', `SESSION_COOKIE_AGE = 31536000
`),
    ignores: f('mysite/settings.py', `SESSION_COOKIE_AGE = 1209600
`),
  },

  // ─── Zero trust ───────────────────────────────────────────────────────
  {
    ruleIds: [8102],
    name: 'ZERO-AUTH-02: access token valid for 30 days',
    detects: f('lib/auth/tokens.ts', `import jwt from 'jsonwebtoken';

export function issueAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET!, { expiresIn: '30d' });
}
`),
    ignores: f('lib/auth/tokens.ts', `import jwt from 'jsonwebtoken';

export function issueAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET!, { expiresIn: '15m' });
}
`),
  },
  {
    ruleIds: [8117],
    name: 'ZERO-AUTH-17: sign-up schema accepts 4-character passwords',
    detects: f('app/(auth)/signup/schema.ts', `import { z } from 'zod';

export const signUpSchema = z.object({
  email: z.string().email(),
  password: z.string().min(4),
});
`),
    ignores: f('app/(auth)/signup/schema.ts', `import { z } from 'zod';

export const signUpSchema = z.object({
  email: z.string().email(),
  password: z.string().min(12),
});
`),
  },
  {
    ruleIds: [8142],
    name: 'ZERO-AUTH-42: GraphQL introspection forced on',
    detects: f('server/graphql.ts', `import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});
`),
    ignores: f('server/graphql.ts', `import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
`),
  },
  {
    ruleIds: [8143],
    name: 'ZERO-AUTH-43: webhook acts on an unverified payload',
    detects: f('app/api/webhooks/github/route.ts', `export async function POST(req: Request) {
  const event = await req.json();
  await deploy(event);
  return new Response('ok');
}
`),
    ignores: f('app/api/webhooks/github/route.ts', `export async function POST(req: Request) {
  const body = await req.text();
  if (!verifyGithubSignature(body, req.headers.get('x-hub-signature-256'), process.env.GITHUB_WEBHOOK_SECRET!)) {
    return new Response('bad signature', { status: 401 });
  }
  await deploy(JSON.parse(body));
  return new Response('ok');
}
`),
  },

  // ─── Kubernetes / crypto / Terraform ──────────────────────────────────
  {
    ruleIds: [8902],
    name: 'K8S-02: container pinned to UID 0',
    detects: f('k8s/api-deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          securityContext:
            runAsUser: 0
`),
    ignores: f('k8s/api-deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
`),
  },
  {
    ruleIds: [13302],
    name: 'CRYPTO-02: KMS key without automatic rotation',
    detects: f('infra/kms.tf', `resource "aws_kms_key" "app" {
  description             = "app data key"
  deletion_window_in_days = 30
}
`),
    ignores: f('infra/kms.tf', `resource "aws_kms_key" "app" {
  description             = "app data key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
`),
  },
  {
    ruleIds: [13305],
    name: 'CRYPTO-05: 1024-bit RSA key generation',
    detects: f('lib/crypto/keys.ts', `import { generateKeyPairSync } from 'node:crypto';

export const signingKeys = generateKeyPairSync('rsa', { modulusLength: 1024 });
`),
    ignores: f('lib/crypto/keys.ts', `import { generateKeyPairSync } from 'node:crypto';

export const signingKeys = generateKeyPairSync('rsa', { modulusLength: 4096 });
`),
  },
  {
    ruleIds: [11005],
    name: 'TF-05: registry module without a version pin',
    detects: f('infra/main.tf', `module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name   = "app"
  cidr   = "10.0.0.0/16"
}
`),
    ignores: f('infra/main.tf', `module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
  name    = "app"
  cidr    = "10.0.0.0/16"
}
`),
  },

  // ─── Web vitals / Postgres / PHP ──────────────────────────────────────
  {
    ruleIds: [7102],
    name: 'WEB-PERF-02: img without dimensions',
    detects: f('components/Avatar.tsx', `export function Avatar({ user }: { user: { avatarUrl: string; name: string } }) {
  return <img src={user.avatarUrl} alt={user.name} />;
}
`),
    ignores: f('components/Avatar.tsx', `export function Avatar({ user }: { user: { avatarUrl: string; name: string } }) {
  return <img src={user.avatarUrl} alt={user.name} width={40} height={40} />;
}
`),
  },
  {
    ruleIds: [10305],
    name: 'PG-05: row set locked FOR UPDATE without ORDER BY',
    detects: f('lib/billing/transfer.ts', `export async function transfer(client: PoolClient, fromId: string, toId: string, amount: number) {
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT id, balance FROM accounts WHERE id = ANY($1) FOR UPDATE', [[fromId, toId]]);
  await applyTransfer(client, rows, amount);
  await client.query('COMMIT');
}
`),
    ignores: f('lib/billing/transfer.ts', `export async function transfer(client: PoolClient, fromId: string, toId: string, amount: number) {
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT id, balance FROM accounts WHERE id = ANY($1) ORDER BY id FOR UPDATE', [[fromId, toId]]);
  await applyTransfer(client, rows, amount);
  await client.query('COMMIT');
}
`),
  },
  {
    ruleIds: [18005],
    name: 'PHP-SEC-05: query parameter echoed into the page',
    detects: f('public/search.php', `<?php
echo "Results for " . $_GET['q'];
`),
    ignores: f('public/search.php', `<?php
echo "Results for " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
`),
  },
];
