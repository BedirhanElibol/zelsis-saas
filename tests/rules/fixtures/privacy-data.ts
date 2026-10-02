import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28401], name: 'PRIV-01 login route logs the raw request body',
    detects: f('app/api/auth/login/route.ts', `import bcrypt from 'bcryptjs';
import { NextResponse } from 'next/server';
export async function POST(req: Request) {
  const body = await req.json();
  console.log('login attempt', body);
  const user = await db.user.findUnique({ where: { email: body.email } });
  if (!user || !(await bcrypt.compare(body.password, user.passwordHash))) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('app/api/auth/login/route.ts', `import bcrypt from 'bcryptjs';
import { NextResponse } from 'next/server';
export async function POST(req: Request) {
  const body = await req.json();
  console.log('login attempt', body.email);
  const user = await db.user.findUnique({ where: { email: body.email } });
  if (!user || !(await bcrypt.compare(body.password, user.passwordHash))) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }
  return NextResponse.json({ ok: true });
}
`)
  },
  {
    ruleIds: [28401], name: 'PRIV-01 Flask signup view prints request.json',
    detects: f('app/auth.py', `from flask import request, jsonify
from werkzeug.security import generate_password_hash

@bp.post("/signup")
def signup():
    data = request.get_json()
    print(data)
    user = User(email=data["email"], password_hash=generate_password_hash(data["password"]))
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id), 201
`),
    ignores: f('app/auth.py', `from flask import request, jsonify
from werkzeug.security import generate_password_hash

@bp.post("/signup")
def signup():
    data = request.get_json()
    print("signup", data["email"])
    user = User(email=data["email"], password_hash=generate_password_hash(data["password"]))
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id), 201
`)
  },
  {
    ruleIds: [28402], name: 'PRIV-02 signup form values including password sent to PostHog',
    detects: f('components/signup-form.tsx', `'use client';
import posthog from 'posthog-js';
export function SignupForm() {
  async function onSubmit(values: { email: string; password: string; plan: string }) {
    posthog.capture('signup_submitted', {
      email: values.email,
      password: values.password,
      plan: values.plan,
    });
    await signUp(values);
  }
  return <Form onSubmit={onSubmit} />;
}
`),
    ignores: f('components/signup-form.tsx', `'use client';
import posthog from 'posthog-js';
export function SignupForm() {
  async function onSubmit(values: { email: string; password: string; plan: string }) {
    posthog.capture('signup_submitted', {
      plan: values.plan,
      hasPassword: true,
    });
    await signUp(values);
  }
  return <Form onSubmit={onSubmit} />;
}
`)
  },
  {
    ruleIds: [28403], name: 'PRIV-03 e-mail used as GA4 user_id',
    detects: f('app/providers/analytics.tsx', `'use client';
export function Analytics({ user }: { user: { id: string; email: string } }) {
  useEffect(() => {
    window.gtag('config', process.env.NEXT_PUBLIC_GA_ID, {
      user_id: user.email,
    });
  }, [user]);
  return null;
}
`),
    ignores: f('app/providers/analytics.tsx', `'use client';
export function Analytics({ user }: { user: { id: string; email: string } }) {
  useEffect(() => {
    window.gtag('config', process.env.NEXT_PUBLIC_GA_ID, {
      user_id: user.id,
    });
  }, [user]);
  return null;
}
`)
  },
  {
    ruleIds: [28404], name: 'PRIV-04 Express login returns user with password hash',
    detects: f('src/routes/auth.ts', `import bcrypt from 'bcrypt';
router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = signToken(user.id);
  res.json({ token, user });
});
`),
    ignores: f('src/routes/auth.ts', `import bcrypt from 'bcrypt';
router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = signToken(user.id);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});
`)
  },
  {
    ruleIds: [28405], name: 'PRIV-05 webhook handler logs all request headers',
    detects: f('src/routes/webhooks.ts', `router.post('/webhooks/github', async (req, res) => {
  logger.info('incoming webhook', { headers: req.headers });
  await handleEvent(req.body);
  res.sendStatus(204);
});
`),
    ignores: f('src/routes/webhooks.ts', `router.post('/webhooks/github', async (req, res) => {
  logger.info('incoming webhook', { event: req.headers['x-github-event'] });
  await handleEvent(req.body);
  res.sendStatus(204);
});
`)
  },
  {
    ruleIds: [28406], name: "PRIV-06 DRF User serializer with fields='__all__'",
    detects: f('accounts/serializers.py', `from django.contrib.auth import get_user_model
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = '__all__'
`),
    ignores: f('accounts/serializers.py', `from django.contrib.auth import get_user_model
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email']
        extra_kwargs = {'password': {'write_only': True}}
`)
  },
  {
    ruleIds: [28407], name: 'PRIV-07 Django view returns User.objects.values()',
    detects: f('accounts/views.py', `from django.contrib.auth.models import User
from django.http import JsonResponse

def member_list(request):
    members = list(User.objects.filter(is_active=True).values())
    return JsonResponse(members, safe=False)
`),
    ignores: f('accounts/views.py', `from django.contrib.auth.models import User
from django.http import JsonResponse

def member_list(request):
    members = list(User.objects.filter(is_active=True).values('id', 'username'))
    return JsonResponse(members, safe=False)
`)
  },
  {
    ruleIds: [28408], name: 'PRIV-08 Laravel User model without password in $hidden',
    detects: f('app/Models/User.php', `<?php
namespace App\\Models;

use Illuminate\\Foundation\\Auth\\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['remember_token'];

    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
`),
    ignores: f('app/Models/User.php', `<?php
namespace App\\Models;

use Illuminate\\Foundation\\Auth\\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password'];

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
`)
  },
  {
    ruleIds: [28409], name: 'PRIV-09 remember-me stores the password in localStorage',
    detects: f('src/components/LoginForm.tsx', `export function LoginForm() {
  const onSubmit = async ({ email, password, remember }: LoginValues) => {
    if (remember) {
      localStorage.setItem('email', email);
      localStorage.setItem('password', password);
    }
    await login(email, password);
  };
  return <form onSubmit={handleSubmit(onSubmit)} />;
}
`),
    ignores: f('src/components/LoginForm.tsx', `export function LoginForm() {
  const onSubmit = async ({ email, password, remember }: LoginValues) => {
    if (remember) {
      localStorage.setItem('email', email);
    }
    await login(email, password, { persistSession: remember });
  };
  return <form onSubmit={handleSubmit(onSubmit)} />;
}
`)
  },
  {
    ruleIds: [28410], name: 'PRIV-10 nightly pg_dump uploaded public-read',
    detects: f('scripts/backup.sh', `#!/usr/bin/env bash
set -euo pipefail
FILE="backup-$(date +%F).sql.gz"
pg_dump "$DATABASE_URL" | gzip > "$FILE"
aws s3 cp "$FILE" "s3://acme-backups/$FILE" --acl public-read
`),
    ignores: f('scripts/backup.sh', `#!/usr/bin/env bash
set -euo pipefail
FILE="backup-$(date +%F).sql.gz"
pg_dump "$DATABASE_URL" | gzip > "$FILE"
aws s3 cp "$FILE" "s3://acme-backups/$FILE" --sse aws:kms
`)
  },
  {
    ruleIds: [28411], name: 'PRIV-11 public Supabase bucket for KYC documents (migration)',
    detects: f('supabase/migrations/20250101_storage.sql', `insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true);
insert into storage.buckets (id, name, public) values ('kyc-documents', 'kyc-documents', true);
`),
    ignores: f('supabase/migrations/20250101_storage.sql', `insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true);
insert into storage.buckets (id, name, public) values ('kyc-documents', 'kyc-documents', false);
`)
  },
  {
    ruleIds: [28411], name: 'PRIV-11 public Supabase bucket for invoices (createBucket)',
    detects: f('scripts/setup-storage.ts', `const supabase = createClient(url, serviceKey);
await supabase.storage.createBucket('invoices', {
  public: true,
  allowedMimeTypes: ['application/pdf'],
});
`),
    ignores: f('scripts/setup-storage.ts', `const supabase = createClient(url, serviceKey);
await supabase.storage.createBucket('invoices', {
  public: false,
  allowedMimeTypes: ['application/pdf'],
});
`)
  },
  {
    ruleIds: [28412], name: 'PRIV-12 FastAPI /me returns ORM user without response_model',
    detects: f('app/api/routes/users.py', `from fastapi import APIRouter, Depends
from app.models import User

router = APIRouter()

@router.get("/users/me")
def read_user_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/users/{user_id}/password")
def set_password(user_id: int, body: PasswordIn, session: Session = Depends(get_db)):
    user = session.get(User, user_id)
    user.hashed_password = get_password_hash(body.password)
    session.commit()
    return {"ok": True}
`),
    ignores: f('app/api/routes/users.py', `from fastapi import APIRouter, Depends
from app.models import User, UserPublic

router = APIRouter()

@router.get("/users/me", response_model=UserPublic)
def read_user_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/users/{user_id}/password")
def set_password(user_id: int, body: PasswordIn, session: Session = Depends(get_db)):
    user = session.get(User, user_id)
    user.hashed_password = get_password_hash(body.password)
    session.commit()
    return {"ok": True}
`)
  },
  {
    ruleIds: [28413], name: 'PRIV-13 morgan token logs every request body',
    detects: f('src/server.ts', `import express from 'express';
import morgan from 'morgan';
const app = express();
app.use(express.json());
morgan.token('body', (req) => JSON.stringify(req.body));
app.use(morgan(':method :url :status :body'));
`),
    ignores: f('src/server.ts', `import express from 'express';
import morgan from 'morgan';
const app = express();
app.use(express.json());
morgan.token('reqid', (req) => req.headers['x-request-id']);
app.use(morgan(':method :url :status :reqid'));
`)
  },
  {
    ruleIds: [28414], name: 'PRIV-14 Sentry replay with maskAllText disabled',
    detects: f('instrumentation-client.ts', `import * as Sentry from '@sentry/nextjs';
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  replaysSessionSampleRate: 0.1,
  integrations: [
    Sentry.replayIntegration({
      maskAllText: false,
      blockAllMedia: false,
    }),
  ],
});
`),
    ignores: f('instrumentation-client.ts', `import * as Sentry from '@sentry/nextjs';
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  replaysSessionSampleRate: 0.1,
  integrations: [
    Sentry.replayIntegration({
      maskAllText: true,
      unmask: ['.marketing-copy'],
    }),
  ],
});
`)
  },
];
