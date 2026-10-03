import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28801], name: 'GAP-01 RLS update policy using (true)',
    detects: f('supabase/migrations/20250103000000_profiles.sql', `alter table public.profiles enable row level security;
create policy "update profiles" on public.profiles
  for update to authenticated using (true) with check (true);
`),
    ignores: f('supabase/migrations/20250103000000_profiles.sql', `alter table public.profiles enable row level security;
create policy "public read" on public.profiles for select using (true);
create policy "update own profile" on public.profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
create policy "service writes" on public.profiles for all to service_role using (true);
`),
  },
  {
    ruleIds: [28802], name: 'GAP-02 Firestore root wildcard open to any signed-in user',
    detects: f('firestore.rules', `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
`),
    ignores: f('firestore.rules', `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read;
    }
    match /users/{userId}/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
`),
  },
  {
    ruleIds: [28802], name: 'GAP-02 Storage rules allow without condition',
    detects: f('storage.rules', `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write;
    }
  }
}
`),
    ignores: f('storage.rules', `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /avatars/{userId}/{fileName} {
      allow read;
      allow write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
`),
  },
  {
    ruleIds: [28803], name: 'GAP-03 Realtime Database rules true',
    detects: f('database.rules.json', `{
  "rules": {
    ".read": true,
    ".write": true
  }
}
`),
    ignores: f('database.rules.json', `{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
`),
  },
  {
    ruleIds: [28804], name: 'GAP-04 Supabase profile update with whole request body',
    detects: f('app/api/profile/route.ts', `import { createClient } from '@/lib/supabase/server';
export async function PUT(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  const updates = await req.json();
  const { data } = await supabase.from('profiles').update(updates).eq('id', user.id).select().single();
  return Response.json(data);
}
`),
    ignores: f('app/api/profile/route.ts', `import { z } from 'zod';
import { createClient } from '@/lib/supabase/server';
const ProfileUpdate = z.object({ full_name: z.string().max(80), avatar_url: z.string().url().optional() });
export async function PUT(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  const updates = ProfileUpdate.parse(await req.json());
  const { data } = await supabase.from('profiles').update(updates).eq('id', user.id).select().single();
  return Response.json(data);
}
`),
  },
  {
    ruleIds: [28804], name: 'GAP-04 Mongoose findByIdAndUpdate with req.body',
    detects: f('src/routes/users.js', `const router = require('express').Router();
const User = require('../models/User');
router.put('/:id', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});
module.exports = router;
`),
    ignores: f('src/routes/users.js', `const router = require('express').Router();
const User = require('../models/User');
router.put('/:id', async (req, res) => {
  const { name, bio } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { name, bio }, { new: true });
  res.json(user);
});
module.exports = router;
`),
  },
  {
    ruleIds: [28805], name: 'GAP-05 admin gate on role cookie',
    detects: f('app/admin/page.tsx', `import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
export default async function AdminPage() {
  const role = (await cookies()).get('role')?.value;
  if (role !== 'admin') redirect('/');
  return <AdminDashboard />;
}
`),
    ignores: f('app/admin/page.tsx', `import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { getUserRole } from '@/lib/users';
export default async function AdminPage() {
  const session = await auth();
  const role = session ? await getUserRole(session.user.id) : null;
  if (role !== 'admin') redirect('/');
  return <AdminDashboard />;
}
`),
  },
  {
    ruleIds: [28805], name: 'GAP-05 admin flag from query string',
    detects: f('src/routes/admin.js', `app.get('/admin/export', (req, res) => {
  if (req.query.admin === 'true') {
    return res.json(exportAllUsers());
  }
  res.sendStatus(403);
});
`),
    ignores: f('src/routes/admin.js', `app.get('/admin/export', requireAdmin, (req, res) => {
  if (req.query.format === 'csv') return res.send(toCsv(exportAllUsers()));
  res.json(exportAllUsers());
});
`),
  },
  {
    ruleIds: [28806], name: 'GAP-06 x-user-role header',
    detects: f('app/api/admin/stats/route.ts', `export async function GET(req: Request) {
  if (req.headers.get('x-user-role') !== 'admin') {
    return new Response('Forbidden', { status: 403 });
  }
  return Response.json(await getStats());
}
`),
    ignores: f('app/api/admin/stats/route.ts', `import { auth } from '@/auth';
export async function GET() {
  const session = await auth();
  if (session?.user.role !== 'admin') {
    return new Response('Forbidden', { status: 403 });
  }
  return Response.json(await getStats());
}
`),
  },
  {
    ruleIds: [28807], name: 'GAP-07 service role key returned in response',
    detects: f('app/api/config/route.ts', `export async function GET() {
  return Response.json({ url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SERVICE_ROLE_KEY });
}
`),
    ignores: f('app/api/config/route.ts', `export async function GET() {
  return Response.json({ url: process.env.NEXT_PUBLIC_SUPABASE_URL, key: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, billing: !!process.env.STRIPE_SECRET_KEY });
}
`),
  },
  {
    ruleIds: [28808], name: 'GAP-08 express-session literal secret',
    detects: f('src/app.js', `const session = require('express-session');
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}));
`),
    ignores: f('src/app.js', `const session = require('express-session');
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));
`),
  },
  {
    ruleIds: [28808], name: 'GAP-08 NextAuth literal secret',
    detects: f('auth.ts', `import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [GitHub],
  secret: 'my-nextauth-secret-123',
});
`),
    ignores: f('auth.ts', `import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [GitHub],
  secret: process.env.AUTH_SECRET,
});
`),
  },
  {
    ruleIds: [28809], name: 'GAP-09 upload written with client file name',
    detects: f('app/api/upload/route.ts', `import { writeFile } from 'fs/promises';
import path from 'path';
export async function POST(req: Request) {
  const form = await req.formData();
  const upload = form.get('file') as File;
  const bytes = Buffer.from(await upload.arrayBuffer());
  await writeFile(path.join(process.cwd(), 'public/uploads', upload.name), bytes);
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/upload/route.ts', `import { writeFile } from 'fs/promises';
import path from 'path';
import { randomUUID } from 'crypto';
export async function POST(req: Request) {
  const form = await req.formData();
  const upload = form.get('file') as File;
  const bytes = Buffer.from(await upload.arrayBuffer());
  const stored = randomUUID() + '.png';
  await writeFile(path.join(process.cwd(), 'public/uploads', stored), bytes);
  return Response.json({ ok: true, original: upload.name });
}
`),
  },
  {
    ruleIds: [28809], name: 'GAP-09 multer diskStorage originalname',
    detects: f('src/routes/upload.js', `const multer = require('multer');
const storage = multer.diskStorage({
  destination: 'public/uploads',
  filename: (req, file, cb) => cb(null, file.originalname),
});
`),
    ignores: f('src/routes/upload.js', `const multer = require('multer');
const crypto = require('crypto');
const storage = multer.diskStorage({
  destination: 'public/uploads',
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),
});
`),
  },
  {
    ruleIds: [28810], name: 'GAP-10 ejs.render of request template',
    detects: f('src/routes/preview.js', `const ejs = require('ejs');
app.post('/preview', (req, res) => {
  res.send(ejs.render(req.body.template, { user: req.user }));
});
`),
    ignores: f('src/routes/preview.js', `const ejs = require('ejs');
app.post('/preview', async (req, res) => {
  res.send(await ejs.renderFile('views/preview.ejs', { content: req.body.template }));
});
`),
  },
  {
    ruleIds: [28811], name: 'GAP-11 postMessage token to *',
    detects: f('components/embed-bridge.tsx', `'use client';
export function sendToken(token: string) {
  window.parent.postMessage({ type: 'auth', token }, '*');
}
`),
    ignores: f('components/embed-bridge.tsx', `'use client';
export function sendToken(token: string) {
  window.parent.postMessage({ type: 'auth', token }, 'https://app.example.com');
  window.parent.postMessage({ type: 'resize', height: document.body.scrollHeight }, '*');
}
`),
  },
  {
    ruleIds: [28812], name: 'GAP-12 OTP generator with Math.random',
    detects: f('lib/otp.ts', `export function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
`),
    ignores: f('lib/otp.ts', `import { randomInt } from 'crypto';
export function generateOtp() {
  return randomInt(100000, 1000000).toString();
}
export function generateKey() {
  return Math.random().toString(36).slice(2);
}
`),
  },
  {
    ruleIds: [28813], name: 'GAP-13 Flask debug on 0.0.0.0',
    detects: f('app.py', `from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
`),
    ignores: f('app.py', `import os
from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=os.getenv("FLASK_DEBUG") == "1")
`),
  },
  {
    ruleIds: [28814], name: 'GAP-14 Supabase .or() with search term',
    detects: f('app/api/search/route.ts', `import { createClient } from '@/lib/supabase/server';
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get('q') ?? '';
  const supabase = await createClient();
  const { data } = await supabase.from('posts').select('*').or(\`title.ilike.%\${q}%,body.ilike.%\${q}%\`);
  return Response.json(data);
}
`),
    ignores: f('app/api/search/route.ts', `import { createClient } from '@/lib/supabase/server';
export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  const { data } = await supabase.from('posts').select('*').or(\`author_id.eq.\${user!.id},is_public.eq.true\`);
  return Response.json(data);
}
`),
  },
  {
    ruleIds: [28815], name: 'GAP-15 role in signUp metadata',
    detects: f('app/(auth)/signup/actions.ts', `'use server';
import { createClient } from '@/lib/supabase/server';
export async function signup(formData: FormData) {
  const supabase = await createClient();
  await supabase.auth.signUp({
    email: String(formData.get('email')),
    password: String(formData.get('password')),
    options: { data: { role: formData.get('role') } },
  });
}
`),
    ignores: f('app/(auth)/signup/actions.ts', `'use server';
import { createClient } from '@/lib/supabase/server';
export async function signup(formData: FormData) {
  const supabase = await createClient();
  await supabase.auth.signUp({
    email: String(formData.get('email')),
    password: String(formData.get('password')),
    options: { data: { full_name: formData.get('name') } },
  });
}
`),
  },
  {
    ruleIds: [28816], name: 'GAP-16 storage upload keyed by file name',
    detects: f('app/api/avatar/route.ts', `import { createClient } from '@/lib/supabase/server';
export async function POST(req: Request) {
  const supabase = await createClient();
  const form = await req.formData();
  const file = form.get('file') as File;
  const { data } = await supabase.storage.from('avatars').upload(file.name, file, { upsert: true });
  return Response.json(data);
}
`),
    ignores: f('app/api/avatar/route.ts', `import { createClient } from '@/lib/supabase/server';
export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  const form = await req.formData();
  const file = form.get('file') as File;
  const { data } = await supabase.storage.from('avatars').upload(\`\${user!.id}/\${crypto.randomUUID()}.png\`, file);
  return Response.json(data);
}
`),
  },
  {
    ruleIds: [18032], name: 'RUBY-SEC-02 permit! inside a call',
    detects: f('app/controllers/users_controller.rb', `class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params[:user].permit!)
    redirect_to @user
  end
end
`),
    ignores: f('app/controllers/users_controller.rb', `class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params.require(:user).permit(:name, :email))
    redirect_to @user
  end
end
`),
  },
  {
    ruleIds: [28123], name: 'NODE-WEB-23 express.static of parent directory',
    detects: f('src/server.js', `const express = require('express');
const app = express();
app.use(express.static(__dirname + '/..'));
app.listen(3000);
`),
    ignores: f('src/server.js', `const express = require('express');
const app = express();
app.use(express.static(__dirname + '/../public'));
app.listen(3000);
`),
  },
  {
    ruleIds: [35], name: 'SEC-35 named fs/promises import with request path',
    detects: f('app/api/docs/route.ts', `import { readFile } from 'fs/promises';
import path from 'path';
export async function GET(req: Request) {
  const slug = new URL(req.url).searchParams.get('slug')!;
  const md = await readFile(path.join(process.cwd(), 'content', slug + '.md'), 'utf8');
  return new Response(md);
}
`),
    ignores: f('app/api/docs/route.ts', `import { readFile } from 'fs/promises';
import path from 'path';
export async function GET(req: Request) {
  const slug = path.basename(new URL(req.url).searchParams.get('slug')!);
  const md = await readFile(path.join(process.cwd(), 'content', slug + '.md'), 'utf8');
  return new Response(md);
}
`),
  },
];
