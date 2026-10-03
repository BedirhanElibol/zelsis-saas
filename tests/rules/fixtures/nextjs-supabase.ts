import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const ADMIN_MODULE = `import { createClient } from '@supabase/supabase-js';
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [28001],
    name: 'Server Action deletes with the service-role client without checking the caller',
    detects: f('app/dashboard/projects/actions.ts', `'use server';
${ADMIN_MODULE}import { revalidatePath } from 'next/cache';

const supabaseAdmin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  const { error } = await supabaseAdmin.from('projects').delete().eq('id', projectId);
  if (error) return { error: error.message };
  revalidatePath('/dashboard');
  return { ok: true };
}
`),
    ignores: f('app/dashboard/projects/actions.ts', `'use server';
${ADMIN_MODULE}import { revalidatePath } from 'next/cache';
import { createClient as createServerClient } from '@/utils/supabase/server';

const supabaseAdmin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { error: 'Not signed in' };
  const { error } = await supabaseAdmin.from('projects').delete().eq('id', projectId).eq('owner_id', user.id);
  if (error) return { error: error.message };
  revalidatePath('/dashboard');
  return { ok: true };
}
`)
  },
  {
    ruleIds: [28001],
    name: 'Server Action deletes the auth user through an imported admin client (arrow export)',
    detects: f('src/app/account/actions.ts', `"use server";
import { supabaseAdmin } from '@/lib/supabase/admin';

export const deleteAccount = async (userId: string) => {
  await supabaseAdmin.auth.admin.deleteUser(userId);
};
`),
    ignores: f('src/app/account/actions.ts', `"use server";
import { supabaseAdmin } from '@/lib/supabase/admin';
import { requireUser } from '@/lib/auth';

export const deleteAccount = async () => {
  const user = await requireUser();
  await supabaseAdmin.auth.admin.deleteUser(user.id);
};
`)
  },
  {
    ruleIds: [28002],
    name: 'Route handler updates rows with the service-role client and no auth check',
    detects: f('app/api/credits/route.ts', `import { NextResponse } from 'next/server';
import { createAdminClient } from '@/lib/supabase/admin';

export async function POST(req: Request) {
  const { userId, credits } = await req.json();
  const supabase = createAdminClient();
  await supabase.from('profiles').update({ credits }).eq('id', userId);
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('app/api/credits/route.ts', `import { NextResponse } from 'next/server';
import { createAdminClient } from '@/lib/supabase/admin';
import { createClient } from '@/lib/supabase/server';

export async function POST(req: Request) {
  const supabaseUser = await createClient();
  const { data: { user } } = await supabaseUser.auth.getUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { credits } = await req.json();
  const supabase = createAdminClient();
  await supabase.from('profiles').update({ credits }).eq('id', user.id);
  return NextResponse.json({ ok: true });
}
`)
  },
  {
    ruleIds: [28003],
    name: 'Admin check reads user_metadata.role',
    detects: f('app/admin/page.tsx', `import { redirect } from 'next/navigation';
import { createClient } from '@/utils/supabase/server';

export default async function AdminPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (user?.user_metadata?.role !== 'admin') redirect('/');
  return <h1>Admin</h1>;
}
`),
    ignores: f('app/admin/page.tsx', `import { redirect } from 'next/navigation';
import { createClient } from '@/utils/supabase/server';

export default async function AdminPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (user?.app_metadata?.role !== 'admin') redirect('/');
  return <h1>Admin</h1>;
}
`)
  },
  {
    ruleIds: [28004],
    name: 'RLS policy and signup trigger trust user_metadata',
    detects: f('supabase/migrations/20250101_profiles.sql', `create policy "Admins can read all profiles" on public.profiles
  for select using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'role');
  return new;
end;
$$;
`),
    ignores: f('supabase/migrations/20250101_profiles.sql', `create policy "Admins can read all profiles" on public.profiles
  for select using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');

create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data ->> 'full_name');
  return new;
end;
$$;
`)
  },
  {
    ruleIds: [28005],
    name: 'Storage delete policy only checks the bucket',
    detects: f('supabase/migrations/20250102_storage.sql', `create policy "Users can delete avatars" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars');
`),
    ignores: f('supabase/migrations/20250102_storage.sql', `create policy "Users can delete their own avatar" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars' and (select auth.uid()) = owner_id::uuid);
`)
  },
  {
    ruleIds: [28006],
    name: 'Public view without security_invoker',
    detects: f('supabase/migrations/20250103_views.sql', `create view public.order_totals as
  select user_id, sum(amount) as total from public.orders group by user_id;
`),
    ignores: f('supabase/migrations/20250103_views.sql', `create view public.order_totals with (security_invoker = true) as
  select user_id, sum(amount) as total from public.orders group by user_id;
`)
  },
  {
    ruleIds: [28007],
    name: 'SECURITY DEFINER RPC adds credits without checking auth.uid()',
    detects: f('supabase/migrations/20250104_credits.sql', `create or replace function public.add_credits(target_user uuid, amount int)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.profiles set credits = credits + amount where id = target_user;
end;
$$;
`),
    ignores: f('supabase/migrations/20250104_credits.sql', `create or replace function public.add_credits(target_user uuid, amount int)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.profiles set credits = credits + amount where id = target_user;
end;
$$;

revoke execute on function public.add_credits(uuid, int) from public, anon, authenticated;
`)
  },
  {
    ruleIds: [28008],
    name: 'Middleware forwards request headers as response headers (CVE-2025-57822)',
    detects: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-pathname', request.nextUrl.pathname);
  return NextResponse.next({ headers: requestHeaders });
}
`),
    ignores: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-pathname', request.nextUrl.pathname);
  return NextResponse.next({ request: { headers: requestHeaders } });
}
`)
  },
  {
    ruleIds: [28008],
    name: 'Middleware passes request.headers straight into NextResponse.next',
    detects: f('src/middleware.ts', `import { NextResponse } from 'next/server';
export function middleware(req) {
  return NextResponse.next({ headers: req.headers });
}
`),
    ignores: f('src/middleware.ts', `import { NextResponse } from 'next/server';
export function middleware(req) {
  return NextResponse.next({ request: req });
}
`)
  },
  {
    ruleIds: [28009],
    name: "Image optimizer remotePatterns allows hostname '**'",
    detects: f('next.config.ts', `import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [{ protocol: 'https', hostname: '**' }],
  },
};

export default nextConfig;
`),
    ignores: f('next.config.ts', `import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [{ protocol: 'https', hostname: 'abcd.supabase.co', pathname: '/storage/v1/object/public/**' }],
  },
};

export default nextConfig;
`)
  },
  {
    ruleIds: [28010],
    name: 'dangerouslyAllowSVG without contentSecurityPolicy',
    detects: f('next.config.mjs', `export default {
  images: {
    dangerouslyAllowSVG: true,
  },
};
`),
    ignores: f('next.config.mjs', `export default {
  images: {
    dangerouslyAllowSVG: true,
    contentDispositionType: 'attachment',
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },
};
`)
  },
  {
    ruleIds: [28011],
    name: 'Server Actions allowedOrigins wildcard',
    detects: f('next.config.js', `module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*'],
    },
  },
};
`),
    ignores: f('next.config.js', `module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['app.example.com', '*.example.com'],
    },
  },
};
`)
  },
  {
    ruleIds: [28012],
    name: 'Access token cookie set without httpOnly',
    detects: f('app/api/login/route.ts', `import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const { accessToken } = await req.json();
  const cookieStore = await cookies();
  cookieStore.set('access_token', accessToken, { secure: true, sameSite: 'lax', path: '/' });
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('app/api/login/route.ts', `import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const { accessToken } = await req.json();
  const cookieStore = await cookies();
  cookieStore.set('access_token', accessToken, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  return NextResponse.json({ ok: true });
}
`)
  },
  {
    ruleIds: [28013],
    name: 'Auth callback redirects to ${origin}${next} without a relative-path check',
    detects: f('app/auth/callback/route.ts', `import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const next = searchParams.get('next') ?? '/';
  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) return NextResponse.redirect(\`\${origin}\${next}\`);
  }
  return NextResponse.redirect(\`\${origin}/auth/auth-code-error\`);
}
`),
    ignores: f('app/auth/callback/route.ts', `import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  let next = searchParams.get('next') ?? '/';
  if (!next.startsWith('/') || next.startsWith('//')) next = '/';
  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) return NextResponse.redirect(\`\${origin}\${next}\`);
  }
  return NextResponse.redirect(\`\${origin}/auth/auth-code-error\`);
}
`)
  },
  {
    ruleIds: [28013],
    name: 'Login Server Action redirects to a form-supplied URL',
    detects: f('app/login/actions.ts', `'use server';
import { redirect } from 'next/navigation';
import { createClient } from '@/utils/supabase/server';

export async function login(formData: FormData) {
  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword({
    email: String(formData.get('email')),
    password: String(formData.get('password')),
  });
  if (error) redirect('/login?error=1');
  redirect(formData.get('redirectTo') as string);
}
`),
    ignores: f('app/login/actions.ts', `'use server';
import { redirect } from 'next/navigation';
import { createClient } from '@/utils/supabase/server';

export async function login(formData: FormData) {
  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword({
    email: String(formData.get('email')),
    password: String(formData.get('password')),
  });
  if (error) redirect('/login?error=1');
  const target = String(formData.get('redirectTo') ?? '/');
  redirect(target.startsWith('/') && !target.startsWith('//') ? target : '/');
}
`)
  },
  {
    ruleIds: [28014],
    name: 'Server Action scopes an update by a user_id from the form',
    detects: f('app/settings/actions.ts', `'use server';
import { createClient } from '@/utils/supabase/server';

export async function updateBio(formData: FormData) {
  const supabase = await createClient();
  const userId = formData.get('userId') as string;
  await supabase.from('profiles').update({ bio: formData.get('bio') }).eq('user_id', userId);
}
`),
    ignores: f('app/settings/actions.ts', `'use server';
import { createClient } from '@/utils/supabase/server';

export async function updateBio(formData: FormData) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;
  await supabase.from('profiles').update({ bio: formData.get('bio') }).eq('user_id', user.id);
}
`)
  },
  {
    ruleIds: [28014],
    name: 'Route handler inserts a row owned by a body-supplied user id',
    detects: f('app/api/notes/route.ts', `import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function POST(req: Request) {
  const supabase = await createClient();
  const body = await req.json();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  await supabase.from('notes').insert({
    title: body.title,
    user_id: body.userId,
  });
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('app/api/notes/route.ts', `import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function POST(req: Request) {
  const supabase = await createClient();
  const body = await req.json();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  await supabase.from('notes').insert({
    title: body.title,
    user_id: user.id,
  });
  return NextResponse.json({ ok: true });
}
`)
  },
  {
    ruleIds: [28015],
    name: 'Next.js pinned to a React2Shell-vulnerable release',
    detects: f('package.json', `{
  "name": "saas-app",
  "dependencies": {
    "next": "15.3.2",
    "react": "19.1.0"
  }
}
`),
    ignores: f('package.json', `{
  "name": "saas-app",
  "dependencies": {
    "next": "15.3.6",
    "react": "19.1.2"
  }
}
`)
  },
  {
    ruleIds: [28016],
    name: 'Own-row UPDATE policy on a table holding role and credits',
    detects: f('supabase/migrations/20250105_profiles.sql', `create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'member',
  credits integer not null default 0
);

alter table public.profiles enable row level security;

create policy "Users can update own profile" on public.profiles
  for update using ((select auth.uid()) = id);
`),
    ignores: f('supabase/migrations/20250105_profiles.sql', `create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'member',
  credits integer not null default 0
);

alter table public.profiles enable row level security;

create policy "Users can update own profile" on public.profiles
  for update using ((select auth.uid()) = id);

revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
`)
  },
  {
    ruleIds: [28017],
    name: 'Signed URL valid for ten years',
    detects: f('lib/storage/invoices.ts', `import { createClient } from '@/utils/supabase/server';

export async function invoiceLink(path: string) {
  const supabase = await createClient();
  const { data } = await supabase.storage.from('invoices').createSignedUrl(path, 60 * 60 * 24 * 365 * 10);
  return data?.signedUrl;
}
`),
    ignores: f('lib/storage/invoices.ts', `import { createClient } from '@/utils/supabase/server';

export async function invoiceLink(path: string) {
  const supabase = await createClient();
  const { data } = await supabase.storage.from('invoices').createSignedUrl(path, 60 * 10);
  return data?.signedUrl;
}
`)
  },
];
