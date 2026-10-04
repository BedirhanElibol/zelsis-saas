'use client';

import React from 'react';
import { LazyMotion, domAnimation, m } from 'framer-motion';
import { AlertCircle, ShieldCheck, ArrowRight, Code2 } from 'lucide-react';

const CHECKS = [
  {
    title: 'Service-Role Client Leaks',
    description: 'Detects if SUPABASE_SERVICE_ROLE_KEY is passed to a client component or used in a Server Action without an auth check.',
    ruleId: '28001',
    bad: `const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export async function deleteProject(id: string) {
  // No auth.getUser() check!
  await supabaseAdmin.from('projects').delete().eq('id', id);
}`,
    good: `const supabase = await createServerClient();
const { data: { user } } = await supabase.auth.getUser();
if (!user) throw new Error('Unauthorized');

// Use user's own token to enforce RLS
await supabase.from('projects').delete().eq('id', id);`,
  },
  {
    title: 'unstable_cache Tenant Leaks',
    description: 'Ensures Next.js unstable_cache keys include the tenant ID when wrapping user-specific database queries.',
    ruleId: '28018',
    bad: `const getProfile = unstable_cache(
  async (userId: string) => {
    return db.query.profiles.findFirst({ where: eq(id, userId) });
  },
  ['profile-data'], // Missing userId in cache keys!
  { revalidate: 3600 }
);`,
    good: `const getProfile = unstable_cache(
  async (userId: string) => {
    return db.query.profiles.findFirst({ where: eq(id, userId) });
  },
  ['profile-data', userId], // Tenant isolated
  { revalidate: 3600 }
);`,
  },
  {
    title: 'Webhook Signature & Idempotency',
    description: 'Catches unverified webhook payloads, timing attacks on HMAC, and missing idempotency checks.',
    ruleId: '8103',
    bad: `export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('x-signature');
  
  // Vulnerable to timing attacks!
  if (sig !== expectedSig) return new Response('Unauthorized');
  
  await processWebhook(JSON.parse(body));
}`,
    good: `const a = Buffer.from(sig);
const b = Buffer.from(expectedSig);

// Constant-time comparison
if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
  return new Response('Unauthorized');
}`,
  },
  {
    title: 'AI SDK & MCP Tool Security',
    description: 'Blocks Server Actions from exposing dangerous AI SDK tools or unauthenticated MCP endpoints to the client.',
    ruleId: '28302',
    bad: `import { RequestsToolkit } from 'langchain/tools';

const toolkit = new RequestsToolkit({
  // Dangerous: Allows LLM to make arbitrary HTTP requests
  allowDangerousRequests: true 
});

const agent = createReactAgent({ tools: toolkit.getTools() });`,
    good: `import { createSafeToolkit } from '@/lib/ai/tools';

// Sandbox HTTP requests to allowed internal APIs only
const toolkit = createSafeToolkit({ allowedDomains: ['api.internal'] });
const agent = createReactAgent({ tools: toolkit.getTools() });`,
  },
  {
    title: 'RLS Policies & USING(true)',
    description: 'Detects overly permissive Row Level Security policies or missing security_invoker on PostgreSQL views.',
    ruleId: '28004',
    bad: `create policy "Admins can read all" on profiles
  for select using (
    -- Trusts client-modifiable metadata!
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'
  );`,
    good: `create policy "Admins can read all" on profiles
  for select using (
    -- Secure: uses app_metadata which clients cannot edit
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );`,
  },
  {
    title: 'Server Action Auth Context',
    description: 'Ensures Next.js Server Actions establish auth context before executing mutations.',
    ruleId: '28014',
    bad: `export async function updateBio(formData: FormData) {
  const userId = formData.get('userId') as string;
  // Blindly trusts userId from the form payload!
  await supabase.from('profiles').update({ bio }).eq('user_id', userId);
}`,
    good: `export async function updateBio(formData: FormData) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;
  // Scopes the update to the authenticated user
  await supabase.from('profiles').update({ bio }).eq('user_id', user.id);
}`,
  }
];

export function FrameworkSpecifics() {
  return (
    <section className="py-24 bg-[#0A0A0A] border-t border-white/5 relative overflow-hidden">
      {/* Decorative gradient */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-3xl h-[400px] bg-emerald-500/5 blur-[120px] pointer-events-none" />
      
      <div className="max-w-7xl mx-auto px-6 lg:px-8 relative z-10">
        <div className="max-w-3xl mb-16">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Checks Next.js & Supabase specifics, not just generic JS.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            Generic SAST tools miss framework-specific flaws. Zelsis understands App Router semantics, 
            Server Actions, unstable_cache, and Supabase Auth/RLS context.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CHECKS.map((check, i) => (
            <div key={i} className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden flex flex-col">
              <div className="p-5 border-b border-white/5 flex-grow">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                    <Code2 className="w-4 h-4" />
                  </div>
                  <h3 className="font-semibold text-white">{check.title}</h3>
                </div>
                <p className="text-sm text-zinc-400 mb-4">{check.description}</p>
                <div className="inline-flex items-center px-2 py-1 rounded bg-white/5 text-xs font-mono text-zinc-300">
                  Rule #{check.ruleId}
                </div>
              </div>
              
              <div className="bg-[#0A0A0A] p-4 text-xs font-mono leading-relaxed overflow-x-auto">
                <div className="text-red-400 mb-2 flex items-center gap-2">
                  <AlertCircle className="w-3 h-3" /> Vulnerable Code
                </div>
                <pre className="text-zinc-500 mb-4"><code>{check.bad}</code></pre>
                
                <div className="text-emerald-400 mb-2 flex items-center gap-2">
                  <ShieldCheck className="w-3 h-3" /> Zelsis Fix
                </div>
                <pre className="text-zinc-300"><code>{check.good}</code></pre>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
