import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile => ({ path, content });

// Cross-layer rules compare two parts of one repository, so every case carries the other layer too.
const ENV_EXAMPLE = f('.env.example', 'DATABASE_URL=\nSTRIPE_SECRET_KEY=\n');
const MIGRATION_NO_RLS = f('supabase/migrations/001_init.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
`);
const MIGRATION_RLS = f('supabase/migrations/001_init.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create index notes_user_id_idx on public.notes (user_id);
`);
const SUPABASE_PKG = f('package.json', '{ "dependencies": { "@supabase/supabase-js": "^2.45.0" } }');

export const CASES: RuleCase[] = [
  {
    ruleIds: [30301], name: 'XL-01 env var read in code but missing from .env.example vs declared',
    detects: [ENV_EXAMPLE, f('lib/mail.ts', `export const resendKey = process.env.RESEND_API_KEY;
export const db = process.env.DATABASE_URL;
`)],
    ignores: [f('.env.example', 'DATABASE_URL=\nRESEND_API_KEY=\n'), f('lib/mail.ts', `export const resendKey = process.env.RESEND_API_KEY;
export const db = process.env.DATABASE_URL;
export const region = process.env.MAIL_REGION || 'eu';
`)],
  },
  {
    ruleIds: [30301], name: 'XL-01 required var guarded by a throw is still flagged; optional, host-injected, script and .env.local.example vars are not',
    detects: [ENV_EXAMPLE, f('lib/stripe.ts', `if (!process.env.PAYMENT_API_KEY) throw new Error('PAYMENT_API_KEY is missing');
export const key = process.env.PAYMENT_API_KEY;
`)],
    ignores: [f('.env.local.example', 'PAYMENT_API_KEY=\n'), f('lib/stripe.ts', `if (!process.env.PAYMENT_API_KEY) throw new Error('PAYMENT_API_KEY is missing');
export const key = process.env.PAYMENT_API_KEY;
export const debug = process.env.DEBUG_PDF === '1';
export const site = process?.env?.NEXT_PUBLIC_VERCEL_URL && process.env.NEXT_PUBLIC_VERCEL_URL.trim();
export function replicas() {
  if (!process.env.REPLICA_URLS) return [];
  return process.env.REPLICA_URLS.split(',');
}
`), f('scripts/publish.ts', `const deno = process.env.DENO_BIN_PATH;
`), f('common/db.go', `package common
import "os"
func Path() string {
	p := os.Getenv("TEST_DB_PATH")
	if p == "" {
		p = "./test.db"
	}
	return p
}
`)],
  },
  {
    ruleIds: [30302], name: 'XL-02 Dockerfile on Node 18 while engines asks for 20 vs matching image',
    detects: [f('package.json', '{ "name": "api", "engines": { "node": ">=20" } }'), f('Dockerfile', 'FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "server.js"]\n')],
    ignores: [f('package.json', '{ "name": "api", "engines": { "node": ">=20" } }'), f('Dockerfile', 'FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "server.js"]\n')],
  },
  {
    ruleIds: [30303], name: 'XL-03 multer allows 50 MB while nginx stops at 1 MB vs nginx raised',
    detects: [f('deploy/nginx.conf', 'server {\n  listen 80;\n  client_max_body_size 1m;\n  location / { proxy_pass http://app:3000; }\n}\n'), f('src/upload.ts', `import multer from 'multer';
export const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });
`)],
    ignores: [f('deploy/nginx.conf', 'server {\n  listen 80;\n  client_max_body_size 60m;\n  location / { proxy_pass http://app:3000; }\n}\n'), f('src/upload.ts', `import multer from 'multer';
export const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });
`)],
  },
  {
    ruleIds: [30304], name: 'XL-04 Supabase query filters by an unindexed column vs index in migration',
    detects: [MIGRATION_NO_RLS, f('app/notes/actions.ts', `'use server';
import { createClient } from '@/lib/supabase/server';
export async function listNotes(userId: string) {
  const supabase = await createClient();
  const { data } = await supabase.from('notes').select('*').eq('user_id', userId);
  return data;
}
`)],
    ignores: [MIGRATION_RLS, f('app/notes/actions.ts', `'use server';
import { createClient } from '@/lib/supabase/server';
export async function listNotes(userId: string) {
  const supabase = await createClient();
  const { data } = await supabase.from('notes').select('*').eq('user_id', userId);
  return data;
}
`)],
  },
  {
    ruleIds: [30305], name: 'XL-05 browser component queries a table with RLS off vs RLS enabled',
    detects: [SUPABASE_PKG, MIGRATION_NO_RLS, f('components/NotesList.tsx', `'use client';
import { createBrowserClient } from '@supabase/ssr';
const supabase = createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function loadNotes() {
  const { data } = await supabase.from('notes').select('id, body');
  return data;
}
`)],
    ignores: [SUPABASE_PKG, MIGRATION_RLS, f('components/NotesList.tsx', `'use client';
import { createBrowserClient } from '@supabase/ssr';
const supabase = createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function loadNotes() {
  const { data } = await supabase.from('notes').select('id, body');
  return data;
}
`)],
  },
  {
    ruleIds: [30306], name: 'XL-06 Go http.Get with the default client vs client with timeout',
    detects: [f('internal/rates/client.go', `package rates

import "net/http"

func Fetch(url string) (*http.Response, error) {
	return http.Get(url)
}
`)],
    ignores: [f('internal/rates/client.go', `package rates

import (
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 10 * time.Second}

func Fetch(url string) (*http.Response, error) {
	return client.Get(url)
}
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 Prisma balance read-modify-write vs atomic decrement',
    detects: [f('app/api/spend/route.ts', `import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const { userId, amount } = await req.json();
  const wallet = await prisma.wallet.findUnique({ where: { userId } });
  if (!wallet || wallet.balance < amount) return Response.json({ error: 'low' }, { status: 400 });
  await prisma.wallet.update({ where: { userId }, data: { balance: wallet.balance - amount } });
  return Response.json({ ok: true });
}
`)],
    ignores: [f('app/api/spend/route.ts', `import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const { userId, amount } = await req.json();
  const res = await prisma.wallet.updateMany({ where: { userId, balance: { gte: amount } }, data: { balance: { decrement: amount } } });
  if (res.count === 0) return Response.json({ error: 'low' }, { status: 400 });
  return Response.json({ ok: true });
}
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 Django credits -= then save vs F() expression',
    detects: [f('billing/services.py', `def spend(account, amount):
    account.credits -= amount
    account.save()
`)],
    ignores: [f('billing/services.py', `from django.db.models import F

def spend(account, amount):
    Account.objects.filter(pk=account.pk, credits__gte=amount).update(credits=F('credits') - amount)
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 JPA setBalance(getBalance() - x) then save vs pessimistic lock',
    detects: [f('src/main/java/app/WalletService.java', `@Service
public class WalletService {
  @Transactional
  public void pay(Long id, long amount) {
    Wallet wallet = walletRepository.findById(id).orElseThrow();
    wallet.setBalance(wallet.getBalance() - amount);
    walletRepository.save(wallet);
  }
}
`)],
    ignores: [f('src/main/java/app/WalletService.java', `@Service
public class WalletService {
  @Transactional
  public void pay(Long id, long amount) {
    Wallet wallet = walletRepository.findByIdForUpdate(id).orElseThrow();
    wallet.setBalance(wallet.getBalance() - amount);
    walletRepository.save(wallet);
  }
}

interface WalletRepository extends JpaRepository<Wallet, Long> {
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select w from Wallet w where w.id = :id")
  Optional<Wallet> findByIdForUpdate(Long id);
}
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 GORM Balance -= then Save vs gorm.Expr atomic update',
    detects: [f('internal/billing/pay.go', `package billing

func Pay(db *gorm.DB, id uint, amount int64) error {
	var w Wallet
	db.First(&w, id)
	w.Balance -= amount
	return db.Save(&w).Error
}
`)],
    ignores: [f('internal/billing/pay.go', `package billing

func Pay(db *gorm.DB, id uint, amount int64) error {
	return db.Model(&Wallet{}).Where("id = ? AND balance >= ?", id, amount).
		Update("balance", gorm.Expr("balance - ?", amount)).Error
}
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 Eloquent ->stock -= then save vs lockForUpdate',
    detects: [f('app/Services/OrderService.php', `<?php
class OrderService {
    public function reserve(int $productId, int $qty): void {
        $product = Product::find($productId);
        $product->stock -= $qty;
        $product->save();
    }
}
`)],
    ignores: [f('app/Services/OrderService.php', `<?php
class OrderService {
    public function reserve(int $productId, int $qty): void {
        DB::transaction(function () use ($productId, $qty) {
            $product = Product::lockForUpdate()->find($productId);
            $product->stock -= $qty;
            $product->save();
        });
    }
}
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 ActiveRecord credits -= then save! vs with_lock',
    detects: [f('app/services/spend_credits.rb', `class SpendCredits
  def call(account, amount)
    account.credits -= amount
    account.save!
  end
end
`)],
    ignores: [f('app/services/spend_credits.rb', `class SpendCredits
  def call(account, amount)
    account.with_lock do
      account.credits -= amount
      account.save!
    end
  end
end
`)],
  },
  {
    ruleIds: [30307], name: 'XL-07 Rails model concern self.credits -= with save! vs with_lock',
    detects: [f('app/models/concerns/has_credits.rb', `module HasCredits
  extend ActiveSupport::Concern

  def use_credit(amount)
    self.credits -= amount
    raise 'not enough credits' if self.credits < 0
  end

  def use_credit!(amount)
    use_credit(amount)
    save!
  end
end
`)],
    ignores: [f('app/models/concerns/has_credits.rb', `module HasCredits
  extend ActiveSupport::Concern

  def use_credit!(amount)
    with_lock do
      self.credits -= amount
      raise 'not enough credits' if self.credits < 0
      save!
    end
  end
end
`)],
  },
  {
    ruleIds: [30315], name: 'XL-15 cascading foreign keys with no index vs indexes added in a later migration',
    detects: [f('supabase/migrations/001_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text
);

create table public.comments (
  id bigint generated always as identity primary key,
  note_id uuid not null,
  body text,
  foreign key (note_id) references public.notes (id) on delete cascade
);
`)],
    ignores: [f('supabase/migrations/001_notes.sql', `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text
);

create table public.comments (
  id bigint generated always as identity primary key,
  note_id uuid not null,
  body text,
  foreign key (note_id) references public.notes (id) on delete cascade
);

create table public.tags (
  id bigint primary key,
  owner_id uuid references auth.users (id)
);
`), f('supabase/migrations/002_indexes.sql', `create index notes_user_id_idx on public.notes (user_id);
create index on public.comments (note_id, created_at);
`), f('migrations/2019_members/up.sql', `create table community_member (
  id serial primary key,
  user_id int references users on update cascade on delete cascade not null
);
`), f('migrations/2021_rename/up.sql', `alter table community_member rename column user_id to person_id;
create index idx_community_member_person on community_member (person_id);
`)],
  },
  {
    ruleIds: [30308], name: 'XL-08 user profile cached under a fixed key vs per-user key',
    detects: [f('lib/profile-cache.ts', `import { redis } from './redis';
export async function cacheProfile(user: { id: string }) {
  await redis.set('profile', JSON.stringify(user));
}
`)],
    ignores: [f('lib/profile-cache.ts', `import { redis } from './redis';
export async function cacheProfile(user: { id: string }) {
  await redis.set(\`profile:\${user.id}\`, JSON.stringify(user));
}
`)],
  },
  {
    ruleIds: [30309], name: 'XL-09 BullMQ job with infinite attempts vs bounded with backoff',
    detects: [f('jobs/queue.ts', `import { Queue } from 'bullmq';
const q = new Queue('emails');
export const enqueue = (data: unknown) => q.add('send', data, { attempts: Infinity });
`)],
    ignores: [f('jobs/queue.ts', `import { Queue } from 'bullmq';
const q = new Queue('emails');
export const enqueue = (data: unknown) => q.add('send', data, { attempts: 5, backoff: { type: 'exponential', delay: 1000 } });
`)],
  },
  {
    ruleIds: [30311], name: 'XL-11 Stripe webhook adds credits on every delivery vs dedupe on event.id',
    detects: [f('app/api/stripe/webhook/route.ts', `import Stripe from 'stripe';
import { prisma } from '@/lib/prisma';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature')!;
  const evt = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);
  if (evt.type === 'checkout.session.completed') {
    const s = evt.data.object as Stripe.Checkout.Session;
    await prisma.user.update({ where: { id: s.client_reference_id! }, data: { credits: { increment: 100 } } });
  }
  return new Response('ok');
}
`)],
    ignores: [f('app/api/stripe/webhook/route.ts', `import Stripe from 'stripe';
import { prisma } from '@/lib/prisma';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature')!;
  const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);
  const seen = await prisma.processedEvent.findUnique({ where: { id: event.id } });
  if (seen) return new Response('ok');
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object as Stripe.Checkout.Session;
    await prisma.$transaction([
      prisma.processedEvent.create({ data: { id: event.id } }),
      prisma.user.update({ where: { id: s.client_reference_id! }, data: { credits: { increment: 100 } } }),
    ]);
  }
  return new Response('ok');
}
`)],
  },
  {
    ruleIds: [30312], name: 'XL-12 OTP route sends SMS without a limit vs rate limited',
    detects: [f('app/api/otp/route.ts', `import twilio from 'twilio';
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
export async function POST(req: Request) {
  const { phone } = await req.json();
  await client.verify.v2.services(process.env.TWILIO_VERIFY!).verifications.create({ to: phone, channel: 'sms' });
  return Response.json({ sent: true });
}
`)],
    ignores: [f('app/api/otp/route.ts', `import twilio from 'twilio';
import { Ratelimit } from '@upstash/ratelimit';
import { redis } from '@/lib/redis';
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
const limiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(3, '10 m') });
export async function POST(req: Request) {
  const { phone } = await req.json();
  const { success } = await limiter.limit(phone);
  if (!success) return Response.json({ error: 'Too many requests' }, { status: 429 });
  await client.verify.v2.services(process.env.TWILIO_VERIFY!).verifications.create({ to: phone, channel: 'sms' });
  return Response.json({ sent: true });
}
`)],
  },
  {
    ruleIds: [30313], name: 'XL-13 one invoice query without organizationId vs all scoped',
    detects: [f('lib/invoices.ts', `import { prisma } from './prisma';
export const listInvoices = (orgId: string) => prisma.invoice.findMany({ where: { organizationId: orgId } });
export const countInvoices = (orgId: string) => prisma.invoice.count({ where: { organizationId: orgId } });
export const searchInvoices = (q: string) => prisma.invoice.findMany({ where: { number: { contains: q } } });
`)],
    ignores: [f('lib/invoices.ts', `import { prisma } from './prisma';
export const listInvoices = (orgId: string) => prisma.invoice.findMany({ where: { organizationId: orgId } });
export const countInvoices = (orgId: string) => prisma.invoice.count({ where: { organizationId: orgId } });
export const searchInvoices = (orgId: string, q: string) => prisma.invoice.findMany({ where: { organizationId: orgId, number: { contains: q } } });
`)],
  },
];

CASES.push({
  ruleIds: [30310], name: 'XL-10 form posts without a field the API route reads vs all fields sent',
  detects: [f('app/api/invite/route.ts', `export async function POST(req: Request) {
  const { email, role } = await req.json();
  return Response.json({ email, role });
}
`), f('components/InviteForm.tsx', `'use client';
export async function invite(email: string) {
  await fetch('/api/invite', { method: 'POST', body: JSON.stringify({ email }) });
}
`)],
  ignores: [f('app/api/invite/route.ts', `export async function POST(req: Request) {
  const { email, role } = await req.json();
  return Response.json({ email, role });
}
`), f('components/InviteForm.tsx', `'use client';
export async function invite(email: string, role: string) {
  await fetch('/api/invite', { method: 'POST', body: JSON.stringify({ email, role }) });
}
`)],
});
