import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const MIG = 'supabase/migrations/20250101000000_init.sql';

export const CASES: RuleCase[] = [
  {
    ruleIds: [29974], name: 'PRV-01 raw email in an analytics event',
    detects: f('components/signup-done.tsx', `import posthog from 'posthog-js';
export const trackSignup = (u: { id: string; email: string }) => posthog.capture('signed_up', { email: u.email, plan: 'free' });
`),
    ignores: f('components/signup-done.tsx', `import posthog from 'posthog-js';
export const trackSignup = (u: { id: string; email: string }) => posthog.capture('signed_up', { userId: u.id, plan: 'free' });
`),
  },
  {
    ruleIds: [29975], name: 'PRV-02 national id in a URL',
    detects: f('lib/patients.ts', `export const patientUrl = (p: { tckn: string }) => \`/api/patients?tckn=\${p.tckn}\`;
`),
    ignores: f('lib/patients.ts', `export const patientUrl = (p: { id: string }) => \`/api/patients/\${p.id}\`;
`),
  },
  {
    ruleIds: [29976], name: 'PRV-03 every recipient in To',
    detects: f('lib/announce.ts', `import { resend } from './resend';
export const announce = (users: { email: string }[]) => resend.emails.send({ from: 'news@example.com', to: users.map((u) => u.email), subject: 'Update', html: '<p>Hi</p>' });
`),
    ignores: f('lib/announce.ts', `import { resend } from './resend';
export const announce = (users: { email: string }[]) => resend.batch.send(users.map((u) => ({ from: 'news@example.com', to: u.email, subject: 'Update', html: '<p>Hi</p>' })));
`),
  },
  {
    ruleIds: [29977], name: 'PRV-04 refresh token in localStorage',
    detects: f('lib/session.ts', `export function saveSession(t: { accessToken: string; refreshToken: string }) {
  localStorage.setItem('refreshToken', t.refreshToken);
}
`),
    ignores: f('lib/session.ts', `export function saveSession(t: { theme: string }) {
  localStorage.setItem('theme', t.theme);
}
`),
  },
  {
    ruleIds: [29978], name: 'PRV-05 reset token stored as issued',
    detects: f('lib/reset.ts', `import crypto from 'crypto';
import { prisma } from './db';
export async function startReset(email: string) {
  const token = crypto.randomBytes(32).toString('hex');
  await prisma.user.update({ where: { email }, data: { resetToken: token, resetExpires: new Date(Date.now() + 3600e3) } });
  return token;
}
`),
    ignores: f('lib/reset.ts', `import crypto from 'crypto';
import { prisma } from './db';
export async function startReset(email: string) {
  const token = crypto.randomBytes(32).toString('hex');
  const resetToken = crypto.createHash('sha256').update(token).digest('hex');
  await prisma.user.update({ where: { email }, data: { resetToken, resetExpires: new Date(Date.now() + 3600e3) } });
  return token;
}
`),
  },
  {
    ruleIds: [29979], name: 'PRV-06 fdw user mapping password in a migration',
    detects: f(MIG, `CREATE SERVER legacy FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'legacy.internal', dbname 'app');
CREATE USER MAPPING FOR postgres SERVER legacy OPTIONS (user 'reader', password 'R3ader!Pass2024');
`),
    ignores: f(MIG, `CREATE SERVER legacy FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'legacy.internal', dbname 'app');
`),
  },
  {
    ruleIds: [29980], name: 'DBG-01 SET NULL on a NOT NULL column',
    detects: f(MIG, `CREATE TABLE posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id uuid NOT NULL REFERENCES profiles(id) ON DELETE SET NULL
);
`),
    ignores: f(MIG, `CREATE TABLE posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  editor_id uuid REFERENCES profiles(id) ON DELETE SET NULL
);
`),
  },
  {
    ruleIds: [29981], name: 'DBG-02 NOT IN over a subquery',
    detects: f(MIG, `CREATE VIEW active_users AS SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM bans);
`),
    ignores: f(MIG, `CREATE VIEW active_users AS SELECT * FROM users u WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = u.id);
`),
  },
  {
    ruleIds: [29982], name: 'DBG-03 trigger updates its own table',
    detects: f(MIG, `CREATE FUNCTION touch_post() RETURNS trigger AS $$
BEGIN
  UPDATE posts SET updated_at = now() WHERE id = NEW.id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER posts_touch AFTER UPDATE ON posts FOR EACH ROW EXECUTE FUNCTION touch_post();
`),
    ignores: f(MIG, `CREATE FUNCTION touch_post() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER posts_touch BEFORE UPDATE ON posts FOR EACH ROW EXECUTE FUNCTION touch_post();
`),
  },
  {
    ruleIds: [29983], name: 'DBG-04 blocking materialized view refresh in a function',
    detects: f(MIG, `CREATE FUNCTION refresh_stats() RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW daily_stats;
END;
$$ LANGUAGE plpgsql;
`),
    ignores: f(MIG, `CREATE MATERIALIZED VIEW daily_stats AS SELECT date_trunc('day', created_at) d, count(*) n FROM orders GROUP BY 1;
CREATE UNIQUE INDEX ON daily_stats (d);
REFRESH MATERIALIZED VIEW daily_stats;
CREATE FUNCTION refresh_stats() RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY daily_stats;
END;
$$ LANGUAGE plpgsql;
`),
  },
  {
    ruleIds: [29984], name: 'DBG-05 pg_notify with the whole row',
    detects: f(MIG, `CREATE FUNCTION notify_order() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('orders', row_to_json(NEW)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
`),
    ignores: f(MIG, `CREATE FUNCTION notify_order() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('orders', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
`),
  },
  {
    ruleIds: [29985], name: 'DBG-06 serial key on an events table',
    detects: f(MIG, `CREATE TABLE page_views (id SERIAL PRIMARY KEY, path text NOT NULL, created_at timestamptz DEFAULT now());
`),
    ignores: f(MIG, `CREATE TABLE page_views (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, path text NOT NULL);
CREATE TABLE course_reviews (id SERIAL PRIMARY KEY, body text);
`),
  },
  {
    ruleIds: [29986], name: 'DBG-07 Redis KEYS pattern',
    detects: f('lib/sessions.ts', `import { redis } from './redis';
export async function activeSessions() {
  return redis.keys('session:*');
}
`),
    ignores: f('lib/sessions.ts', `import { redis } from './redis';
export async function activeSessions() {
  const out: string[] = [];
  for await (const key of redis.scanIterator({ MATCH: 'session:*', COUNT: 100 })) out.push(key);
  return out;
}
`),
  },
  {
    ruleIds: [29987], name: 'DBG-08 count by loading rows',
    detects: f('lib/stats.ts', `import { prisma } from './db';
export const userCount = async () => (await prisma.user.findMany()).length;
`),
    ignores: f('lib/stats.ts', `import { prisma } from './db';
export const userCount = () => prisma.user.count();
`),
  },
  {
    ruleIds: [29988], name: 'DBG-09 table loaded then filtered in JS',
    detects: f('lib/orders.ts', `import { prisma } from './db';
export const openOrders = async () => (await prisma.order.findMany()).filter((o) => o.status === 'open');
`),
    ignores: f('lib/orders.ts', `import { prisma } from './db';
export const openOrders = () => prisma.order.findMany({ where: { status: 'open' } });
`),
  },
];
