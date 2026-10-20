import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// False alarms found while scanning recently launched open-source apps for outreach (2026-10-15).
// Each case keeps the real pattern reported and the look-alike quiet.
export const CASES: RuleCase[] = [
  {
    ruleIds: [12002], name: 'GRPH-02 Cypher built from input vs SQL migrations and sql`` tagged templates',
    detects: f('src/graph/users.ts', `import neo4j from 'neo4j-driver';
export async function findUser(session: neo4j.Session, name: string) {
  return session.run(\`MATCH (u:User {name: '\${name}'}) RETURN u\`);
}
`),
    ignores: f('server/db/migration/20260923_alertable.ts', `export async function up(tx: Tx, children: string[], row: Row, next: object) {
  for (const table of children) await tx.run(\`CREATE TEMP TABLE session_\${table} AS SELECT * FROM \${table}\`);
  await tx.run(sql\`UPDATE trigger SET target_json = \${JSON.stringify(next)} WHERE id = \${row.id}\`);
}
`)
  },
  {
    ruleIds: [24102], name: 'CORE-02 PHP exec() with a variable vs PDO $db->exec()',
    detects: f('admin/backup.php', `<?php
$name = $_GET['name'];
exec("tar czf /backups/" . $name . ".tgz /var/www");
`),
    ignores: f('db.php', `<?php
function create_database(PDO $server, string $databaseName): void {
    $server->exec('CREATE DATABASE IF NOT EXISTS \`' . $databaseName . '\` CHARACTER SET utf8mb4');
}
`)
  },
  {
    ruleIds: [33], name: 'SEC-33 child_process exec with a template vs database.exec() in a file without child_process',
    detects: f('server/ping.ts', `import { exec } from 'child_process';
export function ping(host: string) {
  exec(\`ping -c 1 \${host}\`);
}
`),
    ignores: f('src/home/store.ts', `import Database from 'better-sqlite3';
export function backup(database: Database.Database, partial: string) {
  database.exec(\`VACUUM INTO '\${partial.replaceAll("'", "''")}'\`);
}
`)
  },
  {
    ruleIds: [8811], name: 'PY-SEC-11 exec() on a variable vs a method named exec',
    detects: f('app/plugins.py', `def run_plugin(source):
    exec(source)
`),
    ignores: f('sdk/database.py', `class Database:
    def exec(self, sql: str, *bindings) -> list:
        return self._conn.execute(sql, bindings).fetchall()
`)
  },
  {
    ruleIds: [9302], name: 'MOB-SEC-02 real-looking client secret vs GOCSPX-xxxx placeholder',
    detects: f('app/src/main/java/com/acme/auth/OAuth.kt', `object OAuth {
    val clientSecret = "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"
}
`),
    ignores: f('app/src/main/java/com/acme/auth/OAuth.kt', `object OAuth {
    val clientSecret = "GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
`)
  },
  {
    ruleIds: [28838], name: 'GAP-38 FastAPI DELETE without auth: deployed API vs app pinned to 127.0.0.1',
    detects: [
      { path: 'server/app/api/items.py', content: `from fastapi import APIRouter
router = APIRouter()

@router.delete("/{item_id}")
async def delete_item(item_id: int, registry: Registry) -> None:
    registry.delete(item_id)
` },
      { path: 'Dockerfile', content: 'FROM python:3.12-slim\nCMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]\n' }
    ],
    ignores: [
      { path: 'server/app/api/items.py', content: `from fastapi import APIRouter
router = APIRouter()

@router.delete("/{item_id}")
async def delete_item(item_id: int, registry: Registry) -> None:
    registry.delete(item_id)
` },
      { path: 'server/app/settings.py', content: 'class Settings(BaseSettings):\n    host: str = "127.0.0.1"\n    port: int = 8787\n' }
    ]
  },
  {
    ruleIds: [18001], name: 'PHP-SEC-01 request value concatenated into SQL vs a function declared : int',
    detects: f('lib/habits.php', `<?php
function habits_for(PDO $db): array {
    return $db->query("SELECT id, name FROM habits WHERE user_id = " . $_GET['user'])->fetchAll();
}
`),
    ignores: [
      { path: 'lib/habits.php', content: `<?php
function habits_active(PDO $db): array {
    return $db->query("SELECT id, name FROM habits WHERE user_id = " . life_os_user_id() . " AND archived = 0")->fetchAll();
}
` },
      { path: 'lib/user_context.php', content: `<?php
function life_os_user_id(): int {
    return (int) $GLOBALS['life_os_request_user_id'];
}
` }
    ]
  },
  {
    ruleIds: [16], name: 'SEC-16 innerHTML with raw data vs a file that escapes interpolations, and an icon constant',
    detects: f('public/assets/list.js', `export function render(main, items) {
  main.innerHTML = items.map((i) => \`<li>\${i.title}</li>\`).join('');
}
`),
    ignores: [
      { path: 'public/assets/dashboard.js', content: `const esc = globalThis.app.escapeHtml;
export function render(main, items) {
  main.innerHTML = items.map((i) => \`<li>\${esc(i.title)}</li>\`).join('');
}
` },
      { path: 'public/assets/voice-input.js', content: `const icon = '<svg viewBox="0 0 24 24"><path d="M12 2v20"/></svg>';
export function mount(button) {
  button.innerHTML = icon;
}
` }
    ]
  },
  {
    ruleIds: [24101], name: 'CORE-01 value interpolated into SQL vs a table-name constant after FROM',
    detects: f('app/src/main/java/com/acme/db/Notes.kt', `class Notes(private val db: SQLiteDatabase) {
    fun byTitle(title: String) = db.rawQuery("SELECT * FROM notes WHERE title = '$title'", null)
}
`),
    ignores: f('app/src/main/java/com/acme/db/AuditLog.kt', `class AuditLog(private val db: SQLiteDatabase) {
    fun count(): Int = db.rawQuery("SELECT COUNT(*) FROM $TABLE", null).use { c -> c.moveToFirst(); c.getInt(0) }
    companion object { const val TABLE = "config_audit" }
}
`)
  },
  {
    ruleIds: [24102], name: 'CORE-02 Python command string built then run with shell=True vs a fixed command variable',
    detects: f('app/tasks.py', `import subprocess
def convert(name):
    cmd = f"ffmpeg -i uploads/{name} out.mp4"
    subprocess.run(cmd, shell=True)
`),
    ignores: f('app/deps.py', `import subprocess
INSTALL = "pip install -r requirements.txt"
def install(cmd=INSTALL):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
`)
  },
  {
    ruleIds: [28838], name: 'GAP-38 DELETE without auth vs a caller dependency',
    detects: f('cloud/api.py', `from fastapi import APIRouter
router = APIRouter()

@router.delete("/v1/devices/{device_id}")
async def forget_device(device_id: str) -> None:
    devices.remove(device_id)
`),
    ignores: f('cloud/api.py', `from fastapi import APIRouter, Depends
router = APIRouter()

@router.delete("/v1/devices/{device_id}")
async def forget_device(device_id: str, caller: Caller = Depends(hub_dep)) -> None:
    devices.remove(caller.id, device_id)
`)
  },
  {
    ruleIds: [14], name: 'SEC-14 JWT fallback secret vs one the app refuses to start without in production',
    detects: f('server.ts', `import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || "development-secret-change-me";
export const sign = (id: string) => jwt.sign({ id }, JWT_SECRET);
`),
    ignores: f('server.ts', `import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || "development-secret-change-me";
if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET must be configured in production");
}
export const sign = (id: string) => jwt.sign({ id }, JWT_SECRET);
`)
  },
  {
    ruleIds: [21], name: 'SEC-21 logging a token vs logging its fingerprint',
    detects: f('src/runner.ts', `export function start(config: { token: string }) {
  console.log("runner starting", config.token);
}
`),
    ignores: f('src/runner.ts', `export function start(config: { token: string }) {
  console.log("runner starting", installationFingerprint(config.token));
}
`)
  },
  {
    ruleIds: [29910], name: 'SECG-11 public cache on a session route vs a static asset handler',
    detects: f('src/server/routes/me.ts', `export async function me(req: Request, reply: Reply) {
  const user = req.user;
  reply.header("Cache-Control", "public, max-age=3600");
  return { email: user.email };
}
`),
    ignores: f('src/server/app.ts', `app.register(fastifyStatic, {
  root: config.clientDir,
  setHeaders(reply, filePath) {
    if (filePath.includes("/assets/")) reply.header("Cache-Control", "public, max-age=31536000, immutable");
  }
});
app.get("/api/me", async (req) => ({ user: req.user }));
`)
  },
  {
    ruleIds: [28828], name: 'GAP-28 decoded secret echoed to the log vs written to a file',
    detects: f('.github/workflows/release.yml', `jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ secrets.APPLE_API_KEY }}" | base64 --decode
`),
    ignores: f('.github/workflows/release.yml', `jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ secrets.APPLE_API_KEY }}" | base64 --decode > "$RUNNER_TEMP/AuthKey.p8"
`)
  },
  {
    ruleIds: [29302], name: 'AST-02 anonymous revoke vs a route behind apiUser() + checkOrgRole()',
    detects: f('web/app/api/orgs/[slug]/keys/[id]/route.ts', `import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ slug: string; id: string }> }) {
  const { id } = await params;
  await db.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
  return NextResponse.json({ ok: true });
}
`),
    ignores: f('web/app/api/orgs/[slug]/keys/[id]/route.ts', `import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { apiUser } from "@/lib/auth-helpers";
import { checkOrgRole } from "@/lib/rbac";
export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ slug: string; id: string }> }) {
  const { slug, id } = await params;
  const userId = await apiUser();
  const chk = await checkOrgRole(userId, slug, "admin");
  if (!chk.ok) return NextResponse.json({ error: chk.error }, { status: chk.status });
  const key = await db.apiKey.findFirst({ where: { id, orgId: chk.access.org.id } });
  if (!key) return NextResponse.json({ error: "not found" }, { status: 404 });
  await db.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
  return NextResponse.json({ ok: true });
}
`)
  },
  {
    ruleIds: [8844], name: 'PY-SEC-44 unverified decode of a client token vs an id_token from the code exchange',
    detects: f('app/auth.py', `import jwt
def current_user(request):
    token = request.headers["Authorization"].split()[1]
    return jwt.decode(token, options={"verify_signature": False})
`),
    ignores: f('app/oidc.py', `import jwt, httpx
def finish_login(code, cfg):
    resp = httpx.post(cfg.token_endpoint, data={"grant_type": "authorization_code", "code": code})
    id_token = resp.json()["id_token"]
    return jwt.decode(id_token, options={"verify_signature": False})
`)
  },
  {
    ruleIds: [5013], name: 'SEC-SECRET-13 OpenAI key in app code vs a fake-keys test fixture',
    detects: f('src/llm.ts', `export const client = new OpenAI({ apiKey: "sk-4BhS07qso9pVhcsmtU3tyK8zkSbrFKgre4rHtDCWem7VZKYk" });
`),
    ignores: f('tests/fixtures/fake_api_keys.json', `[{ "provider": "openai", "key": "sk-4BhS07qso9pVhcsmtU3tyK8zkSbrFKgre4rHtDCWem7VZKYk" }]
`)
  },
  {
    ruleIds: [10102], name: 'ECOMM-02 charge amount from the request vs a scroll amount',
    detects: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
export async function POST(req: Request) {
  const body = await req.json();
  return stripe.paymentIntents.create({ amount: body.amount, currency: 'usd' });
}
`),
    ignores: f('src/agent/browser.ts', `export async function act(input: { selector: string; direction: 'up' | 'down'; amount: number }) {
  return scroll({ selector: input.selector, direction: input.direction, amount: input.amount });
}
`)
  },
  {
    ruleIds: [24101, 8804], name: 'CORE-01/PY-SEC-04 value in SET vs SET clause built from columns with %s params',
    detects: f('app/store.py', `def rename(conn, item_id, name):
    conn.execute(f"UPDATE items SET name = '{name}' WHERE id = %s", (item_id,))
`),
    ignores: f('app/store.py', `def update(conn, slug, fields):
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    values = list(fields.values()) + [slug]
    conn.execute(f"UPDATE agents SET {set_clause} WHERE slug = %s", values)
`)
  },
  {
    ruleIds: [29833], name: 'BUG-162 Drizzle delete without where vs cookies().delete() and Map.delete() in a Drizzle file',
    detects: f('src/server/users.ts', `import { eq } from 'drizzle-orm';
import { users } from './schema';
export async function wipe() {
  await db.delete(users);
}
`),
    ignores: f('src/app/actions.ts', `import { eq } from 'drizzle-orm';
import { cookies } from 'next/headers';
export async function clearPromo(pending: Map<string, unknown>, callId: string) {
  const store = await cookies();
  store.delete(PROMO_COOKIE);
  pending.delete(callId);
}
`)
  },
  {
    ruleIds: [29889], name: 'BUG-212 BigInt mixed with a number vs a BigInt literal with separators',
    detects: f('src/money.ts', `export const toUnits = (stroops: string) => BigInt(stroops) / 10000000;
`),
    ignores: f('src/money.ts', `export const toUnits = (stroops: string) => BigInt(stroops) / 10_000_000n;
`)
  },
  {
    ruleIds: [28838], name: 'GAP-38 DELETE without auth vs require_operator(request) at the top of the body',
    detects: f('app/main.py', `from fastapi import FastAPI, Request
app = FastAPI()

@app.delete("/api/mentions/{mid}")
def api_delete(mid: int, request: Request):
    db.delete_mention(mid)
`),
    ignores: f('app/main.py', `from fastapi import FastAPI, Request
app = FastAPI()

@app.delete("/api/mentions/{mid}")
def api_delete(mid: int, request: Request):
    require_operator(request)
    require_csrf(request)
    db.delete_mention(mid)
`)
  },
  {
    ruleIds: [24101], name: 'CORE-01 f-string query with a request value vs UI text, a module constant and a migration',
    detects: f('backend/cases/views.py', `def search(cursor, request):
    q = request.GET["q"]
    cursor.execute(f"SELECT id, title FROM cases WHERE title LIKE '%{q}%'")
`),
    ignores: [
      ...f('backend/cases/bulk_views.py', `MAX_BULK_IDS = 100

def check(ids):
    if len(ids) > MAX_BULK_IDS:
        return {"errors": f"Select at most {MAX_BULK_IDS} tickets at a time."}
`),
      ...f('backend/common/rls/pool.py', `CONTEXT_VARIABLE = "app.tenant_id"
CLEAR_CONTEXT_SQL = f"SELECT current_setting('x') FROM pg_settings WHERE name = '{CONTEXT_VARIABLE}'"
`),
      ...f('db/migrate/20170813164435_add_unique_indexes.rb', `class AddUniqueIndexes < ActiveRecord::Migration[5.1]
  def up
    execute "DELETE FROM visibilities AS a1 USING visibilities AS a2 #{where_clause}"
  end
end
`),
    ],
  },
  {
    ruleIds: [8814], name: 'PY-SEC-14 route fetches a URL from the query string vs a job fetching its configured URL and a checked host',
    detects: f('app/routes/preview.py', `import requests
from flask import request

@bp.route("/preview")
def preview():
    url = request.args["url"]
    return requests.get(url, timeout=5).text
`),
    ignores: [
      ...f('postrun/job/incident_init.py', `import requests

def init(endpoint, headers):
    url = endpoint + "/incident"
    r = requests.get(url, headers=headers)
    return r.json()
`),
      ...f('app/routes/fetch.py', `import requests
from urllib.parse import urlparse
from flask import request

ALLOWED_HOSTS = {"api.example.com"}

@bp.route("/fetch")
def fetch():
    url = request.args["url"]
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url, timeout=5).text
`),
    ],
  },
  {
    ruleIds: [24102], name: 'CORE-02 Ruby backtick command with interpolation vs backticks inside error and log strings',
    detects: f('app/services/archive.rb', 'class Archive\n  def pack(dir)\n    out = `tar czf /tmp/out.tgz #{dir}`\n    out\n  end\nend\n'),
    ignores: f('lib/sdk/models/api_meta.rb', 'class ApiMeta\n  def initialize(attributes = {})\n    attributes.each_key do |k|\n      fail ArgumentError, "`#{k}` is not a valid attribute in `ApiMeta`."\n    end\n    raise "A `disco` command named \'#{name}\' is already registered" if taken\n  end\nend\n'),
  },
  {
    ruleIds: [3021], name: 'INFRA-21 multi-line query with an interpolated id vs a migration and a confirm message',
    detects: f('src/repositories/user.repository.ts', 'export async function findUser(pool, id: string) {\n  return pool.query(`\n    SELECT id, email\n    FROM users\n    WHERE id = ${id}\n  `);\n}\n'),
    ignores: [
      ...f('src/db/migrations/1717180399574-CreatePlans.ts', 'export class CreatePlans {\n  async up(queryRunner, orgs) {\n    for (const org of orgs) await queryRunner.query(`INSERT INTO plans (org_id) VALUES (\'${org.id}\')`);\n  }\n}\n'),
      ...f('src/ui/confirm.ts', 'export function ask(dialog, name: string) {\n  return dialog.exec(`Delete ${name}? This cannot be undone.`);\n}\n'),
    ],
  },
  {
    ruleIds: [3003], name: 'INFRA-03 password in a URI to a real host vs Compose and CI service names',
    detects: f('src/config/database.ts', 'export const DATABASE_URL = "postgresql://app_admin:Qx7vR2mTz9@db-prod-01.eu-west-1.rds.amazonaws.com:5432/app";\n'),
    ignores: [
      ...f('container-compose.yml', 'services:\n  web:\n    environment:\n      DATABASE_URL: postgresql://forem:forem@db:5432/PracticalDeveloper_development\n'),
      ...f('.forgejo/workflows/test-migrations.yml', "jobs:\n  test:\n    steps:\n      - name: Start migration test\n        env:\n          TEST_DATABASE_URL: 'mysql://bookstack-test:bookstack-test@mysql/bookstack-test'\n"),
    ],
  },
  {
    ruleIds: [24103], name: 'CORE-03 PHP unserialize on a cookie vs Serializable methods and allowed_classes false',
    detects: f('src/Session/CartCookie.php', "<?php\nclass CartCookie {\n  public function load() {\n    return unserialize($_COOKIE['cart']);\n  }\n}\n"),
    ignores: f('src/Model/Identity.php', "<?php\nclass Identity implements \\Serializable {\n  public function unserialize($serialized): void {\n    [$this->class, $this->id] = $this->unserialize($serialized);\n  }\n  public function opts($raw) {\n    return unserialize($raw, ['allowed_classes' => false]);\n  }\n}\n"),
  },
  {
    ruleIds: [5045, 5046], name: 'SEC-SECRET-45/46 key blocks with key material vs a header used as a detection pattern or prefix check',
    detects: f('deploy/keys.py', 'DEPLOY_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----"""\nSIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLR\n-----END RSA PRIVATE KEY-----"""\n'),
    ignores: f('apps/common/utils/encode.py', 'def is_ssh_key(text):\n    return text.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")\n\nRSA_HEADER = re.compile(r"-----BEGIN RSA PRIVATE KEY-----")\n'),
  },
  {
    ruleIds: [3001], name: 'INFRA-01 table without RLS in a Supabase app vs Prisma migrations of an app whose only supabase-js user is an example package',
    detects: [
      ...f('package.json', '{ "dependencies": { "@supabase/supabase-js": "^2.45.0" } }\n'),
      ...f('db/schema.sql', 'create table public.notes (\n  id uuid primary key,\n  body text\n);\n'),
    ],
    ignores: [
      ...f('examples/supabase-demo/package.json', '{ "dependencies": { "@supabase/supabase-js": "^2.45.0" } }\n'),
      ...f('apps/backend/prisma/migrations/20240610085756_init/migration.sql', '-- CreateTable\nCREATE TABLE "VerificationCode" (\n  "id" UUID NOT NULL,\n  "code" TEXT NOT NULL\n);\n'),
    ],
  },
  {
    ruleIds: [15701], name: 'KERN-SEC-01 privileged compose service vs a locale key ending in _add, a PodSecurityPolicy and a scan report',
    detects: f('docker-compose.yml', 'services:\n  agent:\n    image: acme/agent:1.4\n    privileged: true\n'),
    ignores: [
      ...f('config/locales/client.fi.yml', 'fi:\n  js:\n    user:\n      description_add: "Lisää kaikki ALL osoitteet"\n'),
      ...f('charts/storage/templates/psp.yaml', 'apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata:\n  name: storage-node\nspec:\n  privileged: true\n'),
      ...f('unittests/scans/dockerbench/docker-bench-report.json', '{ "remediation": "You should not use the --privileged option in docker exec commands." }\n'),
    ],
  },
  {
    ruleIds: [27214], name: 'SCA requests pinned below 2.31 vs a >= floor and packages whose name only starts with requests',
    detects: f('requirements.txt', 'flask==3.0.3\nrequests==2.28.1\n'),
    ignores: f('requirements.txt', 'requests>=2.20\nrequests-oauthlib==1.3.0\nrequests_toolbelt==0.9.1\n'),
  },
  {
    ruleIds: [9704], name: 'FINTECH-04 Stripe webhook using the body unverified vs one handing the signature to a service that calls constructEvent',
    detects: f('src/app/api/webhook/stripe/route.js', `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(req) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await prisma.subscription.update({ where: { id: event.data.object.metadata.subId }, data: { status: "active" } });
  }
  return NextResponse.json({ received: true });
}
`),
    ignores: [
      ...f('src/app/api/webhook/stripe/route.js', `import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { BillingService } from "@/lib/services/billing";

export async function POST(req) {
  const body = await req.text();
  const signature = (await headers()).get("stripe-signature");
  const result = await BillingService.handleWebhook(body, signature);
  return NextResponse.json(result);
}
`),
      ...f('src/lib/services/billing.js', `import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export const BillingService = {
  async handleWebhook(body, signature) {
    const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET);
    return { type: event.type };
  },
};
`),
      ...f('src/app/api/v1/webhooks/route.ts', `import { requireApiKey } from '@/lib/auth/api-context';

export async function POST(request: Request) {
  const ctx = await requireApiKey(request, 'webhooks:manage');
  const body = await request.json();
  const { data } = await ctx.supabase.from('webhook_endpoints').insert({ url: body.url, events: ['invoice.paid'] }).select().single();
  return Response.json(data);
}
`),
    ],
  }
];
