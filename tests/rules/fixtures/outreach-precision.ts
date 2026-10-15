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
  }
];
