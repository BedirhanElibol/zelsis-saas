import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3021], name: 'SQL concat request value vs ORM table name and constant column map',
    detects: f('app/models/Usage.ts', 'export async function bump(repository: Repo, name: string) {\n  await repository.query(`UPDATE "Usage" SET n = 1 WHERE name = \'${name}\'`);\n}\n'),
    ignores: f('app/models/Usage.ts', 'const COUNTERS = { a: "a_count" };\nexport async function bump(repository: Repo, type: "a") {\n  const table = repository.metadata.tableName;\n  const column = COUNTERS[type];\n  await repository.query(`INSERT INTO "${table}" ("${column}") VALUES (1)`);\n}\n'),
  },
  {
    ruleIds: [3021], name: 'SQL concat condition list holding a request value vs literals only',
    detects: f('app/stats.ts', 'export async function rows(db: Db, filter: string) {\n  const conditions = [\'rank <= $1\'];\n  conditions.push(filter);\n  return db.query(`SELECT rank FROM words WHERE ${conditions.join(\' AND \')}`);\n}\n'),
    ignores: f('app/stats.ts', 'export async function rows(db: Db, filter: string) {\n  const conditions = [\'rank <= $1\'];\n  if (filter === \'A\') conditions.push(\'n > 0\');\n  return db.query(`SELECT rank FROM words WHERE ${conditions.join(\' AND \')}`);\n}\n'),
  },
  {
    ruleIds: [3021], name: 'SQL concat plain string parameter vs a parameter typed keyof',
    detects: f('app/settings.ts', 'export function set(db: Db, key: string, value: string) {\n  db.prepare(`UPDATE guilds SET ${key} = ?`).run(value);\n}\n'),
    ignores: f('app/settings.ts', 'export function set<K extends keyof Settings>(db: Db, key: K, value: string) {\n  db.prepare(`UPDATE guilds SET ${key} = ?`).run(value);\n}\n'),
  },
  {
    ruleIds: [6043], name: 'DB-PERF-43 dynamic query in app code vs a bin setup script',
    detects: f('app/roles.ts', 'export const drop = (client: Client, user: string) => client.query(`DROP OWNED BY ${user}`);\n'),
    ignores: f('bin/dbBootstrap.ts', 'export const drop = (client: Client, user: string) => client.query(`DROP OWNED BY ${user}`);\n'),
  },
  {
    ruleIds: [28121], name: 'NODE-WEB-21 stored password hash vs hashing both sides for timingSafeEqual',
    detects: f('app/user.ts', 'import crypto from "crypto";\nexport const hash = (password: string) =>\n  crypto.createHash("sha256").update(password).digest("hex");\n'),
    ignores: f('app/auth.ts', 'import crypto from "crypto";\nexport function same(password: string, secret: string) {\n  const given = crypto.createHash("sha256").update(password).digest();\n  const expected = crypto.createHash("sha256").update(secret).digest();\n  return crypto.timingSafeEqual(given, expected);\n}\n'),
  },
  {
    ruleIds: [8120], name: 'ZERO-AUTH-20 login link without state vs a bot install link',
    detects: f('app/links.ts', 'export const LOGIN = `https://discord.com/oauth2/authorize?client_id=${ID}&response_type=code&redirect_uri=${URI}`;\n'),
    ignores: f('app/links.ts', 'export const INSTALL = `https://discord.com/oauth2/authorize?client_id=${ID}`;\n'),
  },
  {
    ruleIds: [8], name: 'SEC-08 wildcard origin with credentials vs credentials off',
    detects: f('app/cors.ts', 'import cors from "cors";\nexport const handler = cors({ origin: \'*\' });\n'),
    ignores: f('app/cors.ts', 'import cors from "cors";\nexport const handler = cors({ origin: \'*\', credentials: false });\n'),
  },
  {
    ruleIds: [29306], name: 'AST-06 request URL fetched directly vs through a named host check',
    detects: f('app/hook.ts', 'import express from "express";\nconst app = express();\napp.post("/hook", async (req, res) => {\n  await fetch(req.body.url);\n  res.send("ok");\n});\n'),
    ignores: f('app/hook.ts', 'import express from "express";\nconst app = express();\napp.post("/hook", async (req, res) => {\n  if (!auth.isSnsSubscribeUrl(req.body.url)) return res.send("no");\n  await fetch(req.body.url);\n  res.send("ok");\n});\n'),
  },
];
