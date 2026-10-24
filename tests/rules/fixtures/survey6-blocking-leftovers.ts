import type { RuleCase } from '../cases';

const f = (path: string, content: string) => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [14],
    name: 'SEC-14 JWT/session secret fallback in app vs local/dev/mock/flash',
    detects: [
      ...f('src/auth.ts', "export const authConfig = { secret: process.env.SESSION_SECRET ?? 'tEsTeD' };\n"),
      ...f('config/jwt.ts', "export const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';\n")
    ],
    ignores: [
      // When guarded by production check, ignores completely
      ...f('src/server.ts', "const secret = process.env.JWT_SECRET || 'dev';\nif (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) throw new Error('missing');\n")
    ]
  },
  {
    ruleIds: [34],
    name: 'SEC-34 SSRF fixed origin config/env vs request url',
    detects: [
      ...f('app/api/proxy/route.ts', "export async function GET(req: any) {\n  return await fetch(req.nextUrl.searchParams.get('url'));\n}\n"),
      ...f('server/proxy.ts', "export async function handle(req: any) {\n  const target = req.query.url;\n  return await fetch(target);\n}\n")
    ],
    ignores: [
      ...f('app/api/ticket/route.ts', "const STORAGE_URL = process.env.STORAGE_URL;\nexport async function GET(req: any) {\n  const id = req.nextUrl.searchParams.get('id');\n  return await fetch(`${STORAGE_URL}/tickets/${id}`);\n}\n"),
      ...f('app/api/fetch-api/route.ts', "export async function GET(req: any) {\n  const userId = req.nextUrl.searchParams.get('userId');\n  return await fetch(`${process.env.API_BASE_URL}/users/${userId}`);\n}\n")
    ]
  },
  {
    ruleIds: [24101],
    name: 'CORE-01 DuckDB read_parquet and model table name with bound parameters',
    detects: [
      ...f('db/query.py', "def search(user_input):\n    return f\"SELECT * FROM users WHERE username = '{user_input}'\"\n"),
      ...f('analytics/duck.py', "def query_parquet(DATA_PATH, user_role):\n    return f\"SELECT * FROM read_parquet('{DATA_PATH}/*.parquet') WHERE role = '{user_role}'\"\n")
    ],
    ignores: [
      ...f('analytics/safe_duck.py', "def query_safe(DATA_PATH, user_id):\n    return f\"SELECT * FROM read_parquet('{DATA_PATH}/*.parquet') WHERE id = %s\", (user_id,)\n"),
      ...f('models/repo.py', "def get_by_id(model, user_id):\n    return f\"SELECT * FROM {model.__tablename__} WHERE id = %s\", (user_id,)\n")
    ]
  },
  {
    ruleIds: [32],
    name: 'SEC-32 browser asset data- handler new Function vs request eval',
    detects: [
      ...f('server/calc.ts', "export function compute(req: any) {\n  return eval(req.query.expr);\n}\n"),
      ...f('public/assets/framework.js', "function bindHandler(el) {\n  const handler = new Function('event', el.getAttribute('data-click'));\n  el.onclick = handler;\n}\n")
    ],
    ignores: [
      ...f('lib/calc.ts', "export function square(n: number) {\n  return n * n;\n}\n")
    ]
  }
];
