import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile => ({ path, content });

// A route that trusts parseToken(); the bug lives in the helper, so the helper is what both cases change.
const ROUTE = f('app/api/admin/users/route.ts', `import { NextRequest, NextResponse } from 'next/server';
import { parseToken } from '@/lib/auth';

export async function DELETE(req: NextRequest) {
  const user = parseToken(req.headers.get('authorization')?.slice(7) ?? '');
  if (user.role !== 'admin') return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  return NextResponse.json({ ok: true });
}
`);

export const CASES: RuleCase[] = [
  {
    ruleIds: [30401], name: 'MG-01 parseToken() base64-decodes the JWT payload and trusts the role vs jose jwtVerify',
    detects: [ROUTE, f('lib/auth.ts', `export function parseToken(token: string) {
  const [, payload] = token.split('.');
  const json = Buffer.from(payload, 'base64url').toString('utf8');
  return JSON.parse(json) as { sub: string; role: string };
}
`)],
    ignores: [ROUTE, f('lib/auth.ts', `import { jwtVerify } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET!);

export async function parseToken(token: string) {
  const { payload } = await jwtVerify(token, secret);
  return payload as { sub: string; role: string };
}

export function peekExpiry(token: string) {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).exp as number;
}
`)],
  },
  {
    ruleIds: [30401], name: 'MG-01 Express middleware sets req.user from an atob-decoded token vs a browser helper that only shows the name',
    detects: [f('server/middleware/auth.js', `function getUserFromToken(header) {
  const token = (header || '').replace('Bearer ', '');
  const parts = token.split('.');
  return JSON.parse(atob(parts[1]));
}

module.exports = function auth(req, res, next) {
  req.user = getUserFromToken(req.headers.authorization);
  if (!req.user.userId) return res.status(401).end();
  next();
};
`)],
    ignores: [f('src/components/UserBadge.tsx', `'use client';

export function displayName() {
  const token = localStorage.getItem('token') ?? '';
  const claims = JSON.parse(atob(token.split('.')[1]));
  return claims.email;
}
`)],
  },
  {
    ruleIds: [30401], name: 'MG-01 Python helper reads sub from a base64-decoded token vs an HMAC-checked one',
    detects: [f('app/auth.py', `import base64
import json

from fastapi import Header


def current_user_id(token: str) -> str:
    header, payload, signature = token.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data["sub"]
`)],
    ignores: [f('app/auth.py', `import base64
from fastapi import Header
import hashlib
import hmac
import json
import os


def current_user_id(token: str) -> str:
    header, payload, signature = token.split(".")
    expected = base64.urlsafe_b64encode(hmac.new(os.environ["SECRET"].encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()).rstrip(b"=")
    if not hmac.compare_digest(expected, signature.encode()):
        raise PermissionError("bad signature")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    return data["sub"]
`)],
  },
];
