import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

/**
 * Wave 3-4: API, Go, secrets, chaos, OAuth and search rules that survived the soundness review.
 * Each vulnerable fixture sits next to the idiomatic fixed version of the same code.
 */
const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// Assembled at runtime so secret scanners do not flag this file.
const fakeApiSecret = ['k7Qp2xVz9LmR4tYw', '8NcB3hJd6FsA1gKe', '5PuX0oTi'].join('');

// ---------------------------------------------------------------- API
const corsRoute = (methods: string) => `import { NextResponse } from 'next/server';

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': 'https://app.acme.dev',
      'Access-Control-Allow-Methods': '${methods}',
    },
  });
}
`;

const usersHandler = (where: string) => `import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const users = await prisma.user.findMany({
    where: ${where},
    take: 50,
  });
  res.status(200).json(users);
}
`;

const ordersRoute = (catchBody: string) => `import { NextResponse } from 'next/server';
import { Order } from '@/lib/models';

export async function POST(req: Request) {
  try {
    const order = await Order.create(await req.json());
    return NextResponse.json(order, { status: 201 });
  } catch (err: any) {
${catchBody}
  }
}
`;

const statusRoute = (ret: string) => `import { NextResponse } from 'next/server';

const ORDERS_URL = 'http://orders.default.svc.cluster.local:8080';

export async function GET() {
  const res = await fetch(\`\${ORDERS_URL}/healthz\`);
  ${ret}
}
`;

// ---------------------------------------------------------------- Go
const goRedirect = (body: string) => `package handlers

import (
	"net/http"
	"strings"
)

func LoginCallback(w http.ResponseWriter, r *http.Request) {
${body}
}

var _ = strings.HasPrefix
`;

const goOpen = (check: string) => `package config

import (
	"io"
	"os"
)

func Load(path string) string {
	f, err := os.Open(path)
${check}	defer f.Close()
	data, _ := io.ReadAll(f)
	return string(data)
}
`;

const goCookie = (httpOnly: string) => `package handlers

import "net/http"

func setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: ${httpOnly},
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
`;

const goCtx = (setup: string) => `package users

import (
	"context"
	"time"
)

func FetchUser(repo Repo, id string) (*User, error) {
${setup}
	return repo.Find(ctx, id)
}
`;

const goChan = (mk: string) => `package stats

func Count(nums []int) int {
	results := ${mk}
	results <- len(nums)
	return <-results
}
`;

// ---------------------------------------------------------------- client / config
const scrollSpy = (effect: string) => `'use client';
import { useEffect, useState } from 'react';

export function ScrollProgress() {
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    const onScroll = () => setProgress(window.scrollY / document.body.scrollHeight);
${effect}
  }, []);
  return <div style={{ width: \`\${progress * 100}%\` }} />;
}
`;

const oidcClients = (uri: string) => `export const clients = [
  {
    client_id: 'dashboard',
    client_secret: process.env.DASHBOARD_CLIENT_SECRET,
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['${uri}'],
  },
];
`;

const productSearch = (pattern: string) => `import { es } from './client';

export async function searchProducts(q: string) {
  return es.search({
    index: 'products',
    size: 20,
    query: { wildcard: { name: { value: ${pattern}, case_insensitive: true } } },
  });
}
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [7219],
    name: 'CORS preflight allowing every method vs an explicit method list',
    detects: f('app/api/proxy/route.ts', corsRoute('*')),
    ignores: f('app/api/proxy/route.ts', corsRoute('GET, POST, OPTIONS')),
  },
  {
    ruleIds: [7226],
    name: 'client query object used as the Prisma where clause vs an allow-listed filter',
    detects: f('pages/api/users.ts', usersHandler('req.query')),
    ignores: f('pages/api/users.ts', usersHandler("{ role: String(req.query.role ?? 'member') }")),
  },
  {
    ruleIds: [7237],
    name: 'raw Sequelize driver error returned in a 400 vs a generic message',
    detects: f('app/api/orders/route.ts', ordersRoute('    return NextResponse.json({ error: err.original }, { status: 400 });')),
    ignores: f('app/api/orders/route.ts', ordersRoute("    console.error('order insert failed', err.original);\n    return NextResponse.json({ error: 'Invalid order' }, { status: 400 });")),
  },
  {
    ruleIds: [7250],
    name: 'internal cluster hostname echoed in a public response vs a boolean status',
    detects: f('app/api/status/route.ts', statusRoute("return NextResponse.json({ ok: res.ok, upstream: 'http://orders.default.svc.cluster.local:8080' });")),
    ignores: f('app/api/status/route.ts', statusRoute('return NextResponse.json({ ok: res.ok });')),
  },
  {
    ruleIds: [9016],
    name: 'zero-copy byte/string cast through unsafe.Pointer vs a plain conversion',
    detects: f('internal/bytesconv/bytesconv.go', 'package bytesconv\n\nimport "unsafe"\n\nfunc BytesToString(b []byte) string {\n\treturn *(*string)(unsafe.Pointer(&b))\n}\n'),
    ignores: f('internal/bytesconv/bytesconv.go', 'package bytesconv\n\nfunc BytesToString(b []byte) string {\n\treturn string(b)\n}\n'),
  },
  {
    ruleIds: [9019],
    name: 'redirect to the raw ?next= value vs a relative-path check',
    detects: f('internal/handlers/auth.go', goRedirect('\thttp.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)')),
    ignores: f('internal/handlers/auth.go', goRedirect('\tnext := r.URL.Query().Get("next")\n\tif !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {\n\t\tnext = "/"\n\t}\n\thttp.Redirect(w, r, next, http.StatusFound)')),
  },
  {
    ruleIds: [9027],
    name: 'file handle used before the error is checked vs an err != nil guard',
    detects: f('internal/config/load.go', goOpen('')),
    ignores: f('internal/config/load.go', goOpen('\tif err != nil {\n\t\treturn ""\n\t}\n')),
  },
  {
    ruleIds: [9032],
    name: 'session cookie with HttpOnly turned off vs HttpOnly on',
    detects: f('internal/handlers/session.go', goCookie('false')),
    ignores: f('internal/handlers/session.go', goCookie('true')),
  },
  {
    ruleIds: [9037],
    name: 'context cancel func discarded vs defer cancel()',
    detects: f('internal/users/fetch.go', goCtx('\tctx, _ := context.WithTimeout(context.Background(), 5*time.Second)')),
    ignores: f('internal/users/fetch.go', goCtx('\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n\tdefer cancel()')),
  },
  {
    ruleIds: [9040],
    name: 'predictable file name in the shared temp dir vs os.CreateTemp',
    detects: f('internal/export/csv.go', 'package export\n\nimport (\n\t"os"\n\t"path/filepath"\n)\n\nfunc tempFile() (*os.File, error) {\n\treturn os.Create(filepath.Join(os.TempDir(), "export.csv"))\n}\n'),
    ignores: f('internal/export/csv.go', 'package export\n\nimport "os"\n\nfunc tempFile() (*os.File, error) {\n\treturn os.CreateTemp("", "export-*.csv")\n}\n'),
  },
  {
    ruleIds: [9049],
    name: 'send on an unbuffered channel from the only goroutine vs a buffered channel',
    detects: f('internal/stats/count.go', goChan('make(chan int)')),
    ignores: f('internal/stats/count.go', goChan('make(chan int, 1)')),
  },
  {
    ruleIds: [5100],
    name: 'random-looking API secret hardcoded vs read from the environment',
    detects: f('app/settings.py', `import os\n\nAPI_SECRET = "${fakeApiSecret}"\nDEBUG = os.environ.get("DEBUG") == "1"\n`),
    ignores: f('app/settings.py', 'import os\n\nAPI_SECRET = os.environ["API_SECRET"]\nDEBUG = os.environ.get("DEBUG") == "1"\n'),
  },
  {
    ruleIds: [8435],
    name: 'window scroll listener added in an effect without cleanup vs removed on unmount',
    detects: f('components/scroll-progress.tsx', scrollSpy("    window.addEventListener('scroll', onScroll);")),
    ignores: f('components/scroll-progress.tsx', scrollSpy("    window.addEventListener('scroll', onScroll);\n    return () => window.removeEventListener('scroll', onScroll);")),
  },
  {
    ruleIds: [10902],
    name: 'OAuth client registered with a wildcard sub-domain redirect URI vs the exact callback',
    detects: f('lib/auth/oidc-clients.ts', oidcClients('https://*.acme.app/api/auth/callback')),
    ignores: f('lib/auth/oidc-clients.ts', oidcClients('https://app.acme.app/api/auth/callback')),
  },
  {
    ruleIds: [13002],
    name: 'leading-wildcard search on user input vs a prefix (trailing) wildcard',
    detects: f('lib/search/products.ts', productSearch('`*${q}`')),
    ignores: f('lib/search/products.ts', productSearch('`${q}*`')),
  },
];
