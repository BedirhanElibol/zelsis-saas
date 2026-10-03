import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
// Assembled at runtime so secret scanners do not flag this fixture file itself.
const LITERAL_SECRET = ['conduit', 'jwt', 'signing', 'key'].join('-');

export const CASES: RuleCase[] = [
  {
    ruleIds: [28101], name: 'NODE-WEB-01 res.sendFile with request path',
    detects: f('src/routes/files.ts', `import path from 'path';
router.get('/files/:name', (req, res) => {
  res.sendFile(path.join(__dirname, '../uploads', req.params.name));
});
`),
    ignores: f('src/routes/files.ts', `import path from 'path';
router.get('/files/:name', (req, res) => {
  res.sendFile(path.basename(req.params.name), { root: path.join(__dirname, '../uploads') });
});
`)
  },
  {
    ruleIds: [28102], name: 'NODE-WEB-02 prototype pollution via nested request keys',
    detects: f('src/routes/settings.ts', `router.post('/settings', requireAuth, (req, res) => {
  const { section, key, value } = req.body;
  const prefs = loadPrefs(req.user.id);
  prefs[section][key] = value;
  savePrefs(req.user.id, prefs);
  res.json(prefs);
});
`),
    ignores: f('src/routes/settings.ts', `const SECTIONS = new Set(['ui', 'email']);
router.post('/settings', requireAuth, (req, res) => {
  const { section, key, value } = req.body;
  const prefs = loadPrefs(req.user.id);
  if (!SECTIONS.has(section) || !Object.hasOwn(prefs[section], key)) return res.status(400).end();
  prefs[section][key] = value;
  savePrefs(req.user.id, prefs);
  res.json(prefs);
});
`)
  },
  {
    ruleIds: [28103], name: 'NODE-WEB-03 req.query used as Mongo filter',
    detects: f('src/controllers/products.ts', `export async function listProducts(req, res) {
  const products = await Product.find(req.query).limit(50);
  res.json(products);
}
`),
    ignores: f('src/controllers/products.ts', `export async function listProducts(req, res) {
  const { category } = listQuery.parse(req.query);
  const products = await Product.find({ category: String(category) }).limit(50);
  res.json(products);
}
`)
  },
  {
    ruleIds: [28104], name: 'NODE-WEB-04 login query includes request password',
    detects: f('src/routes/auth.ts', `router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: issueToken(user) });
});
`),
    ignores: f('src/routes/auth.ts', `router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: String(email) });
  if (!user || !(await bcrypt.compare(String(password), user.passwordHash))) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: issueToken(user) });
});
`)
  },
  {
    ruleIds: [28105], name: 'NODE-WEB-05 RegExp from query string',
    detects: f('src/routes/search.ts', `router.get('/search', async (req, res) => {
  const pattern = new RegExp(req.query.q, 'i');
  res.json(await Post.find({ title: pattern }));
});
`),
    ignores: f('src/routes/search.ts', `import escapeStringRegexp from 'escape-string-regexp';
router.get('/search', async (req, res) => {
  const pattern = new RegExp(escapeStringRegexp(String(req.query.q ?? '')), 'i');
  res.json(await Post.find({ title: pattern }));
});
`)
  },
  {
    ruleIds: [28106], name: 'NODE-WEB-06 hardcoded jwt.sign secret',
    detects: f('src/services/auth.ts', `import jwt from 'jsonwebtoken';
export const issueToken = (user) => jwt.sign({ id: user.id, role: user.role }, '${LITERAL_SECRET}', { expiresIn: '1h' });
`),
    ignores: f('src/services/auth.ts', `import jwt from 'jsonwebtoken';
export const issueToken = (user) => jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET!, { expiresIn: '1h' });
`)
  },
  {
    ruleIds: [28107], name: 'NODE-WEB-07 webhook HMAC compared with ===',
    detects: f('src/routes/webhooks.ts', `import crypto from 'crypto';
router.post('/webhooks/github', express.raw({ type: '*/*' }), (req, res) => {
  const signature = req.get('x-hub-signature-256') || '';
  const expected = 'sha256=' + crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!).update(req.body).digest('hex');
  if (signature !== expected) return res.status(401).end();
  res.sendStatus(204);
});
`),
    ignores: f('src/routes/webhooks.ts', `import crypto from 'crypto';
router.post('/webhooks/github', express.raw({ type: '*/*' }), (req, res) => {
  const signature = Buffer.from(req.get('x-hub-signature-256') || '');
  const expected = Buffer.from('sha256=' + crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!).update(req.body).digest('hex'));
  if (signature.length !== expected.length || !crypto.timingSafeEqual(signature, expected)) return res.status(401).end();
  res.sendStatus(204);
});
`)
  },
  {
    ruleIds: [28108], name: 'NODE-WEB-08 crypto.createCipher',
    detects: f('src/lib/encrypt.ts', `import crypto from 'crypto';
export function encrypt(text: string) {
  const cipher = crypto.createCipher('aes-256-cbc', process.env.ENC_KEY!);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
`),
    ignores: f('src/lib/encrypt.ts', `import crypto from 'crypto';
export function encrypt(text: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(process.env.ENC_KEY!, 'hex'), iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString('hex')).join('.');
}
`)
  },
  {
    ruleIds: [28109], name: 'NODE-WEB-09 zero IV for createCipheriv',
    detects: f('src/lib/encrypt.ts', `import crypto from 'crypto';
const IV = Buffer.alloc(16, 0);
export function encrypt(text: string, key: Buffer) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, IV);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
`),
    ignores: f('src/lib/encrypt.ts', `import crypto from 'crypto';
export function encrypt(text: string, key: Buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + ':' + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
`)
  },
  {
    ruleIds: [28110], name: 'NODE-WEB-10 reflected XSS via res.send template',
    detects: f('src/routes/greet.ts', `router.get('/hello', (req, res) => {
  res.send(\`<h1>Hello \${req.query.name}</h1>\`);
});
`),
    ignores: f('src/routes/greet.ts', `import escapeHtml from 'escape-html';
router.get('/hello', (req, res) => {
  res.send(\`<h1>Hello \${escapeHtml(String(req.query.name ?? ''))}</h1>\`);
});
`)
  },
  {
    ruleIds: [28111], name: 'NODE-WEB-11 res.render view from request',
    detects: f('src/routes/pages.ts', `router.get('/page/:name', (req, res) => {
  res.render(req.params.name, { user: req.user });
});
`),
    ignores: f('src/routes/pages.ts', `const PAGES = { about: 'about', pricing: 'pricing' } as const;
router.get('/page/:name', (req, res) => {
  const view = PAGES[req.params.name as keyof typeof PAGES];
  if (!view) return res.status(404).end();
  res.render(view, { user: req.user });
});
`)
  },
  {
    ruleIds: [28112], name: 'NODE-WEB-12 req.query as render locals',
    detects: f('src/routes/search.ts', `router.get('/search', (req, res) => {
  res.render('search', req.query);
});
`),
    ignores: f('src/routes/search.ts', `router.get('/search', (req, res) => {
  res.render('search', { q: String(req.query.q ?? '') });
});
`)
  },
  {
    ruleIds: [28113], name: 'NODE-WEB-13 zip slip with unzipper',
    detects: f('src/services/import.ts', `import unzipper from 'unzipper';
import fs from 'fs';
import path from 'path';
export function extract(zipPath: string, outDir: string) {
  return fs.createReadStream(zipPath).pipe(unzipper.Parse()).on('entry', (entry) => {
    const target = path.join(outDir, entry.path);
    entry.pipe(fs.createWriteStream(target));
  });
}
`),
    ignores: f('src/services/import.ts', `import unzipper from 'unzipper';
import fs from 'fs';
import path from 'path';
export function extract(zipPath: string, outDir: string) {
  const root = path.resolve(outDir);
  return fs.createReadStream(zipPath).pipe(unzipper.Parse()).on('entry', (entry) => {
    const target = path.resolve(root, entry.path);
    if (!target.startsWith(root + path.sep)) return entry.autodrain();
    entry.pipe(fs.createWriteStream(target));
  });
}
`)
  },
  {
    ruleIds: [28114], name: 'NODE-WEB-14 vm.runInNewContext with request body',
    detects: f('src/routes/formula.ts', `import vm from 'vm';
router.post('/formula', (req, res) => {
  const result = vm.runInNewContext(req.body.expression, { Math });
  res.json({ result });
});
`),
    ignores: f('src/routes/formula.ts', `import { evaluate } from 'mathjs';
router.post('/formula', (req, res) => {
  const result = evaluate(String(req.body.expression));
  res.json({ result });
});
`)
  },
  {
    ruleIds: [28115], name: 'NODE-WEB-15 vm2 sandbox',
    detects: f('src/sandbox/run.ts', `const { VM } = require('vm2');
export const runSnippet = (code: string) => new VM({ timeout: 1000 }).run(code);
`),
    ignores: f('src/sandbox/run.ts', `import ivm from 'isolated-vm';
export async function runSnippet(code: string) {
  const isolate = new ivm.Isolate({ memoryLimit: 32 });
  const context = await isolate.createContext();
  return context.eval(code, { timeout: 1000 });
}
`)
  },
  {
    ruleIds: [28116], name: 'NODE-WEB-16 spawn with shell: true and request input',
    detects: f('src/routes/tools.ts', `import { spawn } from 'child_process';
router.post('/ping', (req, res) => {
  const host = req.body.host;
  const proc = spawn('ping', ['-c', '1', host], { shell: true });
  proc.stdout.pipe(res);
});
`),
    ignores: f('src/routes/tools.ts', `import { spawn } from 'child_process';
import net from 'net';
router.post('/ping', (req, res) => {
  const host = req.body.host;
  if (!net.isIP(host)) return res.status(400).end();
  const proc = spawn('ping', ['-c', '1', host]);
  proc.stdout.pipe(res);
});
`)
  },
  {
    ruleIds: [28117], name: 'NODE-WEB-17 require of request parameter',
    detects: f('src/routes/export.ts', `router.get('/export/:format', (req, res) => {
  const exporter = require(\`../exporters/\${req.params.format}\`);
  exporter.run(req, res);
});
`),
    ignores: f('src/routes/export.ts', `import csv from '../exporters/csv';
import json from '../exporters/json';
const EXPORTERS = { csv, json } as const;
router.get('/export/:format', (req, res) => {
  const exporter = EXPORTERS[req.params.format as keyof typeof EXPORTERS];
  if (!exporter) return res.status(404).end();
  exporter.run(req, res);
});
`)
  },
  {
    ruleIds: [28118], name: 'NODE-WEB-18 SSRF from Hono query',
    detects: f('src/index.ts', `import { Hono } from 'hono';
const app = new Hono();
app.get('/preview', async (c) => {
  const page = await fetch(c.req.query('url')!);
  return c.text(await page.text());
});
`),
    ignores: f('src/index.ts', `import { Hono } from 'hono';
const ALLOWED_HOSTS = new Set(['example.com']);
const app = new Hono();
app.get('/preview', async (c) => {
  const target = new URL(c.req.query('url') ?? '');
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) return c.text('forbidden', 403);
  const page = await fetch(target);
  return c.text(await page.text());
});
`)
  },
  {
    ruleIds: [28119], name: 'NODE-WEB-19 open redirect in Koa',
    detects: f('src/routes/session.ts', `router.get('/logout', async (ctx) => {
  ctx.session = null;
  ctx.redirect(ctx.query.returnTo);
});
`),
    ignores: f('src/routes/session.ts', `router.get('/logout', async (ctx) => {
  ctx.session = null;
  const back = String(ctx.query.returnTo ?? '/');
  const safe = back.startsWith('/') && !back.startsWith('//') ? back : '/';
  ctx.redirect(safe);
});
`)
  },
  {
    ruleIds: [28120], name: 'NODE-WEB-20 reset link from Host header',
    detects: f('src/routes/password.ts', `router.post('/forgot-password', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    const token = await createResetToken(user);
    const resetUrl = \`\${req.protocol}://\${req.get('host')}/reset-password?token=\${token}\`;
    await mailer.send(user.email, 'Reset your password', resetUrl);
  }
  res.sendStatus(204);
});
`),
    ignores: f('src/routes/password.ts', `router.post('/forgot-password', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    const token = await createResetToken(user);
    const resetUrl = \`\${process.env.APP_URL}/reset-password?token=\${token}\`;
    await mailer.send(user.email, 'Reset your password', resetUrl);
  }
  res.sendStatus(204);
});
`)
  },
  {
    ruleIds: [28121], name: 'NODE-WEB-21 password hashed with sha256',
    detects: f('src/services/users.ts', `import crypto from 'crypto';
export async function register(email: string, password: string) {
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  return db.user.create({ data: { email, passwordHash: hash } });
}
`),
    ignores: f('src/services/users.ts', `import argon2 from 'argon2';
export async function register(email: string, password: string) {
  const hash = await argon2.hash(password, { type: argon2.argon2id });
  return db.user.create({ data: { email, passwordHash: hash } });
}
`)
  },
  {
    ruleIds: [28122], name: 'NODE-WEB-22 CORS reflects Origin with credentials',
    detects: f('src/middleware/cors.ts', `export function cors(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}
`),
    ignores: f('src/middleware/cors.ts', `const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
export function cors(req, res, next) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
}
`)
  },
  {
    ruleIds: [28123], name: 'NODE-WEB-23 express.static serves project root',
    detects: f('server.js', `const express = require('express');
const app = express();
app.use(express.static(__dirname));
app.listen(3000);
`),
    ignores: f('server.js', `const express = require('express');
const path = require('path');
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.listen(3000);
`)
  },
  {
    ruleIds: [28124], name: 'NODE-WEB-24 JWT verify accepts HS256 and RS256',
    detects: f('src/middleware/auth.ts', `import jwt from 'jsonwebtoken';
export const verifyToken = (token: string) => jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
`),
    ignores: f('src/middleware/auth.ts', `import jwt from 'jsonwebtoken';
export const verifyToken = (token: string) => jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
`)
  },
  {
    ruleIds: [28125], name: 'NODE-WEB-25 knex orderByRaw with request input',
    detects: f('src/repositories/orders.ts', `export async function listOrders(req, res) {
  const { sort } = req.query;
  const rows = await knex('orders').where('user_id', req.user.id).orderByRaw(\`\${sort} desc\`);
  res.json(rows);
}
`),
    ignores: f('src/repositories/orders.ts', `const SORTABLE = { created: 'created_at', total: 'total' } as const;
export async function listOrders(req, res) {
  const column = SORTABLE[req.query.sort as keyof typeof SORTABLE] ?? 'created_at';
  const rows = await knex('orders').where('user_id', req.user.id).orderBy(column, 'desc');
  res.json(rows);
}
`)
  }
];
