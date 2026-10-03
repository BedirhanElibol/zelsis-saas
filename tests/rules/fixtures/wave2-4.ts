import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

/**
 * Wave 2-4: resilience, infra, mobile, HIPAA, e-commerce, realtime, mesh, graph/vector/TS DBs,
 * WASM, WireGuard, message queues, WAF and SCA rules. Each vulnerable fixture sits next to the
 * idiomatic fixed version of the same code.
 */
const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// ---------------------------------------------------------------- chaos / resilience
const route53 = (ttl: number) => `
resource "aws_route53_record" "api" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "api.example.com"
  type    = "A"
  ttl     = ${ttl}
  records = [aws_eip.api.public_ip]
}

resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "example.com"
  type    = "TXT"
  ttl     = 86400
  records = ["v=spf1 include:_spf.google.com ~all"]
}
`;

const rds = (multiAz: boolean) => `
resource "aws_db_instance" "main" {
  identifier          = "app-production"
  engine              = "postgres"
  engine_version      = "16.3"
  instance_class      = "db.r6g.large"
  allocated_storage   = 100
  multi_az            = ${multiAz}
  storage_encrypted   = true
  deletion_protection = true
}
`;

export const CASES: RuleCase[] = [
  {
    ruleIds: [8409],
    name: 'Route53 A record with a one-day TTL blocks fast failover',
    detects: f('infra/dns.tf', route53(86400)),
    ignores: f('infra/dns.tf', route53(60))
  },
  {
    ruleIds: [8411],
    name: 'one worker thread spawned per input item',
    detects: f('src/jobs/thumbnails.ts', `
import { Worker } from 'node:worker_threads';

export async function renderThumbnails(images: string[]) {
  return Promise.all(images.map((image) => new Promise((resolve, reject) => {
    const worker = new Worker('./thumbnail-worker.js', { workerData: image });
    worker.once('message', resolve);
    worker.once('error', reject);
  })));
}
`),
    ignores: f('src/jobs/thumbnails.ts', `
import Piscina from 'piscina';

const pool = new Piscina({ filename: new URL('./thumbnail-worker.js', import.meta.url).href });

export async function renderThumbnails(images: string[]) {
  return Promise.all(images.map((image) => pool.run(image)));
}
`)
  },
  {
    ruleIds: [8413],
    name: 'stream data handler writes without honouring backpressure',
    detects: f('src/export/csv-export.ts', `
import { createReadStream, createWriteStream } from 'node:fs';

export function copyExport(src: string, dest: string) {
  const input = createReadStream(src);
  const output = createWriteStream(dest);
  input.on('data', (chunk) => {
    output.write(chunk);
  });
  input.on('end', () => output.end());
}
`),
    ignores: f('src/export/csv-export.ts', `
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';

export async function copyExport(src: string, dest: string) {
  await pipeline(createReadStream(src), createWriteStream(dest));
}
`)
  },
  {
    ruleIds: [8418],
    name: 'production RDS instance pinned to a single AZ',
    detects: f('infra/database.tf', rds(false)),
    ignores: f('infra/database.tf', rds(true))
  },
  {
    ruleIds: [8421],
    name: 'Google Fonts import without display=swap',
    detects: f('app/globals.css', `@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600');\n\nbody { font-family: 'Inter', sans-serif; }\n`),
    ignores: f('app/globals.css', `@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');\n\nbody { font-family: 'Inter', sans-serif; }\n`)
  },
  {
    ruleIds: [8428],
    name: 'production logger hardcoded to debug level',
    detects: f('src/lib/logger.ts', `
import pino from 'pino';

export const logger = pino({
  level: 'debug',
  redact: ['req.headers.authorization'],
});
`),
    ignores: f('src/lib/logger.ts', `
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: ['req.headers.authorization'],
});
`)
  },
  {
    ruleIds: [8433],
    name: 'failed database write reported as success',
    detects: f('app/actions/save-profile.ts', `
'use server';
import { db } from '@/lib/db';

export async function saveProfile(userId: string, bio: string) {
  try {
    await db.profile.update({ where: { userId }, data: { bio } });
    return { success: true };
  } catch (error) {
    console.error('profile update failed', error);
    return { success: true };
  }
}
`),
    ignores: f('app/actions/save-profile.ts', `
'use server';
import { db } from '@/lib/db';

export async function saveProfile(userId: string, bio: string) {
  try {
    await db.profile.update({ where: { userId }, data: { bio } });
    return { success: true };
  } catch (error) {
    console.error('profile update failed', error);
    return { success: false, error: 'Could not save your profile' };
  }
}
`)
  },
  {
    ruleIds: [8435],
    name: 'useEffect adds a window listener without cleanup',
    detects: f('components/use-window-width.tsx', `
'use client';
import { useEffect, useState } from 'react';

export function useWindowWidth() {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const onResize = () => setWidth(window.innerWidth);
    window.addEventListener('resize', onResize);
    onResize();
  }, []);
  return width;
}
`),
    ignores: f('components/use-window-width.tsx', `
'use client';
import { useEffect, useState } from 'react';

export function useWindowWidth() {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const onResize = () => setWidth(window.innerWidth);
    window.addEventListener('resize', onResize);
    onResize();
    return () => window.removeEventListener('resize', onResize);
  }, []);
  return width;
}
`)
  },
  {
    ruleIds: [8438],
    name: 'database client reconnects instantly from its error handler',
    detects: f('src/db/client.ts', `
import { Client } from 'pg';

export const client = new Client({ connectionString: process.env.DATABASE_URL });

client.on('error', (err) => {
  console.error('postgres connection lost', err);
  client.connect();
});
`),
    ignores: f('src/db/client.ts', `
import { Client } from 'pg';

export const client = new Client({ connectionString: process.env.DATABASE_URL });
let attempt = 0;

client.on('error', (err) => {
  console.error('postgres connection lost', err);
  const wait = Math.min(30_000, 500 * 2 ** attempt++) + Math.random() * 250;
  setTimeout(() => client.connect(), wait);
});
`)
  },
  {
    ruleIds: [8439],
    name: 'production webpack bundle without content hash',
    detects: f('webpack.config.js', `
module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: __dirname + '/public/assets',
    filename: '[name].js',
  },
};
`),
    ignores: f('webpack.config.js', `
module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: __dirname + '/public/assets',
    filename: '[name].[contenthash].js',
  },
};
`)
  },

  // -------------------------------------------------------------- infra
  {
    ruleIds: [3003],
    name: 'production database URI with inline password',
    detects: f('src/db/pool.ts', `
import { Pool } from 'pg';

export const pool = new Pool({
  connectionString: '${['postgresql://app_admin', 'Tr0ub4dor-prod@db.prod-cluster.eu-west-1.rds.amazonaws.com:5432/app'].join(':')}',
});
`),
    ignores: f('src/db/pool.ts', `
import { Pool } from 'pg';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
`)
  },
  {
    ruleIds: [3004],
    name: 'credentialed CORS that reflects any origin',
    detects: f('src/server/app.ts', `
import express from 'express';
import cors from 'cors';

export const app = express();
app.use(cors({ origin: true, credentials: true }));
`),
    ignores: f('src/server/app.ts', `
import express from 'express';
import cors from 'cors';

export const app = express();
const allowedOrigins = [process.env.APP_URL!];
app.use(cors({ origin: allowedOrigins, credentials: true }));
`)
  },
  {
    ruleIds: [3005],
    name: 'debug route dumps environment without a guard',
    detects: f('app/api/debug/route.ts', `
export async function GET() {
  return Response.json({ env: process.env, versions: process.versions });
}
`),
    ignores: f('app/api/debug/route.ts', `
import { notFound } from 'next/navigation';

export async function GET() {
  if (process.env.NODE_ENV === 'production') notFound();
  return Response.json({ versions: process.versions });
}
`)
  },
  {
    ruleIds: [3007],
    name: 'Deployment container without resource limits',
    detects: f('k8s/api-deployment.yaml', `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          ports:
            - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  ports:
    - port: 80
      targetPort: 3000
`),
    ignores: f('k8s/api-deployment.yaml', `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          ports:
            - containerPort: 3000
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  ports:
    - port: 80
      targetPort: 3000
`)
  },
  {
    ruleIds: [3009],
    name: 'PrismaClient constructed inside the route handler',
    detects: f('app/api/orders/route.ts', `
import { PrismaClient } from '@prisma/client';

export async function GET() {
  const prisma = new PrismaClient();
  const orders = await prisma.order.findMany({ take: 20 });
  return Response.json(orders);
}
`),
    ignores: f('app/api/orders/route.ts', `
import { prisma } from '@/lib/prisma';

export async function GET() {
  const orders = await prisma.order.findMany({ take: 20 });
  return Response.json(orders);
}
`)
  },
  {
    ruleIds: [3011],
    name: 'remote Redis over plaintext redis://',
    detects: f('src/lib/cache.ts', `
import Redis from 'ioredis';

export const redis = new Redis('redis://cache-prod.abc123.use1.cache.amazonaws.com:6379');
`),
    ignores: f('src/lib/cache.ts', `
import Redis from 'ioredis';

export const redis = new Redis('rediss://cache-prod.abc123.use1.cache.amazonaws.com:6379');
`)
  },
  {
    ruleIds: [3012],
    name: 'S3 bucket with public-read ACL',
    detects: f('infra/storage.tf', `
resource "aws_s3_bucket" "invoices" {
  bucket = "acme-invoices"
}

resource "aws_s3_bucket_acl" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  acl    = "public-read"
}
`),
    ignores: f('infra/storage.tf', `
resource "aws_s3_bucket" "invoices" {
  bucket = "acme-invoices"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`)
  },
  {
    ruleIds: [3016],
    name: 'custom Node server without SIGTERM handling',
    detects: f('server.ts', `
import { createServer } from 'node:http';
import { app } from './src/app';

const server = createServer(app);
server.listen(process.env.PORT ?? 3000);
`),
    ignores: f('server.ts', `
import { createServer } from 'node:http';
import { app } from './src/app';

const server = createServer(app);
server.listen(process.env.PORT ?? 3000);

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
`)
  },
  {
    ruleIds: [3017],
    name: 'compose service mounts the host Docker socket',
    detects: f('docker-compose.yml', `
services:
  ci-runner:
    image: ghcr.io/acme/runner:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`),
    ignores: f('docker-compose.yml', `
services:
  ci-runner:
    image: ghcr.io/acme/runner:latest
    volumes:
      - runner-cache:/cache
volumes:
  runner-cache:
`)
  },
  {
    ruleIds: [3018],
    name: 'Firestore rules open to everyone',
    detects: f('firestore.rules', `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
`),
    ignores: f('firestore.rules', `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
`)
  },

  // -------------------------------------------------------------- mobile
  {
    ruleIds: [9301],
    name: 'auth token stored in plain SharedPreferences',
    detects: f('android/app/src/main/java/com/acme/auth/SessionStore.kt', `
package com.acme.auth

import android.content.Context

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE)

    fun save(token: String) {
        prefs.edit().putString("auth_token", token).apply()
    }
}
`),
    ignores: f('android/app/src/main/java/com/acme/auth/SessionStore.kt', `
package com.acme.auth

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SessionStore(context: Context) {
    private val key = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(context, "session", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)

    fun save(token: String) {
        prefs.edit().putString("auth_token", token).apply()
    }
}
`)
  },
  {
    ruleIds: [9302],
    name: 'OAuth client secret compiled into the iOS app',
    detects: f('ios/Acme/Config/OAuthConfig.swift', `
enum OAuthConfig {
    static let clientId = "acme-ios"
    static let clientSecret = "${['k9Fq2LmXv8', 'Rt4Wz7NpQs1Yb'].join('')}"
}
`),
    ignores: f('ios/Acme/Config/OAuthConfig.swift', `
enum OAuthConfig {
    static let clientId = "acme-ios"
    // public client: PKCE instead of a client secret
    static let usesPKCE = true
}
`)
  },
  {
    ruleIds: [9303],
    name: 'Android manifest allows cleartext HTTP',
    detects: f('android/app/src/main/AndroidManifest.xml', `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:label="Acme"
        android:usesCleartextTraffic="true">
    </application>
</manifest>
`),
    ignores: f('android/app/src/main/AndroidManifest.xml', `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:label="Acme"
        android:networkSecurityConfig="@xml/network_security_config">
    </application>
</manifest>
`)
  },
  {
    ruleIds: [9303],
    name: 'iOS ATS disabled with NSAllowsArbitraryLoads',
    detects: f('ios/Acme/Info.plist', `
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
`),
    ignores: f('ios/Acme/Info.plist', `
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        <key>NSAllowsLocalNetworking</key>
        <true/>
    </dict>
</dict>
</plist>
`)
  },
  {
    ruleIds: [9305],
    name: 'exported Android service without a permission',
    detects: f('android/app/src/main/AndroidManifest.xml', `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Acme">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".sync.SyncService"
            android:exported="true" />
    </application>
</manifest>
`),
    ignores: f('android/app/src/main/AndroidManifest.xml', `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Acme">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".sync.SyncService"
            android:exported="true"
            android:permission="com.acme.permission.SYNC" />
    </application>
</manifest>
`)
  },

  // -------------------------------------------------------------- HIPAA
  {
    ruleIds: [9802],
    name: 'patient MRN sent in a URL query string',
    detects: f('app/patients/[id]/chart-loader.ts', `
export async function loadChart(patient: { mrn: string }) {
  const res = await fetch(\`/api/charts?mrn=\${patient.mrn}\`);
  return res.json();
}
`),
    ignores: f('app/patients/[id]/chart-loader.ts', `
export async function loadChart(patient: { mrn: string }) {
  const res = await fetch('/api/charts/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mrn: patient.mrn }),
  });
  return res.json();
}
`)
  },
  {
    ruleIds: [9804],
    name: 'Meta pixel tracking on the patient portal',
    detects: f('app/patient-portal/appointments/confirmed.tsx', `
'use client';
import { useEffect } from 'react';

export function AppointmentConfirmed({ clinic }: { clinic: string }) {
  useEffect(() => {
    window.fbq('track', 'Schedule', { content_name: clinic });
  }, [clinic]);
  return <p>Your appointment with {clinic} is confirmed.</p>;
}
`),
    ignores: f('app/patient-portal/appointments/confirmed.tsx', `
'use client';

export function AppointmentConfirmed({ clinic }: { clinic: string }) {
  return <p>Your appointment with {clinic} is confirmed.</p>;
}
`)
  },
  {
    ruleIds: [9805],
    name: 'patient portal session cookie lives for 30 days',
    detects: f('src/server/patient-session.ts', `
import session from 'express-session';

export const patientSession = session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
  },
});
`),
    ignores: f('src/server/patient-session.ts', `
import session from 'express-session';

export const patientSession = session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: true,
    maxAge: 15 * 60 * 1000,
  },
});
`)
  },

  // -------------------------------------------------------------- e-commerce
  {
    ruleIds: [10101],
    name: 'stock decremented with read-modify-write',
    detects: f('app/actions/checkout.ts', `
'use server';
import { prisma } from '@/lib/prisma';

export async function reserveItem(productId: string, quantity: number) {
  const product = await prisma.product.findUniqueOrThrow({ where: { id: productId } });
  if (product.stock < quantity) throw new Error('Out of stock');
  await prisma.product.update({
    where: { id: productId },
    data: { stock: product.stock - quantity },
  });
}
`),
    ignores: f('app/actions/checkout.ts', `
'use server';
import { prisma } from '@/lib/prisma';

export async function reserveItem(productId: string, quantity: number) {
  const { count } = await prisma.product.updateMany({
    where: { id: productId, stock: { gte: quantity } },
    data: { stock: { decrement: quantity } },
  });
  if (count === 0) throw new Error('Out of stock');
}
`)
  },
  {
    ruleIds: [10102],
    name: 'checkout charges the price sent by the client',
    detects: f('app/api/checkout/route.ts', `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      quantity: 1,
      price_data: { currency: 'usd', product_data: { name: body.name }, unit_amount: body.price },
    }],
    success_url: \`\${process.env.APP_URL}/thanks\`,
  });
  return Response.json({ url: session.url });
}
`),
    ignores: f('app/api/checkout/route.ts', `
import Stripe from 'stripe';
import { getProduct } from '@/lib/catalog';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.json();
  const product = await getProduct(body.productId);
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ quantity: 1, price: product.stripePriceId }],
    success_url: \`\${process.env.APP_URL}/thanks\`,
  });
  return Response.json({ url: session.url });
}
`)
  },
  {
    ruleIds: [10104],
    name: 'cart quantity persisted without a lower bound',
    detects: f('src/routes/cart.ts', `
import { Router } from 'express';
import { db } from '../db';

export const cart = Router();

cart.post('/items', async (req, res) => {
  const item = await db.cartItem.create({
    data: { cartId: req.session.cartId, productId: req.body.productId, quantity: req.body.quantity },
  });
  res.json(item);
});
`),
    ignores: f('src/routes/cart.ts', `
import { Router } from 'express';
import { z } from 'zod';
import { db } from '../db';

export const cart = Router();
const AddItem = z.object({ productId: z.string(), quantity: z.number().int().positive().max(99) });

cart.post('/items', async (req, res) => {
  const body = AddItem.parse(req.body);
  const item = await db.cartItem.create({
    data: { cartId: req.session.cartId, productId: body.productId, quantity: body.quantity },
  });
  res.json(item);
});
`)
  },
  {
    ruleIds: [10105],
    name: 'guest cart id derived from the clock',
    detects: f('src/lib/cart-session.ts', `
export function ensureCart(cookies: Map<string, string>) {
  let cartId = cookies.get('cart_id');
  if (!cartId) {
    cartId = Date.now().toString(36);
    cookies.set('cart_id', cartId);
  }
  return cartId;
}
`),
    ignores: f('src/lib/cart-session.ts', `
import { randomUUID } from 'node:crypto';

export function ensureCart(cookies: Map<string, string>) {
  let cartId = cookies.get('cart_id');
  if (!cartId) {
    cartId = randomUUID();
    cookies.set('cart_id', cartId);
  }
  return cartId;
}
`)
  },

  // -------------------------------------------------------------- WebSocket
  {
    ruleIds: [10501],
    name: 'ws server never detects dead connections',
    detects: f('src/realtime/server.ts', `
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', (socket) => {
  socket.on('message', (data) => broadcast(data.toString()));
});

function broadcast(message: string) {
  for (const client of wss.clients) client.send(message);
}
`),
    ignores: f('src/realtime/server.ts', `
import { WebSocketServer, type WebSocket } from 'ws';

const wss = new WebSocketServer({ port: 8080 });
const alive = new WeakMap<WebSocket, boolean>();

wss.on('connection', (socket) => {
  alive.set(socket, true);
  socket.on('pong', () => alive.set(socket, true));
  socket.on('message', (data) => broadcast(data.toString()));
});

setInterval(() => {
  for (const client of wss.clients) {
    if (!alive.get(client)) { client.terminate(); continue; }
    alive.set(client, false);
    client.ping();
  }
}, 30_000);

function broadcast(message: string) {
  for (const client of wss.clients) client.send(message);
}
`)
  },
  {
    ruleIds: [10502],
    name: 'WebSocket upgrade accepted without authentication',
    detects: f('src/realtime/gateway.ts', `
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';

const server = createServer();
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

server.listen(8080);
`),
    ignores: f('src/realtime/gateway.ts', `
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { verifyAccessToken } from '../auth/tokens';

const server = createServer();
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', async (req, socket, head) => {
  const token = new URL(req.url ?? '', 'http://localhost').searchParams.get('token');
  const user = token ? await verifyAccessToken(token).catch(() => null) : null;
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\\r\\n\\r\\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, user));
});

server.listen(8080);
`)
  },
  {
    ruleIds: [10503],
    name: 'cookie-authenticated WebSocket upgrade without an Origin check',
    detects: f('src/realtime/gateway.ts', `
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { getSessionFromCookie } from '../auth/session';

const server = createServer();
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', async (req, socket, head) => {
  const user = await getSessionFromCookie(req.headers.cookie);
  if (!user) return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, user));
});
`),
    ignores: f('src/realtime/gateway.ts', `
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { getSessionFromCookie } from '../auth/session';

const server = createServer();
const wss = new WebSocketServer({ noServer: true });
const APP_ORIGIN = process.env.APP_URL;

server.on('upgrade', async (req, socket, head) => {
  if (req.headers.origin !== APP_ORIGIN) return socket.destroy();
  const user = await getSessionFromCookie(req.headers.cookie);
  if (!user) return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, user));
});
`)
  },
  {
    ruleIds: [10505],
    name: 'client reconnects on a fixed one-second timer',
    detects: f('components/live-feed/socket.ts', `
export function connectFeed(onEvent: (e: MessageEvent) => void) {
  const socket = new WebSocket(process.env.NEXT_PUBLIC_FEED_URL!);
  socket.onmessage = onEvent;
  socket.onclose = () => {
    setTimeout(() => connectFeed(onEvent), 1000);
  };
  return socket;
}
`),
    ignores: f('components/live-feed/socket.ts', `
export function connectFeed(onEvent: (e: MessageEvent) => void, attempt = 0) {
  const socket = new WebSocket(process.env.NEXT_PUBLIC_FEED_URL!);
  socket.onopen = () => { attempt = 0; };
  socket.onmessage = onEvent;
  socket.onclose = () => {
    const delay = Math.min(30_000, 1000 * 2 ** attempt) * (0.5 + Math.random());
    setTimeout(() => connectFeed(onEvent, attempt + 1), delay);
  };
  return socket;
}
`)
  },

  // -------------------------------------------------------------- service mesh
  {
    ruleIds: [11201],
    name: 'Istio PeerAuthentication left in PERMISSIVE mode',
    detects: f('k8s/istio/peer-authentication.yaml', `
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: payments
spec:
  mtls:
    mode: PERMISSIVE
`),
    ignores: f('k8s/istio/peer-authentication.yaml', `
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: payments
spec:
  mtls:
    mode: STRICT
`)
  },
  {
    ruleIds: [11204],
    name: 'fault injection left in the production VirtualService',
    detects: f('k8s/istio/checkout-virtualservice.yaml', `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: checkout
spec:
  hosts:
    - checkout
  http:
    - fault:
        delay:
          percentage:
            value: 10
          fixedDelay: 5s
      route:
        - destination:
            host: checkout
`),
    ignores: f('k8s/istio/checkout-virtualservice.yaml', `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: checkout
spec:
  hosts:
    - checkout
  http:
    - timeout: 3s
      retries:
        attempts: 2
        perTryTimeout: 1s
      route:
        - destination:
            host: checkout
`)
  },

  // -------------------------------------------------------------- graph database
  {
    ruleIds: [12001],
    name: 'Cypher variable-length traversal without an upper bound',
    detects: f('src/graph/recommendations.ts', `
import { driver } from './neo4j';

export async function relatedProducts(productId: string) {
  const session = driver.session();
  try {
    const result = await session.run(
      'MATCH (p:Product {id: $productId})-[:BOUGHT_WITH*]-(other:Product) RETURN DISTINCT other LIMIT 20',
      { productId },
    );
    return result.records.map((r) => r.get('other').properties);
  } finally {
    await session.close();
  }
}
`),
    ignores: f('src/graph/recommendations.ts', `
import { driver } from './neo4j';

export async function relatedProducts(productId: string) {
  const session = driver.session();
  try {
    const result = await session.run(
      'MATCH (p:Product {id: $productId})-[:BOUGHT_WITH*1..3]-(other:Product) RETURN DISTINCT other LIMIT 20',
      { productId },
    );
    return result.records.map((r) => r.get('other').properties);
  } finally {
    await session.close();
  }
}
`)
  },
  {
    ruleIds: [12002],
    name: 'Cypher query built with string interpolation',
    detects: f('src/graph/users.ts', `
import { driver } from './neo4j';

export async function findUser(email: string) {
  const session = driver.session();
  const result = await session.run(\`MATCH (u:User) WHERE u.email = '\${email}' RETURN u\`);
  await session.close();
  return result.records[0]?.get('u').properties;
}
`),
    ignores: f('src/graph/users.ts', `
import { driver } from './neo4j';

export async function findUser(email: string) {
  const session = driver.session();
  const result = await session.run('MATCH (u:User) WHERE u.email = $email RETURN u', { email });
  await session.close();
  return result.records[0]?.get('u').properties;
}
`)
  },

  // -------------------------------------------------------------- WebAssembly
  {
    ruleIds: [12701],
    name: 'WebAssembly memory without a maximum size',
    detects: f('src/plugins/runtime.ts', `
export async function loadPlugin(bytes: ArrayBuffer) {
  const memory = new WebAssembly.Memory({ initial: 16 });
  const { instance } = await WebAssembly.instantiate(bytes, { env: { memory } });
  return instance;
}
`),
    ignores: f('src/plugins/runtime.ts', `
export async function loadPlugin(bytes: ArrayBuffer) {
  const memory = new WebAssembly.Memory({ initial: 16, maximum: 256 });
  const { instance } = await WebAssembly.instantiate(bytes, { env: { memory } });
  return instance;
}
`)
  },
  {
    ruleIds: [12703],
    name: 'WASI sandbox preopens the host root directory',
    detects: f('src/plugins/wasi-host.ts', `
import { WASI } from 'node:wasi';

export function createSandbox(args: string[]) {
  return new WASI({
    version: 'preview1',
    args,
    preopens: {
      '/sandbox': '/',
    },
  });
}
`),
    ignores: f('src/plugins/wasi-host.ts', `
import { WASI } from 'node:wasi';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function createSandbox(args: string[]) {
  const workDir = mkdtempSync(join(tmpdir(), 'plugin-'));
  return new WASI({
    version: 'preview1',
    args,
    preopens: {
      '/sandbox': workDir,
    },
  });
}
`)
  },

  // -------------------------------------------------------------- WireGuard / network perimeter
  {
    ruleIds: [13102],
    name: 'full-tunnel WireGuard client without a DNS server',
    detects: f('deploy/wireguard/laptop.conf', `
[Interface]
Address = 10.8.0.5/32
PrivateKey = \${WG_PRIVATE_KEY}

[Peer]
PublicKey = \${WG_SERVER_PUBLIC_KEY}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
`),
    ignores: f('deploy/wireguard/laptop.conf', `
[Interface]
Address = 10.8.0.5/32
PrivateKey = \${WG_PRIVATE_KEY}
DNS = 10.8.0.1

[Peer]
PublicKey = \${WG_SERVER_PUBLIC_KEY}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
`)
  },
  {
    ruleIds: [13103],
    name: 'security group opens PostgreSQL to the internet',
    detects: f('infra/network.tf', `
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`),
    ignores: f('infra/network.tf', `
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)
  },
  {
    ruleIds: [13105],
    name: 'WireGuard private key committed in a config',
    detects: f('deploy/wireguard/wg0.conf', `
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${['yAnz5TF', 'lXXJte14tji3zlMNq', 'hd2rYUIgJBgB3fBmk='].join('+')}
`),
    ignores: f('deploy/wireguard/wg0.conf', `
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/private.key
`)
  },

  // -------------------------------------------------------------- vector / time-series / queues
  {
    ruleIds: [13503],
    name: 'vector search asking for 5000 neighbours',
    detects: f('src/search/semantic.ts', `
import { Pinecone } from '@pinecone-database/pinecone';

const index = new Pinecone().index('docs');

export async function search(vector: number[]) {
  return index.query({ vector, topK: 5000, includeMetadata: true });
}
`),
    ignores: f('src/search/semantic.ts', `
import { Pinecone } from '@pinecone-database/pinecone';

const index = new Pinecone().index('docs');

export async function search(vector: number[]) {
  return index.query({ vector, topK: 20, includeMetadata: true });
}
`)
  },
  {
    ruleIds: [14003],
    name: 'Prometheus metric labelled with the user id',
    detects: f('src/metrics/http.ts', `
import client from 'prom-client';

const requests = new client.Counter({ name: 'http_requests_total', help: 'requests', labelNames: ['route', 'userId'] });

export function track(route: string, userId: string) {
  requests.inc({ route, userId: userId });
}
`),
    ignores: f('src/metrics/http.ts', `
import client from 'prom-client';

const requests = new client.Counter({ name: 'http_requests_total', help: 'requests', labelNames: ['route', 'plan'] });

export function track(route: string, plan: 'free' | 'pro') {
  requests.inc({ route, plan });
}
`)
  },
  {
    ruleIds: [14503],
    name: 'RabbitMQ keeps the default guest account',
    detects: f('deploy/rabbitmq/rabbitmq.conf', `
listeners.tcp.default = 5672
management.tcp.port = 15672
loopback_users = none
default_user = guest
default_pass = guest
`),
    ignores: f('deploy/rabbitmq/rabbitmq.conf', `
listeners.tcp.default = 5672
management.tcp.port = 15672
default_user = acme_admin
default_pass_file = /run/secrets/rabbitmq_password
`)
  },

  // -------------------------------------------------------------- WAF / edge
  {
    ruleIds: [10405],
    name: 'JSON body limit raised to 100 MB',
    detects: f('src/server/app.ts', `
import express from 'express';

export const app = express();
app.use(express.json({ limit: '100mb' }));
`),
    ignores: f('src/server/app.ts', `
import express from 'express';

export const app = express();
app.use(express.json({ limit: '1mb' }));
`)
  },

  // -------------------------------------------------------------- SCA
  {
    ruleIds: [27211],
    name: 'dependency pinned to a vulnerable axios release',
    detects: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { axios: '0.21.1', next: '14.2.5' } }, null, 2)),
    ignores: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { axios: '^1.7.4', next: '14.2.5' } }, null, 2))
  },
  {
    ruleIds: [27211],
    name: 'caret range that can float to a patched release is not reported',
    detects: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { semver: '~6.1.0' } }, null, 2)),
    ignores: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { semver: '^6.1.0', axios: '^1.6.0' } }, null, 2))
  },
  {
    ruleIds: [27212],
    name: 'deprecated request library in dependencies',
    detects: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { request: '^2.88.2' } }, null, 2)),
    ignores: f('package.json', JSON.stringify({ name: 'shop', private: true, dependencies: { undici: '^6.19.8' } }, null, 2))
  },
];
