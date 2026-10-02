import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/**
 * Wave 2-1: rules from the TLS, serverless, SAML, threat-detection, SLSA and UI-cliche engines that were narrowed
 * to a precise pattern. Every `ignores` is the idiomatic fix of the same code.
 */
export const CASES: RuleCase[] = [
  {
    ruleIds: [12301],
    name: 'TLS-01: HTTPS server accepting TLS 1.0 clients',
    detects: f('server/https.ts', `import https from 'node:https';
import { readFileSync } from 'node:fs';
import { app } from './app';

const server = https.createServer(
  {
    key: readFileSync('/etc/ssl/private/api.key'),
    cert: readFileSync('/etc/ssl/certs/api.crt'),
    minVersion: 'TLSv1',
  },
  app,
);

server.listen(443);
`),
    ignores: f('server/https.ts', `import https from 'node:https';
import { readFileSync } from 'node:fs';
import { app } from './app';

const server = https.createServer(
  {
    key: readFileSync('/etc/ssl/private/api.key'),
    cert: readFileSync('/etc/ssl/certs/api.crt'),
    minVersion: 'TLSv1.2',
  },
  app,
);

server.listen(443);
`),
  },
  {
    ruleIds: [12302],
    name: 'TLS-02: legacy cipher list enabling RC4 and 3DES',
    detects: f('server/tls.ts', `import tls from 'node:tls';
import { readFileSync } from 'node:fs';

export const tlsServer = tls.createServer({
  key: readFileSync('certs/server.key'),
  cert: readFileSync('certs/server.crt'),
  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:DES-CBC3-SHA',
  honorCipherOrder: true,
});
`),
    ignores: f('server/tls.ts', `import tls from 'node:tls';
import { readFileSync } from 'node:fs';

export const tlsServer = tls.createServer({
  key: readFileSync('certs/server.key'),
  cert: readFileSync('certs/server.crt'),
  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:!RC4:!3DES:!aNULL',
  honorCipherOrder: true,
});
`),
  },
  {
    ruleIds: [12304],
    name: 'TLS-04: Postgres pool with certificate verification disabled',
    detects: f('lib/db.ts', `import { Pool } from 'pg';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
`),
    ignores: f('lib/db.ts', `import { Pool } from 'pg';
import { readFileSync } from 'node:fs';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { ca: readFileSync('certs/rds-global-bundle.pem', 'utf8') },
});
`),
  },
  {
    ruleIds: [11301],
    name: 'SLS-01: API Gateway function with a 15 minute Lambda timeout',
    detects: f('serverless.yml', `service: orders-api

provider:
  name: aws
  runtime: nodejs20.x
  region: eu-west-1

functions:
  createOrder:
    handler: src/orders.create
    timeout: 900
    memorySize: 512
    events:
      - httpApi:
          path: /orders
          method: post
  nightlyExport:
    handler: src/export.run
    timeout: 900
    events:
      - schedule: cron(0 2 * * ? *)
`),
    ignores: f('serverless.yml', `service: orders-api

provider:
  name: aws
  runtime: nodejs20.x
  region: eu-west-1

functions:
  createOrder:
    handler: src/orders.create
    timeout: 29
    memorySize: 512
    events:
      - httpApi:
          path: /orders
          method: post
  nightlyExport:
    handler: src/export.run
    timeout: 900
    events:
      - schedule: cron(0 2 * * ? *)
`),
  },
  {
    ruleIds: [11302],
    name: 'SLS-02: PrismaClient constructed on every Lambda invocation',
    detects: f('src/handlers/orders.js', `const { PrismaClient } = require('@prisma/client');

exports.handler = async (event) => {
  const prisma = new PrismaClient();
  const orders = await prisma.order.findMany({
    where: { customerId: event.pathParameters.customerId },
  });
  return { statusCode: 200, body: JSON.stringify(orders) };
};
`),
    ignores: f('src/handlers/orders.js', `const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

exports.handler = async (event) => {
  const orders = await prisma.order.findMany({
    where: { customerId: event.pathParameters.customerId },
  });
  return { statusCode: 200, body: JSON.stringify(orders) };
};
`),
  },
  {
    ruleIds: [12802, 12803],
    name: 'SSO-02/03: passport-saml with audience and InResponseTo checks switched off',
    detects: f('lib/auth/saml.ts', `import passport from 'passport';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import { findOrCreateUser } from './users';

passport.use(
  new SamlStrategy(
    {
      callbackUrl: 'https://app.example.com/api/auth/saml/callback',
      entryPoint: process.env.SAML_ENTRY_POINT,
      issuer: 'https://app.example.com/saml/metadata',
      idpCert: process.env.SAML_IDP_CERT,
      audience: false,
      validateInResponseTo: 'never',
    },
    async (profile, done) => done(null, await findOrCreateUser(profile)),
    async (profile, done) => done(null, profile),
  ),
);
`),
    ignores: f('lib/auth/saml.ts', `import passport from 'passport';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import { findOrCreateUser } from './users';
import { samlRequestCache } from './saml-cache';

passport.use(
  new SamlStrategy(
    {
      callbackUrl: 'https://app.example.com/api/auth/saml/callback',
      entryPoint: process.env.SAML_ENTRY_POINT,
      issuer: 'https://app.example.com/saml/metadata',
      idpCert: process.env.SAML_IDP_CERT,
      audience: 'https://app.example.com/saml/metadata',
      validateInResponseTo: 'always',
      cacheProvider: samlRequestCache,
    },
    async (profile, done) => done(null, await findOrCreateUser(profile)),
    async (profile, done) => done(null, profile),
  ),
);
`),
  },
  {
    ruleIds: [13604],
    name: 'THREAT-04: diagnostics endpoint reading /etc/shadow',
    detects: f('app/api/diagnostics/route.ts', `import { readFile } from 'node:fs/promises';

export async function GET() {
  const accounts = await readFile('/etc/shadow', 'utf8');
  return Response.json({ accounts: accounts.split('\\n').length });
}
`),
    ignores: f('app/api/diagnostics/route.ts', `import { readFile } from 'node:fs/promises';

export async function GET() {
  const osRelease = await readFile('/etc/os-release', 'utf8');
  return Response.json({ os: osRelease.split('\\n')[0] });
}
`),
  },
  {
    ruleIds: [13202],
    name: 'OPA-02 (LOW advisory): policy admission webhook that fails open',
    detects: f('deploy/k8s/admission-webhook.yaml', `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-policy
webhooks:
  - name: image-policy.platform.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Ignore
    clientConfig:
      service:
        name: image-policy
        namespace: platform
        path: /validate
    rules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
`),
    ignores: f('deploy/k8s/admission-webhook.yaml', `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-policy
webhooks:
  - name: image-policy.platform.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]
    clientConfig:
      service:
        name: image-policy
        namespace: platform
        path: /validate
    rules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
`),
  },
  {
    ruleIds: [207],
    name: 'CLICHE-07: "Trusted by" strip filled with placeholder companies',
    detects: f('components/landing/logo-cloud.tsx', `export function LogoCloud() {
  return (
    <section className="py-12">
      <p className="text-center text-sm text-muted-foreground">Trusted by fast-growing teams</p>
      <div className="mt-6 flex flex-wrap justify-center gap-10">
        <img src="/logos/acme.svg" alt="Acme Corp" className="h-8" />
        <img src="/logos/globex.svg" alt="Globex" className="h-8" />
        <img src="/logos/nexora.svg" alt="Nexora" className="h-8" />
      </div>
    </section>
  );
}
`),
    ignores: f('components/landing/logo-cloud.tsx', `import { customers } from '@/content/customers';

export function LogoCloud() {
  return (
    <section className="py-12">
      <p className="text-center text-sm text-muted-foreground">Trusted by fast-growing teams</p>
      <div className="mt-6 flex flex-wrap justify-center gap-10">
        {customers.map((c) => (
          <img key={c.slug} src={c.logo} alt={c.name} className="h-8" />
        ))}
      </div>
    </section>
  );
}
`),
  },
  {
    ruleIds: [248],
    name: 'CLICHE-48: settings Switch without an accessible name',
    detects: f('components/settings/notifications.tsx', `'use client';
import { useState } from 'react';
import { Switch } from '@/components/ui/switch';

export function NotificationSettings() {
  const [emailEnabled, setEmailEnabled] = useState(true);
  return (
    <div className="flex items-center justify-between">
      <span>Email notifications</span>
      <Switch checked={emailEnabled} onCheckedChange={(v) => setEmailEnabled(v)} />
    </div>
  );
}
`),
    ignores: f('components/settings/notifications.tsx', `'use client';
import { useState } from 'react';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';

export function NotificationSettings() {
  const [emailEnabled, setEmailEnabled] = useState(true);
  return (
    <div className="flex items-center justify-between">
      <Label htmlFor="email-notifications">Email notifications</Label>
      <Switch id="email-notifications" checked={emailEnabled} onCheckedChange={(v) => setEmailEnabled(v)} />
    </div>
  );
}
`),
  },
  {
    ruleIds: [250],
    name: 'CLICHE-50: footer social links pointing at bare network domains',
    detects: f('components/site-footer.tsx', `import { Github, Twitter } from 'lucide-react';

export function SiteFooter() {
  return (
    <footer className="border-t py-8">
      <nav className="flex gap-4">
        <a href="https://twitter.com/" aria-label="Twitter"><Twitter className="h-5 w-5" /></a>
        <a href="https://github.com/launchkit" aria-label="GitHub"><Github className="h-5 w-5" /></a>
      </nav>
    </footer>
  );
}
`),
    ignores: f('components/site-footer.tsx', `import { Github, Twitter } from 'lucide-react';

export function SiteFooter() {
  return (
    <footer className="border-t py-8">
      <nav className="flex gap-4">
        <a href="https://twitter.com/launchkit" aria-label="Twitter"><Twitter className="h-5 w-5" /></a>
        <a href="https://github.com/launchkit" aria-label="GitHub"><Github className="h-5 w-5" /></a>
      </nav>
    </footer>
  );
}
`),
  },
  {
    ruleIds: [274],
    name: 'CLICHE-74: external link in a new tab without rel',
    detects: f('components/docs-link.tsx', `export function DocsLink() {
  return (
    <a href="https://docs.launchkit.dev/quickstart" target="_blank" className="underline">
      Read the quickstart
    </a>
  );
}
`),
    ignores: f('components/docs-link.tsx', `export function DocsLink() {
  return (
    <a href="https://docs.launchkit.dev/quickstart" target="_blank" rel="noopener noreferrer" className="underline">
      Read the quickstart
    </a>
  );
}
`),
  },
];
