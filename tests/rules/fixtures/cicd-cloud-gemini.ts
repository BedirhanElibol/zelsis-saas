import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const WF = '.github/workflows/ci.yml';

export const CASES: RuleCase[] = [
  {
    ruleIds: [29943], name: 'CIG-01 ingress-nginx snippet annotation',
    detects: f('k8s/ingress.yaml', `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
`),
    ignores: f('k8s/ingress.yaml', `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
`),
  },
  {
    ruleIds: [29944], name: 'CIG-02 pip extra-index-url',
    detects: f('requirements.txt', `--extra-index-url https://pypi.internal.example.com/simple
acme-utils==1.2.0
`),
    ignores: f('requirements.txt', `--index-url https://pypi.internal.example.com/simple
acme-utils==1.2.0
`),
  },
  {
    ruleIds: [29945], name: 'CIG-03 yarn checksumBehavior ignore',
    detects: f('.yarnrc.yml', `checksumBehavior: ignore
nodeLinker: node-modules
`),
    ignores: f('.yarnrc.yml', `nodeLinker: node-modules
`),
  },
  {
    ruleIds: [29946], name: 'CIG-04 Service externalIPs',
    detects: f('k8s/svc.yaml', `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  externalIPs:
    - 10.0.0.5
  ports:
    - port: 80
`),
    ignores: f('k8s/svc.yaml', `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: ClusterIP
  ports:
    - port: 80
`),
  },
  {
    ruleIds: [29947], name: 'CIG-05 pull requests on a self-hosted runner',
    detects: f(WF, `on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
`),
    ignores: f(WF, `on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
`),
  },
  {
    ruleIds: [29948], name: 'CIG-06 nginx real IP from anywhere',
    detects: f('nginx/nginx.conf', `http {
  set_real_ip_from 0.0.0.0/0;
  real_ip_header X-Forwarded-For;
}
`),
    ignores: f('nginx/nginx.conf', `http {
  set_real_ip_from 10.0.0.0/8;
  real_ip_header X-Forwarded-For;
}
`),
  },
  {
    ruleIds: [29949], name: 'CIG-07 Redis protected-mode off without password',
    detects: f('redis/redis.conf', `bind 0.0.0.0
protected-mode no
`),
    ignores: f('redis/redis.conf', `bind 0.0.0.0
protected-mode no
requirepass \${REDIS_PASSWORD}
`),
  },
  {
    ruleIds: [29950], name: 'CIG-08 git dependency on a branch',
    detects: f('requirements.txt', `git+https://github.com/acme/lib.git@main#egg=lib
`),
    ignores: f('requirements.txt', `git+https://github.com/acme/lib.git@3f2c1a9b7d4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a#egg=lib
`),
  },
  {
    ruleIds: [29951], name: 'CIG-09 admission webhook fails open',
    detects: f('k8s/webhook.yaml', `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: policy
webhooks:
  - name: policy.example.com
    failurePolicy: Ignore
`),
    ignores: f('k8s/webhook.yaml', `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: policy
webhooks:
  - name: policy.example.com
    failurePolicy: Fail
`),
  },
  {
    ruleIds: [29952], name: 'CIG-10 uv unsafe index strategy',
    detects: f('uv.toml', `index-strategy = "unsafe-best-match"
`),
    ignores: f('uv.toml', `[[index]]
url = "https://pypi.internal.example.com/simple"
`),
  },
  {
    ruleIds: [29953], name: 'CIG-11 dispatch input in run',
    detects: f(WF, `on:
  workflow_dispatch:
    inputs:
      tag:
        required: true
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: |
          git tag \${{ github.event.inputs.tag }}
`),
    ignores: f(WF, `on:
  workflow_dispatch:
    inputs:
      tag:
        required: true
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - env:
          TAG: \${{ github.event.inputs.tag }}
        run: git tag "$TAG"
`),
  },
  {
    ruleIds: [29954], name: 'CIG-12 Terraform plaintext secret',
    detects: f('infra/ssm.tf', `resource "aws_ssm_parameter" "db" {
  name  = "/prod/db_password"
  type  = "SecureString"
  value = "Sup3rS3cretPassw0rd!"
}
`),
    ignores: f('infra/ssm.tf', `resource "aws_ssm_parameter" "db" {
  name  = "/prod/db_password"
  type  = "SecureString"
  value = random_password.db.result
}
resource "aws_ssm_parameter" "region" {
  name  = "/prod/region"
  type  = "String"
  value = "eu-central-1"
}
`),
  },
  {
    ruleIds: [29955], name: 'CIG-13 TLS verification disabled in an image',
    detects: f('Dockerfile', `FROM node:22-alpine
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
CMD ["node", "server.js"]
`),
    ignores: f('Dockerfile', `FROM node:22-alpine
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/internal-ca.pem
CMD ["node", "server.js"]
`),
  },
  {
    ruleIds: [29956], name: 'CIG-14 ADD remote file without checksum',
    detects: f('Dockerfile', `FROM alpine:3.20
ADD https://example.com/tool-1.2.0.tar.gz /tmp/
`),
    ignores: f('Dockerfile', `FROM alpine:3.20
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/tool-1.2.0.tar.gz /tmp/
`),
  },
  {
    ruleIds: [29958], name: 'CIG-16 override to a git source',
    detects: f('package.json', `{
  "name": "app",
  "dependencies": { "lodash": "4.17.21" },
  "overrides": { "lodash": "github:someone/lodash" }
}
`),
    ignores: f('package.json', `{
  "name": "app",
  "dependencies": { "lodash": "4.17.21" },
  "overrides": { "semver": "7.6.3" }
}
`),
  },
  {
    ruleIds: [29959], name: 'CIG-17 toJSON(secrets)',
    detects: f(WF, `on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$ALL" | base64
        env:
          ALL: \${{ toJSON(secrets) }}
`),
    ignores: f(WF, `on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`),
  },
  {
    ruleIds: [29960], name: 'CIG-18 RDS snapshot shared with all accounts',
    detects: f('infra/snap.tf', `resource "aws_db_snapshot" "nightly" {
  db_instance_identifier = aws_db_instance.main.identifier
  db_snapshot_identifier = "nightly"
  shared_accounts        = ["all"]
}
`),
    ignores: f('infra/snap.tf', `resource "aws_db_snapshot" "nightly" {
  db_instance_identifier = aws_db_instance.main.identifier
  db_snapshot_identifier = "nightly"
  shared_accounts        = ["123456789012"]
}
`),
  },
  {
    ruleIds: [29961], name: 'CIG-19 vercel.json open proxy rewrite',
    detects: f('vercel.json', `{
  "rewrites": [
    { "source": "/p/:host/:path*", "destination": "https://:host/:path*" }
  ]
}
`),
    ignores: f('vercel.json', `{
  "rewrites": [
    { "source": "/api/:path*", "destination": "https://api.example.com/:path*" }
  ]
}
`),
  },
  {
    ruleIds: [29962], name: 'CIG-20 workflow_run artifact into the workspace root',
    detects: f(WF, `on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          name: results
          path: .
`),
    ignores: f(WF, `on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: results
          path: \${{ runner.temp }}/results
`),
  },
  {
    ruleIds: [29963], name: 'CIG-21 CloudFront http-only origin',
    detects: f('infra/cdn.tf', `resource "aws_cloudfront_distribution" "site" {
  origin {
    domain_name = "origin.example.com"
    origin_id   = "app"
    custom_origin_config {
      origin_protocol_policy = "http-only"
    }
  }
}
`),
    ignores: f('infra/cdn.tf', `resource "aws_cloudfront_distribution" "site" {
  origin {
    domain_name = "origin.example.com"
    origin_id   = "app"
    custom_origin_config {
      origin_protocol_policy = "https-only"
    }
  }
}
`),
  },
  {
    ruleIds: [29964], name: 'CIG-22 .npmrc copied into the final image',
    detects: f('Dockerfile', `FROM node:22 AS builder
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
FROM node:22-slim
COPY --from=builder /root/.npmrc /root/.npmrc
COPY --from=builder /app/dist /app/dist
`),
    ignores: f('Dockerfile', `FROM node:22 AS builder
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
FROM node:22-slim
COPY --from=builder /app/dist /app/dist
`),
  },
  {
    ruleIds: [29965], name: 'CIG-23 Postgres behind a LoadBalancer',
    detects: f('k8s/db-svc.yaml', `apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  type: LoadBalancer
  ports:
    - port: 5432
`),
    ignores: f('k8s/db-svc.yaml', `apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  type: ClusterIP
  ports:
    - port: 5432
`),
  },
  {
    ruleIds: [29966], name: 'CIG-24 submodule over git://',
    detects: f('.gitmodules', `[submodule "lib"]
  path = lib
  url = git://example.com/lib.git
`),
    ignores: f('.gitmodules', `[submodule "lib"]
  path = lib
  url = https://github.com/acme/lib.git
`),
  },
  {
    ruleIds: [29967], name: 'CIG-25 GitHub OIDC trust for any repo',
    detects: f('infra/oidc.tf', `data "aws_iam_policy_document" "gha" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:*"]
    }
  }
}
`),
    ignores: f('infra/oidc.tf', `data "aws_iam_policy_document" "gha" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:acme/app:ref:refs/heads/main"]
    }
  }
}
`),
  },
  {
    ruleIds: [29968], name: 'CIG-26 final image with NODE_ENV=development',
    detects: f('Dockerfile', `FROM node:22 AS build
RUN npm ci && npm run build
FROM node:22-slim
ENV NODE_ENV=development
CMD ["node", "dist/server.js"]
`),
    ignores: f('Dockerfile', `FROM node:22 AS build
ENV NODE_ENV=development
RUN npm ci && npm run build
FROM node:22-slim
ENV NODE_ENV=production
CMD ["node", "dist/server.js"]
`),
  },
  {
    ruleIds: [29969], name: 'CIG-27 ACTIONS_STEP_DEBUG in the workflow',
    detects: f(WF, `on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
`),
    ignores: f(WF, `on: push
env:
  CI: true
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
`),
  },
  {
    ruleIds: [29970], name: 'CIG-28 compose shares the host IPC namespace',
    detects: f('docker-compose.yml', `services:
  app:
    image: app:1.0.0
    ipc: host
`),
    ignores: f('docker-compose.yml', `services:
  app:
    image: app:1.0.0
    init: true
`),
  },
  {
    ruleIds: [29972], name: 'CIG-30 npm registry over HTTP',
    detects: f('.npmrc', `registry=http://registry.internal.example.com/
`),
    ignores: f('.npmrc', `registry=https://registry.internal.example.com/
`),
  },
  {
    ruleIds: [29973], name: 'CIG-31 Redis published in a production compose file',
    detects: f('docker-compose.prod.yml', `services:
  redis:
    image: redis:7.4
    ports:
      - "6379:6379"
`),
    ignores: f('docker-compose.prod.yml', `services:
  redis:
    image: redis:7.4
    ports:
      - "127.0.0.1:6379:6379"
`),
  },
];
