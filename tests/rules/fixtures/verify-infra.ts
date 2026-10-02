import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

/**
 * Infra / IaC / LLM-app rules: realistic vulnerable config next to the idiomatic fixed version.
 * Terraform, Kubernetes, Docker Compose, Dockerfile, GitHub Actions and Next.js AI chat code.
 */
const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// ---------------------------------------------------------------- Terraform: security groups
const sg = (sshCidr: string, dbCidr: string, rdpCidr: string) => `
resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${sshCidr}"]
  }

  ingress {
    description = "RDP for the windows build box"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["${rdpCidr}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "postgres" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["${dbCidr}"]
  security_group_id = aws_security_group.db.id
}
`;
const sgOpen = sg('0.0.0.0/0', '0.0.0.0/0', '0.0.0.0/0');
const sgFixed = sg('10.0.0.0/16', '10.0.0.0/16', '10.20.0.0/24');

// ---------------------------------------------------------------- Terraform: IAM / KMS / S3 policies
const iamAdmin = `
resource "aws_iam_policy" "deployer" {
  name = "deployer"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
`;
const iamScoped = `
resource "aws_iam_policy" "deployer" {
  name = "deployer"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "*"
    }, {
      Effect   = "Allow"
      Action   = ["cloudfront:CreateInvalidation"]
      Resource = aws_cloudfront_distribution.site.arn
    }]
  })
}
`;
const iamDoc = (actions: string) => `
data "aws_iam_policy_document" "ci" {
  statement {
    effect    = "Allow"
    actions   = [${actions}]
    resources = ["*"]
  }
}
`;

const kmsKey = (principal: string, condition: string) => `
resource "aws_kms_key" "uploads" {
  description = "uploads bucket key"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowUse",
      "Effect": "Allow",
      "Principal": ${principal},
      "Action": "kms:*",
      "Resource": "*"${condition}
    }
  ]
}
POLICY
}
`;

const bucketPolicyPublic = `
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject"]
      Resource  = "\${aws_s3_bucket.uploads.arn}/*"
    }]
  })
}
`;
const bucketPolicyOac = `
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "\${aws_s3_bucket.uploads.arn}/*"
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn } }
    }, {
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.uploads.arn, "\${aws_s3_bucket.uploads.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
`;

// ---------------------------------------------------------------- Terraform: data stores, edge, compute
const rds = (publicAccess: string, password: string) => `
resource "aws_db_instance" "main" {
  identifier          = "app-prod"
  engine              = "postgres"
  engine_version      = "16.3"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "app"
  password            = ${password}
  publicly_accessible = ${publicAccess}
  storage_encrypted   = true
  skip_final_snapshot = false
}
`;
const hardcodedPw = ['"Sup3r', 'Secret', '2024!"'].join('');

const cloudfront = (minTls: string) => `
resource "aws_cloudfront_distribution" "site" {
  enabled = true
  aliases = ["app.example.com"]
  web_acl_id = aws_wafv2_web_acl.edge.arn

  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.app.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "${minTls}"
  }
}
`;

const listener = (http: string) => `
resource "aws_lb" "web" {
  name               = "web"
  load_balancer_type = "application"
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"
${http}
}
`;
const httpForward = `
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }`;
const httpRedirect = `
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }`;

const ec2 = (tokens: string) => `
resource "aws_instance" "worker" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.small"
  iam_instance_profile   = aws_iam_instance_profile.worker.name
  vpc_security_group_ids = [aws_security_group.worker.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "${tokens}"
  }
}
`;

const awsKey = ['AKIA', 'Q3EGRZ7J', 'W5XYHB2N'].join('');
const providerHardcoded = `
provider "aws" {
  region     = "us-east-1"
  access_key = "${awsKey}"
  secret_key = var.aws_secret_key
}
`;
const providerProfile = `
provider "aws" {
  region  = "us-east-1"
  profile = "acme-prod"
}
`;

// ---------------------------------------------------------------- Kubernetes manifests
const deployment = (securityContext: string, podExtra = '', volumes = '') => `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:${podExtra}
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          ports:
            - containerPort: 3000
          securityContext:
${securityContext}${volumes}
`;
const hardenedCtx = `            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]`;

// ---------------------------------------------------------------- GitHub Actions / CDK / CFN / LLM app helpers
const prTarget = (ref: string) => `name: Preview
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: write
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${ref}
      - run: npm ci && npm run build
        env:
          VERCEL_TOKEN: \${{ secrets.VERCEL_TOKEN }}
`;

const cdkStack = (body: string) => `import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import { Construct } from 'constructs';

export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);
    const { fn, table, bucket, dbSg, appSg } = props;
${body}
  }
}
`;

const cfnDistribution = (policy: string, tls: string) => `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SiteDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Aliases: [app.example.com]
        DefaultCacheBehavior:
          TargetOriginId: site
          ViewerProtocolPolicy: ${policy}
          CachePolicyId: 658327ea-f89d-4fab-a63d-7e88639e58f6
        ViewerCertificate:
          AcmCertificateArn: !Ref Certificate
          SslSupportMethod: sni-only
          MinimumProtocolVersion: ${tls}
`;

const chatPanel = (render: string) => `'use client';
import { useChat } from '@ai-sdk/react';
import { marked } from 'marked';
import ReactMarkdown from 'react-markdown';

export function ChatPanel() {
  const { messages, input, handleInputChange, handleSubmit } = useChat({ api: '/api/chat' });
  return (
    <div>
      {messages.map((message) => (
        <div key={message.id}>
          ${render}
        </div>
      ))}
      <form onSubmit={handleSubmit}>
        <input value={input} onChange={handleInputChange} />
      </form>
    </div>
  );
}
`;

// ---------------------------------------------------------------- MEDIUM hardening helpers
const tfBackend = (extra: string) => `
terraform {
  required_version = ">= 1.10"
  backend "s3" {
    bucket = "acme-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
${extra}
  }
}
`;
const cloudtrail = (multiRegion: string) => `
resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = ${multiRegion}
  enable_log_file_validation    = true
}
`;
const lambdaUrl = (auth: string) => `
resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "${auth}"
}
`;
const redis = (transit: string, auth: string) => `
resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id       = "sessions"
  description                = "session store"
  engine                     = "redis"
  node_type                  = "cache.t4g.small"
  num_cache_clusters         = 2
  at_rest_encryption_enabled = true
  transit_encryption_enabled = ${transit}
${auth}
}
`;
const ebs = (extra: string) => `
resource "aws_ebs_volume" "uploads" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
${extra}
}
`;
const versioning = (status: string) => `
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "${status}"
  }
}
`;
const rdsOps = (retention: string, protection: string) => `
resource "aws_db_instance" "main" {
  identifier              = "app-prod"
  engine                  = "postgres"
  instance_class          = "db.t4g.medium"
  allocated_storage       = 50
  username                = "app"
  password                = random_password.db.result
  storage_encrypted       = true
  backup_retention_period = ${retention}
  deletion_protection     = ${protection}
}
`;
const opensearch = (n2n: string) => `
resource "aws_opensearch_domain" "logs" {
  domain_name    = "app-logs"
  engine_version = "OpenSearch_2.13"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = ${n2n}
  }
}
`;
const eks = (cidrs: string) => `
resource "aws_eks_cluster" "main" {
  name     = "prod"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_public_access  = true
    endpoint_private_access = true
${cidrs}
  }
}
`;
const lambdaRuntime = (runtime: string) => `
resource "aws_lambda_function" "thumbnails" {
  function_name = "thumbnails"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "${runtime}"
  filename      = "dist/thumbnails.zip"
}
`;
const pgParams = (forceSsl: string) => `
resource "aws_db_parameter_group" "pg16" {
  name   = "app-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "${forceSsl}"
  }
}
`;
const ingress = (annotation: string) => `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
${annotation}
spec:
  ingressClassName: nginx
  tls:
    - hosts: [app.example.com]
      secretName: web-tls
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
`;
const torchLoad = (call: string) => `import torch

from app.ml.model import SentimentNet


def load_classifier(checkpoint_path: str) -> SentimentNet:
    model = SentimentNet()
    state = ${call}
    model.load_state_dict(state)
    model.eval()
    return model
`;
const chatRoute = (modelExpr: string, guard: string) => `import { Router } from 'express';
import OpenAI from 'openai';

const openai = new OpenAI();
export const chatRouter = Router();

chatRouter.post('/chat', requireUser, async (req, res) => {
${guard}  const completion = await openai.chat.completions.create({
    model: ${modelExpr},
    max_tokens: 800,
    messages: req.body.messages,
  });
  res.json(completion.choices[0].message);
});
`;
const signupRedirect = (redirect: string) => `'use client';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

export function useSignup() {
  const router = useRouter();
  return async (email: string, password: string) => {
    const supabase = createClient();
    const { error } = await supabase.auth.signUp({ email, password });
    if (error) return error.message;
    sessionStorage.setItem('pendingEmail', email);
    ${redirect}
  };
}
`;
const posthogInit = (mask: string) => `'use client';
import posthog from 'posthog-js';

export function initAnalytics() {
  posthog.init(process.env.NEXT_PUBLIC_POSTHOG_KEY!, {
    api_host: 'https://eu.i.posthog.com',
    person_profiles: 'identified_only',
    session_recording: {
      maskAllInputs: ${mask},
    },
  });
}
`;
const releaseWorkflow = (step: string) => `name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
${step}
      - run: npm publish
`;

export const CASES: RuleCase[] = [
  // ------------------------------------------------------------ security groups
  {
    ruleIds: [8301, 8302, 8303, 11003, 7040],
    name: 'Terraform security group opens SSH, RDP and Postgres to 0.0.0.0/0',
    detects: f('infra/network.tf', sgOpen),
    ignores: f('infra/network.tf', sgFixed)
  },
  {
    ruleIds: [8301, 11003, 7040],
    name: 'Terraform aws_vpc_security_group_ingress_rule opens SSH to the internet',
    detects: f('infra/bastion.tf', `
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
`),
    ignores: f('infra/bastion.tf', `
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = var.office_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
`)
  },
  // ------------------------------------------------------------ IAM, KMS, S3
  {
    ruleIds: [8305],
    name: 'Terraform IAM policy grants Action "*" on Resource "*"',
    detects: f('infra/iam.tf', iamAdmin),
    ignores: f('infra/iam.tf', iamScoped)
  },
  {
    ruleIds: [8305],
    name: 'aws_iam_policy_document statement with actions ["*"] on resources ["*"]',
    detects: f('infra/ci-role.tf', iamDoc('"*"')),
    ignores: f('infra/ci-role.tf', iamDoc('"ecr:GetAuthorizationToken", "ecr:BatchGetImage"'))
  },
  {
    ruleIds: [8320],
    name: 'KMS key policy lets any AWS principal use the key',
    detects: f('infra/kms.tf', kmsKey('{ "AWS": "*" }', '')),
    ignores: f('infra/kms.tf', kmsKey('{ "AWS": "*" }', `,
      "Condition": { "StringEquals": { "kms:CallerAccount": "123456789012" } }`))
  },
  {
    ruleIds: [8324],
    name: 'S3 bucket policy allows everyone to read and write objects',
    detects: f('infra/storage.tf', bucketPolicyPublic),
    ignores: f('infra/storage.tf', bucketPolicyOac)
  },
  // ------------------------------------------------------------ data stores, edge, compute
  {
    ruleIds: [8310],
    name: 'RDS instance publicly accessible',
    detects: f('infra/database.tf', rds('true', 'var.db_password')),
    ignores: f('infra/database.tf', rds('false', 'var.db_password'))
  },
  {
    ruleIds: [8322],
    name: 'Terraform database password hardcoded in the resource',
    detects: f('infra/database.tf', rds('false', hardcodedPw)),
    ignores: f('infra/database.tf', rds('false', 'random_password.db.result'))
  },
  {
    ruleIds: [8335],
    name: 'CloudFront viewer certificate allows TLS 1.0',
    detects: f('infra/cdn.tf', cloudfront('TLSv1')),
    ignores: f('infra/cdn.tf', cloudfront('TLSv1.2_2021'))
  },
  {
    ruleIds: [8328],
    name: 'Public ALB serves the app over plain HTTP on port 80',
    detects: f('infra/alb.tf', listener(httpForward)),
    ignores: f('infra/alb.tf', listener(httpRedirect))
  },
  {
    ruleIds: [8348],
    name: 'EC2 instance keeps IMDSv1 enabled (http_tokens = "optional")',
    detects: f('infra/worker.tf', ec2('optional')),
    ignores: f('infra/worker.tf', ec2('required'))
  },
  {
    ruleIds: [11004],
    name: 'AWS access key hardcoded in the Terraform provider block',
    detects: f('infra/providers.tf', providerHardcoded),
    ignores: f('infra/providers.tf', providerProfile)
  },
  // ------------------------------------------------------------ Kubernetes
  {
    ruleIds: [8901, 7013, 12201],
    name: 'Kubernetes Deployment runs a privileged container',
    detects: f('k8s/api-deployment.yaml', deployment(`            privileged: true
            runAsUser: 0`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx))
  },
  {
    ruleIds: [8312],
    name: 'Kubernetes pod shares the host PID namespace',
    detects: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      hostPID: true`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      hostPID: false`))
  },
  {
    ruleIds: [8321, 12204],
    name: 'Kubernetes pod uses the host network namespace',
    detects: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      # hostNetwork: true was only needed for the old metrics agent
      dnsPolicy: ClusterFirst`))
  },
  {
    ruleIds: [8329, 8909],
    name: 'Kubernetes container adds ALL Linux capabilities (block list style)',
    detects: f('k8s/api-deployment.yaml', deployment(`            capabilities:
              add:
                - ALL`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx))
  },
  {
    ruleIds: [8909],
    name: 'Kubernetes container adds SYS_ADMIN capability',
    detects: f('k8s/api-deployment.yaml', deployment(`            capabilities:
              add: ["NET_BIND_SERVICE", "SYS_ADMIN"]`)),
    ignores: f('k8s/api-deployment.yaml', deployment(`            capabilities:
              drop: ["ALL"]
              add: ["NET_BIND_SERVICE"]`))
  },
  {
    ruleIds: [8904],
    name: 'Kubernetes pod mounts the Docker socket from the host',
    detects: f('k8s/api-deployment.yaml', deployment(hardenedCtx, '', `
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
            type: Socket`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx, '', `
          volumeMounts:
            - name: cache
              mountPath: /tmp/cache
      volumes:
        - name: cache
          emptyDir: {}
        - name: node-logs
          hostPath:
            path: /var/log/app
            type: DirectoryOrCreate`))
  },
  // ------------------------------------------------------------ Docker Compose / Dockerfile
  {
    ruleIds: [8331],
    name: 'docker-compose service runs privileged',
    detects: f('docker-compose.yml', `services:
  web:
    build: .
    ports:
      - "3000:3000"
    privileged: true
    env_file: .env.production
  db:
    image: postgres:16
`),
    ignores: f('docker-compose.yml', `services:
  web:
    build: .
    ports:
      - "3000:3000"
    read_only: true
    cap_drop: [ALL]
    env_file: .env.production
  db:
    image: postgres:16
`)
  },
  {
    ruleIds: [12202],
    name: 'Dockerfile final stage switches back to root',
    detects: f('Dockerfile', `FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/.next ./.next
COPY --from=build /app/node_modules ./node_modules
USER node
RUN npm prune --omit=dev
USER root
EXPOSE 3000
CMD ["npm", "start"]
`),
    ignores: f('Dockerfile', `FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
USER root
RUN apk add --no-cache tini
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/node_modules ./node_modules
USER node
EXPOSE 3000
CMD ["npm", "start"]
`)
  },
  // ------------------------------------------------------------ GitHub Actions
  {
    ruleIds: [9504],
    name: 'GitHub workflow grants the token write-all permissions',
    detects: f('.github/workflows/ci.yml', `name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
`),
    ignores: f('.github/workflows/ci.yml', `name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
`)
  },
  {
    ruleIds: [9501],
    name: 'pull_request_target workflow checks out and builds the PR head',
    detects: f('.github/workflows/preview.yml', prTarget('${{ github.event.pull_request.head.sha }}')),
    ignores: f('.github/workflows/preview.yml', prTarget('${{ github.event.pull_request.base.sha }}'))
  },
  // ------------------------------------------------------------ CDK / CloudFormation
  {
    ruleIds: [7020],
    name: 'CDK PolicyStatement grants actions ["*"]',
    detects: f('infra/lib/api-stack.ts', cdkStack(`    fn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['*'],
      resources: [table.tableArn],
    }));`)),
    ignores: f('infra/lib/api-stack.ts', cdkStack(`    fn.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'],
      resources: [table.tableArn],
    }));`))
  },
  {
    ruleIds: [7040],
    name: 'CDK security group opens Postgres to any IPv4 address',
    detects: f('infra/lib/api-stack.ts', cdkStack(`    dbSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(5432), 'postgres');`)),
    ignores: f('infra/lib/api-stack.ts', cdkStack(`    dbSg.addIngressRule(ec2.Peer.securityGroupId(appSg.securityGroupId), ec2.Port.tcp(5432), 'postgres from app');`))
  },
  {
    ruleIds: [7026],
    name: 'CDK CloudFront distribution serves plain HTTP (ALLOW_ALL)',
    detects: f('infra/lib/web-stack.ts', cdkStack(`    new cloudfront.Distribution(this, 'Site', {
      defaultBehavior: {
        origin: new origins.S3Origin(bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.ALLOW_ALL,
      },
    });`)),
    ignores: f('infra/lib/web-stack.ts', cdkStack(`    new cloudfront.Distribution(this, 'Site', {
      defaultBehavior: {
        origin: new origins.S3Origin(bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
    });`))
  },
  {
    ruleIds: [7026, 7027],
    name: 'CloudFormation distribution allows HTTP and TLS 1.0',
    detects: f('infra/cloudfront.yml', cfnDistribution('allow-all', 'TLSv1')),
    ignores: f('infra/cloudfront.yml', cfnDistribution('redirect-to-https', 'TLSv1.2_2021'))
  },
  // ------------------------------------------------------------ LLM apps
  {
    ruleIds: [8004],
    name: 'Chat UI renders model output as raw HTML via marked()',
    detects: f('app/chat/chat-panel.tsx', chatPanel('<div className="prose" dangerouslySetInnerHTML={{ __html: marked(message.content) }} />')),
    ignores: f('app/chat/chat-panel.tsx', chatPanel('<ReactMarkdown className="prose">{message.content}</ReactMarkdown>'))
  },
  {
    ruleIds: [8017],
    name: 'OpenAI key read from a NEXT_PUBLIC_ env var in browser code',
    detects: f('lib/openai-client.ts', `import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});
`),
    ignores: f('lib/openai-client.ts', `import 'server-only';
import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});
`)
  },
  // ------------------------------------------------------------ MEDIUM hardening settings (Terraform)
  {
    ruleIds: [7030],
    name: 'Terraform output exposes the database password without sensitive = true',
    detects: f('infra/outputs.tf', `
output "db_endpoint" {
  value = aws_db_instance.main.address
}

output "db_password" {
  value = random_password.db.result
}
`),
    ignores: f('infra/outputs.tf', `
output "db_endpoint" {
  value = aws_db_instance.main.address
}

output "db_password" {
  value     = random_password.db.result
  sensitive = true
}
`)
  },
  {
    ruleIds: [7031, 11001],
    name: 'S3 state backend without encrypt = true',
    detects: f('infra/backend.tf', tfBackend('    use_lockfile = true')),
    ignores: f('infra/backend.tf', tfBackend('    use_lockfile = true\n    encrypt      = true'))
  },
  {
    ruleIds: [11002],
    name: 'S3 state backend without state locking',
    detects: f('infra/backend.tf', tfBackend('    encrypt = true')),
    ignores: f('infra/backend.tf', tfBackend('    encrypt      = true\n    use_lockfile = true'))
  },
  {
    ruleIds: [7036, 8307],
    name: 'CloudTrail trail limited to a single region',
    detects: f('infra/audit.tf', cloudtrail('false')),
    ignores: f('infra/audit.tf', cloudtrail('true'))
  },
  {
    ruleIds: [7037],
    name: 'ECR repository without scan on push',
    detects: f('infra/ecr.tf', `
resource "aws_ecr_repository" "api" {
  name                 = "acme/api"
  image_tag_mutability = "IMMUTABLE"
}
`),
    ignores: f('infra/ecr.tf', `
resource "aws_ecr_repository" "api" {
  name                 = "acme/api"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`)
  },
  {
    ruleIds: [7042],
    name: 'Lambda function URL with authorization_type NONE',
    detects: f('infra/lambda.tf', lambdaUrl('NONE')),
    ignores: f('infra/lambda.tf', lambdaUrl('AWS_IAM'))
  },
  {
    ruleIds: [7043, 8323],
    name: 'ElastiCache Redis with in-transit encryption disabled',
    detects: f('infra/redis.tf', redis('false', '  auth_token                 = var.redis_auth_token')),
    ignores: f('infra/redis.tf', redis('true', '  auth_token                 = var.redis_auth_token'))
  },
  {
    ruleIds: [7044],
    name: 'ElastiCache Redis without an auth token',
    detects: f('infra/redis.tf', redis('true', '')),
    ignores: f('infra/redis.tf', redis('true', '  auth_token                 = var.redis_auth_token'))
  },
  {
    ruleIds: [8304],
    name: 'EBS volume without encryption',
    detects: f('infra/volumes.tf', ebs('')),
    ignores: f('infra/volumes.tf', ebs('  encrypted         = true\n  kms_key_id        = aws_kms_key.ebs.arn'))
  },
  {
    ruleIds: [8306],
    name: 'S3 bucket versioning explicitly disabled',
    detects: f('infra/storage.tf', versioning('Disabled')),
    ignores: f('infra/storage.tf', versioning('Enabled'))
  },
  {
    ruleIds: [8309],
    name: 'RDS automated backups turned off',
    detects: f('infra/database.tf', rdsOps('0', 'true')),
    ignores: f('infra/database.tf', rdsOps('7', 'true'))
  },
  {
    ruleIds: [8332],
    name: 'RDS instance without deletion protection',
    detects: f('infra/database.tf', rdsOps('7', 'false')),
    ignores: f('infra/database.tf', rdsOps('7', 'true'))
  },
  {
    ruleIds: [8333],
    name: 'OpenSearch domain with node-to-node encryption disabled',
    detects: f('infra/search.tf', opensearch('false')),
    ignores: f('infra/search.tf', opensearch('true'))
  },
  {
    ruleIds: [8338],
    name: 'EKS API endpoint public to the whole internet',
    detects: f('infra/eks.tf', eks('')),
    ignores: f('infra/eks.tf', eks('    public_access_cidrs     = ["203.0.113.0/24"]'))
  },
  {
    ruleIds: [8342],
    name: 'Lambda on an end-of-life Node.js runtime',
    detects: f('infra/lambda.tf', lambdaRuntime('nodejs16.x')),
    ignores: f('infra/lambda.tf', lambdaRuntime('nodejs20.x'))
  },
  {
    ruleIds: [8344],
    name: 'RDS parameter group turns off rds.force_ssl',
    detects: f('infra/database.tf', pgParams('0')),
    ignores: f('infra/database.tf', pgParams('1'))
  },
  // ------------------------------------------------------------ MEDIUM hardening settings (Kubernetes)
  {
    ruleIds: [8345],
    name: 'ingress-nginx configuration-snippet annotation',
    detects: f('k8s/ingress.yaml', ingress(`    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";`)),
    ignores: f('k8s/ingress.yaml', ingress('    nginx.ingress.kubernetes.io/ssl-redirect: "true"'))
  },
  {
    ruleIds: [8902],
    name: 'Kubernetes container explicitly runs as UID 0',
    detects: f('k8s/api-deployment.yaml', deployment(`            runAsUser: 0
            allowPrivilegeEscalation: false`)),
    ignores: f('k8s/api-deployment.yaml', deployment(`            runAsUser: 10001
            runAsNonRoot: true
            allowPrivilegeEscalation: false`))
  },
  {
    ruleIds: [8905],
    name: 'Pod spec explicitly mounts the service account token',
    detects: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      serviceAccountName: api
      automountServiceAccountToken: true`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx, `
      serviceAccountName: api
      automountServiceAccountToken: false`))
  },
  {
    ruleIds: [8908, 12203],
    name: 'Kubernetes container with a writable root filesystem',
    detects: f('k8s/api-deployment.yaml', deployment(`            runAsNonRoot: true
            readOnlyRootFilesystem: false`)),
    ignores: f('k8s/api-deployment.yaml', deployment(hardenedCtx))
  },
  // ------------------------------------------------------------ MEDIUM / LOW app and CI settings
  {
    ruleIds: [8008],
    name: 'torch.load of a checkpoint without weights_only=True',
    detects: f('app/ml/classifier.py', torchLoad('torch.load(checkpoint_path, map_location="cpu")')),
    ignores: f('app/ml/classifier.py', torchLoad('torch.load(checkpoint_path, map_location="cpu", weights_only=True)'))
  },
  {
    ruleIds: [8056],
    name: 'Client picks the LLM model straight from the request body',
    detects: f('src/routes/chat.ts', chatRoute('req.body.model', '')),
    ignores: f('src/routes/chat.ts', chatRoute('model', `  const ALLOWED_MODELS = ['gpt-4o-mini', 'gpt-4o'];
  const model = ALLOWED_MODELS.includes(req.body.model) ? req.body.model : 'gpt-4o-mini';
`))
  },
  {
    ruleIds: [8215],
    name: 'Email address put into the URL query string',
    detects: f('app/(auth)/signup/signup-form.ts', signupRedirect('router.push(`/verify-email?email=${email}`);')),
    ignores: f('app/(auth)/signup/signup-form.ts', signupRedirect("router.push('/verify-email');"))
  },
  {
    ruleIds: [8225],
    name: 'Session replay records form inputs unmasked',
    detects: f('app/providers/posthog.ts', posthogInit('false')),
    ignores: f('app/providers/posthog.ts', posthogInit('true'))
  },
  {
    ruleIds: [9505],
    name: 'Workflow echoes a secret to the build log',
    detects: f('.github/workflows/release.yml', releaseWorkflow('      - run: echo "Publishing with token ${{ secrets.NPM_TOKEN }}"')),
    ignores: f('.github/workflows/release.yml', releaseWorkflow('      - run: echo "${{ secrets.NPM_TOKEN }}" | npm login --registry https://registry.npmjs.org --auth-type=legacy'))
  }
];
