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
  }
];
