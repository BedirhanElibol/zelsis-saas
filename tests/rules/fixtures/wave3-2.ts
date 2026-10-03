import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/** package.json with the given dependency lines (and optional extra scripts). */
const pkg = (deps: string[], scripts: string[] = ['"dev": "next dev"', '"build": "next build"']): string => `{
  "name": "acme-dashboard",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    ${scripts.join(',\n    ')}
  },
  "dependencies": {
    ${deps.join(',\n    ')}
  }
}
`;

const BASE_DEPS = ['"next": "15.1.0"', '"react": "19.0.0"', '"react-dom": "19.0.0"'];

const deployment = (tolerations: string): string => `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          ports:
            - containerPort: 8080
      tolerations:
${tolerations}
`;

/**
 * Wave 3-2: supply-chain, IaC, GraphQL, ASVS, LLM-cost, WAF, container and SCA rules that were narrowed or
 * downgraded and are proven here. Every `ignores` is the idiomatic fix of the same code.
 */
export const CASES: RuleCase[] = [
  {
    ruleIds: [7301],
    name: 'SUPPLY-01: app dependency pinned to "*"',
    detects: f('package.json', pkg([...BASE_DEPS, '"zod": "*"'])),
    ignores: f('package.json', pkg([...BASE_DEPS, '"zod": "^3.23.8"'])),
  },
  {
    ruleIds: [7313],
    name: 'SUPPLY-13: discontinued crypto-js dependency',
    detects: f('package.json', pkg([...BASE_DEPS, '"crypto-js": "^4.2.0"'])),
    ignores: f('package.json', pkg(BASE_DEPS)),
  },
  {
    ruleIds: [7320],
    name: 'SUPPLY-20: left-pad dependency instead of String.prototype.padStart',
    detects: f('package.json', pkg([...BASE_DEPS, '"left-pad": "^1.3.0"'])),
    ignores: f('package.json', pkg(BASE_DEPS)),
  },
  {
    ruleIds: [7349],
    name: 'SUPPLY-49: build script making the output world-writable',
    detects: f('package.json', pkg(BASE_DEPS, ['"build": "tsc -p tsconfig.build.json"', '"postbuild": "chmod -R 777 dist"'])),
    ignores: f('package.json', pkg(BASE_DEPS, ['"build": "tsc -p tsconfig.build.json"', '"postbuild": "chmod -R 755 dist"'])),
  },
  {
    ruleIds: [7332],
    name: 'SUPPLY-32: Gradle resolving Maven Central over plain HTTP',
    detects: f('build.gradle', `plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.4'
}

repositories {
    maven { url "http://repo.maven.apache.org/maven2" }
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
`),
    ignores: f('build.gradle', `plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.4'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
`),
  },
  {
    ruleIds: [7334],
    name: 'SUPPLY-34: compiler toolchain installed in the final runtime stage',
    detects: f('Dockerfile', `FROM node:20-alpine AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat python3 make g++
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN apk add --no-cache gcc g++ make
COPY --from=deps /app/node_modules ./node_modules
COPY . .
CMD ["node", "server.js"]
`),
    ignores: f('Dockerfile', `FROM node:20-alpine AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat python3 make g++
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY . .
CMD ["node", "server.js"]
`),
  },
  {
    ruleIds: [8349],
    name: 'IAC-49: Deployment toleration without key tolerates every taint',
    detects: f('k8s/api-deployment.yaml', deployment(`        - operator: Exists`)),
    ignores: f('k8s/api-deployment.yaml', deployment(`        - key: dedicated
          operator: Exists
          effect: NoSchedule`)),
  },
  {
    ruleIds: [8507],
    name: 'GQL-07: Apollo playground enabled unconditionally',
    detects: f('src/graphql/server.ts', `import { ApolloServer } from 'apollo-server-express';
import { typeDefs } from './schema';
import { resolvers } from './resolvers';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  playground: true,
});
`),
    ignores: f('src/graphql/server.ts', `import { ApolloServer } from 'apollo-server-express';
import { typeDefs } from './schema';
import { resolvers } from './resolvers';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  playground: process.env.NODE_ENV !== 'production',
});
`),
  },
  {
    ruleIds: [13805],
    name: 'ASVS-05: bcrypt password hash with cost 8',
    detects: f('lib/auth/password.ts', `import bcrypt from 'bcryptjs';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 8);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
`),
    ignores: f('lib/auth/password.ts', `import bcrypt from 'bcryptjs';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
`),
  },
  {
    ruleIds: [8073],
    name: 'LLM-COST-03: one embeddings request per chunk',
    detects: f('lib/ai/embed.ts', `import OpenAI from 'openai';

const openai = new OpenAI();

export async function embedChunks(chunks: string[]): Promise<number[][]> {
  const vectors: number[][] = [];
  for (const chunk of chunks) {
    const res = await openai.embeddings.create({ model: 'text-embedding-3-small', input: chunk });
    vectors.push(res.data[0].embedding);
  }
  return vectors;
}
`),
    ignores: f('lib/ai/embed.ts', `import OpenAI from 'openai';

const openai = new OpenAI();

export async function embedChunks(chunks: string[]): Promise<number[][]> {
  const res = await openai.embeddings.create({ model: 'text-embedding-3-small', input: chunks });
  return res.data.map((d) => d.embedding);
}
`),
  },
  {
    ruleIds: [10405],
    name: 'WAF-05: JSON body limit raised to 100 MB',
    detects: f('server/app.ts', `import express from 'express';
import { router } from './routes';

export const app = express();
app.use(express.json({ limit: '100mb' }));
app.use('/api', router);
`),
    ignores: f('server/app.ts', `import express from 'express';
import { router } from './routes';

export const app = express();
app.use(express.json({ limit: '1mb' }));
app.use('/api', router);
`),
  },
  {
    ruleIds: [12205],
    name: 'CONTAINER-05: host Docker socket mounted into the app container',
    detects: f('docker-compose.yml', `services:
  app:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./uploads:/app/uploads
`),
    ignores: f('docker-compose.yml', `services:
  app:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - ./uploads:/app/uploads
`),
  },
  {
    ruleIds: [27211],
    name: 'SCA: axios pinned to a release with a known SSRF CVE',
    detects: f('package.json', pkg([...BASE_DEPS, '"axios": "1.6.0"'])),
    ignores: f('package.json', pkg([...BASE_DEPS, '"axios": "1.7.4"'])),
  },
];
