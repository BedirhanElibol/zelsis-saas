import assert from 'node:assert/strict';
import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';
import { evaluateCloudNativeRules } from '../../../lib/rules/cloud-native-rules';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const multiStageDockerfile = `# syntax=docker/dockerfile:1
# Production build image
FROM node:20-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder /build/node_modules ./node_modules
CMD ["node", "server.js"]
`;

const evalRes = evaluateCloudNativeRules(
  { path: 'Dockerfile', content: multiStageDockerfile },
  multiStageDockerfile.split('\n'),
  multiStageDockerfile,
  { count: 1 }
);
const cloud04Finding = evalRes.findings.find((finding) => finding.ruleId === 7004);
assert.equal(cloud04Finding?.lineRange, 'L8', 'CLOUD-04 must report the last FROM line (L8), not line 1');
assert.equal(cloud04Finding?.snippet, 'FROM node:20-alpine AS runner');

export const CASES: RuleCase[] = [
  {
    ruleIds: [7004],
    name: 'CLOUD-04 multi-stage Dockerfile without USER reports on the final FROM stage vs Dockerfile with USER',
    detects: f('Dockerfile', multiStageDockerfile),
    ignores: f('Dockerfile', `${multiStageDockerfile}USER node\n`)
  }
];
