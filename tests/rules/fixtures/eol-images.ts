import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [31101], name: 'EOL-01 Node 14 base image vs a supported Node release',
    detects: f('Dockerfile', 'FROM node:14-alpine\nWORKDIR /app\nCMD ["node", "server.js"]\n'),
    ignores: f('Dockerfile', 'FROM node:24-alpine\nWORKDIR /app\nCMD ["node", "server.js"]\n'),
  },
  {
    ruleIds: [31101], name: 'EOL-01 Debian buster under a current runtime vs bookworm',
    detects: f('api/Dockerfile', 'FROM python:3.13-slim-buster AS base\nRUN pip install -r requirements.txt\n'),
    ignores: f('api/Dockerfile', 'FROM python:3.13-slim-bookworm AS base\nRUN pip install -r requirements.txt\n'),
  },
  {
    ruleIds: [31101], name: 'EOL-01 Ubuntu bionic codename vs an image tag held in a build argument',
    detects: f('docker/Dockerfile.prod', 'FROM ubuntu:bionic\nRUN apt-get update\n'),
    ignores: f('docker/Dockerfile.prod', 'ARG BASE=ubuntu:24.04\nFROM ${BASE}\nRUN apt-get update\n'),
  },
];
