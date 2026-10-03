import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const wf = (content: string) => f('.github/workflows/ci.yml', content);

export const CASES: RuleCase[] = [
  // ---------------------------------------------------------------- LLM applications
  {
    ruleIds: [28201],
    name: 'AI-APP-01 OpenAI key read from a VITE_ env var in the frontend',
    detects: f('src/lib/ai.ts', `import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: import.meta.env.VITE_OPENAI_API_KEY,
});
`),
    ignores: f('src/lib/ai.ts', `export async function askAssistant(question: string) {
  const res = await fetch('/api/assistant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  });
  return res.json();
}
`)
  },
  {
    ruleIds: [28201],
    name: 'AI-APP-01 NEXT_PUBLIC_ Anthropic key in a client component',
    detects: f('components/chat-box.tsx', `'use client';
import { useState } from 'react';

const ANTHROPIC_KEY = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY;

export function ChatBox() {
  const [reply, setReply] = useState('');
  async function send(text: string) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': ANTHROPIC_KEY!, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 512, messages: [{ role: 'user', content: text }] }),
    });
    setReply((await res.json()).content[0].text);
  }
  return <button onClick={() => send('hi')}>{reply}</button>;
}
`),
    ignores: f('components/chat-box.tsx', `'use client';
import { useState } from 'react';

export function ChatBox() {
  const [reply, setReply] = useState('');
  async function send(text: string) {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    setReply((await res.json()).reply);
  }
  return <button onClick={() => send('hi')}>{reply}</button>;
}
`)
  },
  {
    ruleIds: [28202],
    name: 'AI-APP-02 generateText output passed to eval',
    detects: f('app/api/calc/route.ts', `import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';

export async function POST(req: Request) {
  const { question } = await req.json();
  const { text } = await generateText({
    model: openai('gpt-4o-mini'),
    prompt: \`Write a single JavaScript expression that answers: \${question}\`,
  });
  const expression = text.trim();
  const result = eval(expression);
  return Response.json({ result });
}
`),
    ignores: f('app/api/calc/route.ts', `import { generateObject } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

const Calc = z.object({ op: z.enum(['add', 'sub', 'mul', 'div']), a: z.number(), b: z.number() });
const OPS = { add: (a: number, b: number) => a + b, sub: (a: number, b: number) => a - b, mul: (a: number, b: number) => a * b, div: (a: number, b: number) => a / b };

export async function POST(req: Request) {
  const { question } = await req.json();
  const { object } = await generateObject({ model: openai('gpt-4o-mini'), schema: Calc, prompt: question });
  return Response.json({ result: OPS[object.op](object.a, object.b) });
}
`)
  },
  {
    ruleIds: [28202],
    name: 'AI-APP-02 chat completion content run with os.system (Python)',
    detects: f('app/services/devops_bot.py', `import os
from openai import OpenAI

client = OpenAI()

def run_task(request: str) -> None:
    response = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=200,
        messages=[{"role": "user", "content": f"Give one bash command to: {request}"}],
    )
    command = response.choices[0].message.content.strip()
    os.system(command)
`),
    ignores: f('app/services/devops_bot.py', `import subprocess
from openai import OpenAI

client = OpenAI()
ACTIONS = {"restart": ["systemctl", "restart", "web"], "status": ["systemctl", "status", "web"]}

def run_task(request: str) -> None:
    response = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=5,
        messages=[{"role": "user", "content": f"Reply with restart or status for: {request}"}],
    )
    action = response.choices[0].message.content.strip()
    if action in ACTIONS:
        subprocess.run(ACTIONS[action], check=True)
`)
  },
  {
    ruleIds: [28203],
    name: 'AI-APP-03 text-to-SQL output executed with $queryRawUnsafe',
    detects: f('app/api/insights/route.ts', `import OpenAI from 'openai';
import { prisma } from '@/lib/prisma';

const openai = new OpenAI();

export async function POST(req: Request) {
  const { question } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 300,
    messages: [{ role: 'system', content: 'Translate the question into PostgreSQL.' }, { role: 'user', content: question }],
  });
  const sql = completion.choices[0].message.content ?? '';
  const rows = await prisma.$queryRawUnsafe(sql);
  return Response.json({ rows });
}
`),
    ignores: f('app/api/insights/route.ts', `import OpenAI from 'openai';
import { prisma } from '@/lib/prisma';

const openai = new OpenAI();

export async function POST(req: Request) {
  const { question } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 20,
    messages: [{ role: 'system', content: 'Reply with a metric name: signups or revenue.' }, { role: 'user', content: question }],
  });
  const metric = completion.choices[0].message.content ?? '';
  const rows = metric === 'revenue'
    ? await prisma.invoice.aggregate({ _sum: { amount: true } })
    : await prisma.user.count();
  return Response.json({ rows });
}
`)
  },
  {
    ruleIds: [28204],
    name: 'AI-APP-04 AI SDK tool runs a model-provided shell command',
    detects: f('lib/agent/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
import { execSync } from 'node:child_process';

export const runCommand = tool({
  description: 'Run a shell command in the project directory',
  inputSchema: z.object({ command: z.string() }),
  execute: async ({ command }) => {
    const output = execSync(command, { cwd: process.cwd() }).toString();
    return { output };
  },
});
`),
    ignores: f('lib/agent/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
import { execFileSync } from 'node:child_process';

export const runScript = tool({
  description: 'Run one of the project scripts',
  inputSchema: z.object({ script: z.enum(['lint', 'test', 'build']) }),
  execute: async ({ script }) => {
    const output = execFileSync('npm', ['run', script], { cwd: process.cwd() }).toString();
    return { output };
  },
});
`)
  },
  {
    ruleIds: [28204],
    name: 'AI-APP-04 FastMCP tool runs subprocess with shell=True',
    detects: f('server/mcp_server.py', `import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def run(cmd: str) -> str:
    """Run a command on the build host."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
`),
    ignores: f('server/mcp_server.py', `import subprocess
from typing import Literal
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")

@mcp.tool()
def run(task: Literal["test", "lint"]) -> str:
    """Run a predefined task on the build host."""
    return subprocess.run(["make", task], capture_output=True, text=True).stdout
`)
  },
  {
    ruleIds: [28205],
    name: 'AI-APP-05 MCP server reads any path the model asks for',
    detects: f('src/server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { readFile } from 'node:fs/promises';

const server = new McpServer({ name: 'docs', version: '1.0.0' });

server.tool(
  'read_doc',
  { path: z.string() },
  async ({ path }) => {
    const text = await readFile(path, 'utf8');
    return { content: [{ type: 'text', text }] };
  }
);
`),
    ignores: f('src/server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const DOCS_ROOT = path.resolve('docs');
const server = new McpServer({ name: 'docs', version: '1.0.0' });

server.tool(
  'read_doc',
  { file: z.string() },
  async ({ file }) => {
    const target = path.resolve(DOCS_ROOT, file);
    if (!target.startsWith(DOCS_ROOT + path.sep)) throw new Error('outside docs');
    const text = await readFile(target, 'utf8');
    return { content: [{ type: 'text', text }] };
  }
);
`)
  },
  {
    ruleIds: [28206],
    name: 'AI-APP-06 dangerouslyAllowBrowser with a build-time key (React Native / Vite)',
    detects: f('src/services/assistant.ts', `import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.EXPO_PUBLIC_AI_KEY,
  dangerouslyAllowBrowser: true,
});

export async function ask(prompt: string) {
  const res = await client.responses.create({ model: 'gpt-4o-mini', input: prompt, max_output_tokens: 300 });
  return res.output_text;
}
`),
    ignores: f('src/services/assistant.ts', `import OpenAI from 'openai';

export function createClient(userProvidedKey: string) {
  return new OpenAI({
    apiKey: userProvidedKey,
    dangerouslyAllowBrowser: true,
  });
}
`)
  },
  {
    ruleIds: [28207],
    name: 'AI-APP-07 LangChain pandas agent with allow_dangerous_code',
    detects: f('app/analytics/agent.py', `import pandas as pd
from langchain_openai import ChatOpenAI
from langchain_experimental.agents import create_pandas_dataframe_agent

def answer(question: str, csv_path: str) -> str:
    df = pd.read_csv(csv_path)
    agent = create_pandas_dataframe_agent(ChatOpenAI(model="gpt-4o"), df, allow_dangerous_code=True)
    return agent.invoke(question)["output"]
`),
    ignores: f('app/analytics/agent.py', `import pandas as pd
from langchain_openai import ChatOpenAI

def answer(question: str, csv_path: str) -> str:
    df = pd.read_csv(csv_path)
    summary = df.describe().to_string()
    llm = ChatOpenAI(model="gpt-4o")
    return llm.invoke(f"Using these statistics:\\n{summary}\\nAnswer: {question}").content
`)
  },

  // ---------------------------------------------------------------- GitHub Actions
  {
    ruleIds: [28251],
    name: 'GHA-01 pull_request_target checks out the fork head and runs npm',
    detects: wf(`name: Preview
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
          repository: \${{ github.event.pull_request.head.repo.full_name }}
      - run: npm ci && npm run build
      - run: npx vercel deploy --token \${{ secrets.VERCEL_TOKEN }}
`),
    ignores: wf(`name: Preview
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
      - run: npm ci && npm run build
`)
  },
  {
    ruleIds: [28252],
    name: 'GHA-02 workflow_run checks out the triggering head and builds it',
    detects: wf(`name: Coverage comment
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
      - run: npm ci && npm run coverage
      - run: gh pr comment --body-file coverage.md
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`),
    ignores: wf(`name: Coverage comment
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  report:
    runs-on: ubuntu-latest
    if: github.event.workflow_run.event == 'push'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
      - run: npm ci && npm run coverage
`)
  },
  {
    ruleIds: [28253],
    name: 'GHA-03 workflow_run head_branch interpolated into a shell script',
    detects: wf(`name: Deploy preview
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Announce
        run: |
          echo "Deploying branch \${{ github.event.workflow_run.head_branch }}"
          ./scripts/notify.sh
`),
    ignores: wf(`name: Deploy preview
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Announce
        env:
          HEAD_BRANCH: \${{ github.event.workflow_run.head_branch }}
        run: |
          echo "Deploying branch $HEAD_BRANCH"
          ./scripts/notify.sh
`)
  },
  {
    ruleIds: [28254],
    name: 'GHA-04 /test comment checks out the PR without checking the commenter',
    detects: wf(`name: E2E on comment
on:
  issue_comment:
    types: [created]

jobs:
  e2e:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/\${{ github.event.issue.number }}/head
      - run: npm ci && npm run test:e2e
        env:
          DATABASE_URL: \${{ secrets.STAGING_DATABASE_URL }}
`),
    ignores: wf(`name: E2E on comment
on:
  issue_comment:
    types: [created]

jobs:
  e2e:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/test') && contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/\${{ github.event.issue.number }}/head
      - run: npm ci && npm run test:e2e
        env:
          DATABASE_URL: \${{ secrets.STAGING_DATABASE_URL }}
`)
  },
  {
    ruleIds: [28255],
    name: 'GHA-05 artifact file contents appended to GITHUB_ENV in workflow_run',
    detects: wf(`name: Label PR
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: pr
          run-id: \${{ github.event.workflow_run.id }}
          github-token: \${{ secrets.GITHUB_TOKEN }}
      - run: echo "PR_NUMBER=$(cat pr/number)" >> $GITHUB_ENV
      - run: gh pr edit "$PR_NUMBER" --add-label checked
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`),
    ignores: wf(`name: Label PR
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: pr
          run-id: \${{ github.event.workflow_run.id }}
          github-token: \${{ secrets.GITHUB_TOKEN }}
      - id: pr
        run: |
          number=$(tr -cd '0-9' < pr/number)
          echo "number=$number" >> "$GITHUB_OUTPUT"
      - run: gh pr edit "\${{ steps.pr.outputs.number }}" --add-label checked
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`)
  },
  {
    ruleIds: [28256],
    name: 'GHA-06 ACTIONS_ALLOW_UNSECURE_COMMANDS enabled',
    detects: wf(`name: CI
on: [push]

env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "::set-env name=NODE_ENV::production"
      - run: npm ci && npm run build
`),
    ignores: wf(`name: CI
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "NODE_ENV=production" >> "$GITHUB_ENV"
      - run: npm ci && npm run build
`)
  },
  {
    ruleIds: [28257],
    name: 'GHA-07 whole workspace uploaded with hidden files after checkout',
    detects: wf(`name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: site
          path: .
          include-hidden-files: true
`),
    ignores: wf(`name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: site
          path: dist/
`)
  },
  {
    ruleIds: [28258],
    name: 'GHA-08 Dependabot auto-merge gated on github.actor',
    detects: wf(`name: Dependabot auto-merge
on: pull_request_target

permissions:
  contents: write
  pull-requests: write

jobs:
  automerge:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: \${{ github.event.pull_request.html_url }}
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`),
    ignores: wf(`name: Dependabot auto-merge
on: pull_request_target

permissions:
  contents: write
  pull-requests: write

jobs:
  automerge:
    runs-on: ubuntu-latest
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: \${{ github.event.pull_request.html_url }}
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`)
  },
];
