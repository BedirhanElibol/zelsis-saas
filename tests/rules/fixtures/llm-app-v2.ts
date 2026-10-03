import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28301],
    name: 'LLM-V2-01 embedding model loaded with trust_remote_code and no pinned revision',
    detects: f('app/embeddings.py', `from sentence_transformers import SentenceTransformer

model = SentenceTransformer(
    "nomic-ai/nomic-embed-text-v1.5",
    trust_remote_code=True,
)


def embed(texts: list[str]) -> list[list[float]]:
    return model.encode(texts).tolist()
`),
    ignores: f('app/embeddings.py', `from sentence_transformers import SentenceTransformer

model = SentenceTransformer(
    "nomic-ai/nomic-embed-text-v1.5",
    trust_remote_code=True,
    revision="e5cf08aadaa33385f5990def41f7a23405aec398",
)


def embed(texts: list[str]) -> list[list[float]]:
    return model.encode(texts).tolist()
`)
  },
  {
    ruleIds: [28302],
    name: 'LLM-V2-02 LangChain requests toolkit with allow_dangerous_requests',
    detects: f('app/agent.py', `from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit
from langchain_community.utilities.requests import TextRequestsWrapper
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

toolkit = RequestsToolkit(
    requests_wrapper=TextRequestsWrapper(headers={}),
    allow_dangerous_requests=True,
)
agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), toolkit.get_tools())
`),
    ignores: f('app/agent.py', `import httpx
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI


@tool
def get_order_status(order_id: int) -> str:
    """Look up an order in the orders API."""
    return httpx.get(f"https://api.example.com/orders/{order_id}").text


agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), [get_order_status])
`)
  },
  {
    ruleIds: [28303],
    name: 'LLM-V2-03 PALChain answering user math questions',
    detects: f('app/math_agent.py', `from langchain_experimental.pal_chain import PALChain
from langchain_openai import OpenAI

llm = OpenAI(temperature=0)
pal = PALChain.from_math_prompt(llm, verbose=True)


def solve(question: str) -> str:
    return pal.run(question)
`),
    ignores: f('app/math_agent.py', `from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(temperature=0)
prompt = ChatPromptTemplate.from_template("Solve step by step: {question}")
chain = prompt | llm


def solve(question: str) -> str:
    return chain.invoke({"question": question}).content
`)
  },
  {
    ruleIds: [28304],
    name: 'LLM-V2-04 MCP proxy spawns stdio server from query string',
    detects: f('server/mcp-proxy.ts', `import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const app = express();

app.get('/connect', async (req, res) => {
  const transport = new StdioClientTransport({
    command: req.query.command as string,
    args: (req.query.args as string).split(' '),
  });
  const client = new Client({ name: 'proxy', version: '1.0.0' });
  await client.connect(transport);
  res.json(await client.listTools());
});
`),
    ignores: f('server/mcp-proxy.ts', `import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SERVERS } from './servers';

const app = express();

app.get('/connect', async (req, res) => {
  const server = SERVERS[String(req.query.server)];
  if (!server) return res.status(404).end();
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args,
  });
  const client = new Client({ name: 'proxy', version: '1.0.0' });
  await client.connect(transport);
  res.json(await client.listTools());
});
`)
  },
  {
    ruleIds: [28305],
    name: 'LLM-V2-05 MCP tool forwards the incoming bearer token to the upstream API',
    detects: f('src/mcp/server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

const server = new McpServer({ name: 'crm', version: '1.0.0' });

server.tool('list_contacts', { query: z.string() }, async ({ query }, extra) => {
  const res = await fetch(\`https://api.crm.example.com/contacts?q=\${encodeURIComponent(query)}\`, {
    headers: { Authorization: \`Bearer \${extra.authInfo?.token}\` },
  });
  return { content: [{ type: 'text', text: await res.text() }] };
});
`),
    ignores: f('src/mcp/server.ts', `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { getUpstreamToken } from './upstream-auth';

const server = new McpServer({ name: 'crm', version: '1.0.0' });

server.tool('list_contacts', { query: z.string() }, async ({ query }, extra) => {
  const upstreamToken = await getUpstreamToken(extra.authInfo?.clientId);
  const res = await fetch(\`https://api.crm.example.com/contacts?q=\${encodeURIComponent(query)}\`, {
    headers: { Authorization: \`Bearer \${upstreamToken}\` },
  });
  return { content: [{ type: 'text', text: await res.text() }] };
});
`)
  },
  {
    ruleIds: [28306],
    name: 'LLM-V2-06 FastMCP over HTTP bound to 0.0.0.0 without auth',
    detects: f('server/main.py', `from fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool
def list_reports() -> list[str]:
    return ["q1.pdf", "q2.pdf"]


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
`),
    ignores: f('server/main.py', `from fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool
def list_reports() -> list[str]:
    return ["q1.pdf", "q2.pdf"]


if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000)
`)
  },
  {
    ruleIds: [28306],
    name: 'LLM-V2-06 Streamable HTTP MCP server on Express listening on 0.0.0.0 without auth',
    detects: f('src/index.ts', `import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { registerTools } from './tools';

const app = express();
app.use(express.json());

app.post('/mcp', async (req, res) => {
  const server = new McpServer({ name: 'ops', version: '1.0.0' });
  registerTools(server);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, '0.0.0.0');
`),
    ignores: f('src/index.ts', `import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { registerTools } from './tools';
import { verifier } from './auth';

const app = express();
app.use(express.json());

app.post('/mcp', requireBearerAuth({ verifier }), async (req, res) => {
  const server = new McpServer({ name: 'ops', version: '1.0.0' });
  registerTools(server);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, '0.0.0.0');
`)
  },
  {
    ruleIds: [28307],
    name: 'LLM-V2-07 Vue chat renders assistant markdown with v-html',
    detects: f('src/components/ChatMessage.vue', `<template>
  <div class="message" :class="message.role">
    <div class="body" v-html="marked.parse(message.content)"></div>
  </div>
</template>

<script setup lang="ts">
import { marked } from 'marked';

defineProps<{ message: { role: 'user' | 'assistant'; content: string } }>();
</script>
`),
    ignores: f('src/components/ChatMessage.vue', `<template>
  <div class="message" :class="message.role">
    <div class="body" v-html="DOMPurify.sanitize(marked.parse(message.content))"></div>
  </div>
</template>

<script setup lang="ts">
import { marked } from 'marked';
import DOMPurify from 'dompurify';

defineProps<{ message: { role: 'user' | 'assistant'; content: string } }>();
</script>
`)
  },
  {
    ruleIds: [28307],
    name: 'LLM-V2-07 streamed completion chunks appended with innerHTML +=',
    detects: f('src/chat.ts', `export async function ask(question: string, output: HTMLElement) {
  const res = await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ question }) });
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = decoder.decode(value);
    output.innerHTML += chunk;
  }
}
`),
    ignores: f('src/chat.ts', `export async function ask(question: string, output: HTMLElement) {
  const res = await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ question }) });
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = decoder.decode(value);
    output.append(document.createTextNode(chunk));
  }
}
`)
  },
  {
    ruleIds: [28308],
    name: 'LLM-V2-08 react-markdown with rehype-raw for assistant messages',
    detects: f('components/assistant-message.tsx', `'use client';
import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import remarkGfm from 'remark-gfm';
import type { UIMessage } from 'ai';

export function AssistantMessage({ message }: { message: UIMessage }) {
  const text = message.parts.map((p) => (p.type === 'text' ? p.text : '')).join('');
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw]}>
      {text}
    </ReactMarkdown>
  );
}
`),
    ignores: f('components/assistant-message.tsx', `'use client';
import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize from 'rehype-sanitize';
import remarkGfm from 'remark-gfm';
import type { UIMessage } from 'ai';

export function AssistantMessage({ message }: { message: UIMessage }) {
  const text = message.parts.map((p) => (p.type === 'text' ? p.text : '')).join('');
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw, rehypeSanitize]}>
      {text}
    </ReactMarkdown>
  );
}
`)
  },
  {
    ruleIds: [28309],
    name: 'LLM-V2-09 AI SDK tool fetches any URL the model picks',
    detects: f('app/api/chat/route.ts', `import { openai } from '@ai-sdk/openai';
import { streamText, tool } from 'ai';
import { z } from 'zod';

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai('gpt-4o-mini'),
    messages,
    tools: {
      readPage: tool({
        description: 'Read a web page',
        inputSchema: z.object({ url: z.string().url() }),
        execute: async ({ url }) => {
          const res = await fetch(url);
          return (await res.text()).slice(0, 5000);
        },
      }),
    },
  });
  return result.toUIMessageStreamResponse();
}
`),
    ignores: f('app/api/chat/route.ts', `import { openai } from '@ai-sdk/openai';
import { streamText, tool } from 'ai';
import { z } from 'zod';

const ALLOWED_HOSTS = new Set(['docs.example.com', 'blog.example.com']);

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: openai('gpt-4o-mini'),
    messages,
    tools: {
      readPage: tool({
        description: 'Read a documentation page',
        inputSchema: z.object({ url: z.string().url() }),
        execute: async ({ url }) => {
          const target = new URL(url);
          if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) return 'Host not allowed';
          const res = await fetch(target, { redirect: 'error' });
          return (await res.text()).slice(0, 5000);
        },
      }),
    },
  });
  return result.toUIMessageStreamResponse();
}
`)
  },
  {
    ruleIds: [28309],
    name: 'LLM-V2-09 MCP python tool fetches a model-chosen URL',
    detects: f('server/web_tools.py', `import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool()
async def fetch_page(url: str) -> str:
    """Fetch a web page and return its text."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, follow_redirects=True)
        return resp.text[:5000]
`),
    ignores: f('server/web_tools.py', `import httpx
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")
ALLOWED_HOSTS = {"docs.python.org", "fastapi.tiangolo.com"}


@mcp.tool()
async def fetch_page(url: str) -> str:
    """Fetch a documentation page and return its text."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        return "host not allowed"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, follow_redirects=False)
        return resp.text[:5000]
`)
  },
  {
    ruleIds: [28310],
    name: 'LLM-V2-10 route passes the client-chosen model to OpenAI',
    detects: f('app/api/chat/route.ts', `import OpenAI from 'openai';

const openai = new OpenAI();

export async function POST(req: Request) {
  const { messages, model } = await req.json();
  const completion = await openai.chat.completions.create({
    model,
    messages,
  });
  return Response.json(completion.choices[0].message);
}
`),
    ignores: f('app/api/chat/route.ts', `import OpenAI from 'openai';

const openai = new OpenAI();
const ALLOWED_MODELS = ['gpt-4o-mini', 'gpt-4.1-mini'];

export async function POST(req: Request) {
  const { messages, model } = await req.json();
  if (!ALLOWED_MODELS.includes(model)) return new Response('Unsupported model', { status: 400 });
  const completion = await openai.chat.completions.create({
    model,
    messages,
  });
  return Response.json(completion.choices[0].message);
}
`)
  },
  {
    ruleIds: [28310],
    name: 'LLM-V2-10 FastAPI forwards a free-text model field',
    detects: f('app/routers/chat.py', `from fastapi import APIRouter
from openai import OpenAI
from pydantic import BaseModel

router = APIRouter()
client = OpenAI()


class ChatRequest(BaseModel):
    message: str
    model: str = "gpt-4o-mini"


@router.post("/chat")
def chat(req: ChatRequest):
    completion = client.chat.completions.create(
        model=req.model,
        messages=[{"role": "user", "content": req.message}],
    )
    return {"reply": completion.choices[0].message.content}
`),
    ignores: f('app/routers/chat.py', `from typing import Literal

from fastapi import APIRouter
from openai import OpenAI
from pydantic import BaseModel

router = APIRouter()
client = OpenAI()


class ChatRequest(BaseModel):
    message: str
    model: Literal["gpt-4o-mini", "gpt-4.1-mini"] = "gpt-4o-mini"


@router.post("/chat")
def chat(req: ChatRequest):
    completion = client.chat.completions.create(
        model=req.model,
        messages=[{"role": "user", "content": req.message}],
    )
    return {"reply": completion.choices[0].message.content}
`)
  },
  {
    ruleIds: [28311],
    name: 'LLM-V2-11 Pinecone namespace taken from the request body',
    detects: f('app/api/search/route.ts', `import { Pinecone } from '@pinecone-database/pinecone';
import { embed } from '@/lib/embed';

const pc = new Pinecone();
const index = pc.index('docs');

export async function POST(req: Request) {
  const { query, workspaceId } = await req.json();
  const vector = await embed(query);
  const results = await index.namespace(workspaceId).query({
    vector,
    topK: 5,
    includeMetadata: true,
  });
  return Response.json(results.matches);
}
`),
    ignores: f('app/api/search/route.ts', `import { Pinecone } from '@pinecone-database/pinecone';
import { embed } from '@/lib/embed';
import { requireUser } from '@/lib/auth';

const pc = new Pinecone();
const index = pc.index('docs');

export async function POST(req: Request) {
  const user = await requireUser();
  const { query } = await req.json();
  const vector = await embed(query);
  const results = await index.namespace(user.workspaceId).query({
    vector,
    topK: 5,
    includeMetadata: true,
  });
  return Response.json(results.matches);
}
`)
  },
  {
    ruleIds: [28311],
    name: 'LLM-V2-11 LangChain retriever filter tenant from the request model',
    detects: f('app/rag.py', `from fastapi import FastAPI
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from pydantic import BaseModel

app = FastAPI()
store = Chroma(collection_name="docs", embedding_function=OpenAIEmbeddings())


class AskRequest(BaseModel):
    question: str
    org_id: str


@app.post("/ask")
def ask(body: AskRequest):
    docs = store.similarity_search(body.question, k=4, filter={"org_id": body.org_id})
    return {"sources": [d.page_content for d in docs]}
`),
    ignores: f('app/rag.py', `from fastapi import Depends, FastAPI
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from pydantic import BaseModel

from app.auth import current_user

app = FastAPI()
store = Chroma(collection_name="docs", embedding_function=OpenAIEmbeddings())


class AskRequest(BaseModel):
    question: str


@app.post("/ask")
def ask(body: AskRequest, user=Depends(current_user)):
    docs = store.similarity_search(body.question, k=4, filter={"org_id": user.org_id})
    return {"sources": [d.page_content for d in docs]}
`)
  },
  {
    ruleIds: [28312],
    name: 'LLM-V2-12 Stripe secret placed in the system prompt',
    detects: f('app/api/support/route.ts', `import { anthropic } from '@ai-sdk/anthropic';
import { streamText } from 'ai';

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: anthropic('claude-sonnet-4-5'),
    system: \`You are the billing assistant.
When a refund is needed call the Stripe API with key \${process.env.STRIPE_SECRET_KEY}.\`,
    messages,
  });
  return result.toUIMessageStreamResponse();
}
`),
    ignores: f('app/api/support/route.ts', `import { anthropic } from '@ai-sdk/anthropic';
import { streamText } from 'ai';
import { refundTool } from '@/lib/tools/refund';

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({
    model: anthropic('claude-sonnet-4-5'),
    system: \`You are the billing assistant. Use the refund tool when a refund is needed.\`,
    tools: { refund: refundTool },
    messages,
  });
  return result.toUIMessageStreamResponse();
}
`)
  },
  {
    ruleIds: [28312],
    name: 'LLM-V2-12 database URL in a python f-string system prompt',
    detects: f('app/sql_assistant.py', `import os
from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = f"""You write SQL for our analytics database.
Connection: {os.environ["DATABASE_URL"]}
Only produce SELECT statements."""


def ask(question: str) -> str:
    out = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": question}],
    )
    return out.choices[0].message.content
`),
    ignores: f('app/sql_assistant.py', `import os
from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = f"""You write SQL for our analytics database ({os.environ.get("DB_DIALECT", "postgres")}).
Only produce SELECT statements."""


def ask(question: str) -> str:
    out = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": question}],
    )
    return out.choices[0].message.content
`)
  },
  {
    ruleIds: [28313],
    name: 'LLM-V2-13 OpenAI-compatible base URL from the request with the server key',
    detects: f('app/api/proxy/route.ts', `import { createOpenAI } from '@ai-sdk/openai';
import { generateText } from 'ai';

export async function POST(req: Request) {
  const body = await req.json();
  const provider = createOpenAI({
    baseURL: body.endpoint,
    apiKey: process.env.OPENAI_API_KEY,
  });
  const { text } = await generateText({ model: provider('gpt-4o-mini'), prompt: body.prompt });
  return Response.json({ text });
}
`),
    ignores: f('app/api/proxy/route.ts', `import { createOpenAI } from '@ai-sdk/openai';
import { generateText } from 'ai';

const PROVIDERS: Record<string, string> = {
  openai: 'https://api.openai.com/v1',
  groq: 'https://api.groq.com/openai/v1',
};

export async function POST(req: Request) {
  const body = await req.json();
  const provider = createOpenAI({
    baseURL: PROVIDERS.openai,
    apiKey: process.env.OPENAI_API_KEY,
  });
  const { text } = await generateText({ model: provider('gpt-4o-mini'), prompt: body.prompt });
  return Response.json({ text });
}
`)
  },
  {
    ruleIds: [28314],
    name: 'LLM-V2-14 Keras model loaded with safe_mode=False',
    detects: f('ml/serve.py', `import keras
from huggingface_hub import hf_hub_download

path = hf_hub_download("acme/churn-model", "model.keras")
model = keras.models.load_model(path, safe_mode=False)


def predict(features):
    return model.predict(features)
`),
    ignores: f('ml/serve.py', `import keras
from huggingface_hub import hf_hub_download

path = hf_hub_download("acme/churn-model", "model.keras", revision="3f1c2b7e9a")
model = keras.models.load_model(path)


def predict(features):
    return model.predict(features)
`)
  },
  {
    ruleIds: [28315],
    name: 'LLM-V2-15 joblib.load on a model downloaded from the hub',
    detects: f('ml/classifier.py', `import joblib
from huggingface_hub import hf_hub_download

model_path = hf_hub_download(repo_id="acme/spam-classifier", filename="model.joblib")
clf = joblib.load(model_path)


def is_spam(text: str) -> bool:
    return bool(clf.predict([text])[0])
`),
    ignores: f('ml/classifier.py', `import skops.io as sio
from huggingface_hub import hf_hub_download

model_path = hf_hub_download(repo_id="acme/spam-classifier", filename="model.skops", revision="9b2f0c1d4e")
clf = sio.load(model_path, trusted=["sklearn.pipeline.Pipeline"])


def is_spam(text: str) -> bool:
    return bool(clf.predict([text])[0])
`)
  },
  {
    ruleIds: [28316],
    name: 'LLM-V2-16 Ollama port published on all interfaces',
    detects: f('docker-compose.yml', `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama:/root/.ollama
  web:
    build: .
    environment:
      OLLAMA_URL: http://ollama:11434
volumes:
  ollama:
`),
    ignores: f('docker-compose.yml', `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "127.0.0.1:11434:11434"
    volumes:
      - ollama:/root/.ollama
  web:
    build: .
    environment:
      OLLAMA_URL: http://ollama:11434
volumes:
  ollama:
`)
  },
];
