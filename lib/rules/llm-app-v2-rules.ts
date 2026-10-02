/**
 * LLM and agent application security, research-backed replacements for the old LLM pack (LLM-V2-xx, Rule IDs 28301-28399).
 *
 * Sources: OWASP Top 10 for LLM Applications 2025 (LLM02/03/05/06/07/08/10), OWASP Agentic AI Threats & Mitigations,
 * MCP specification "Security Best Practices" (token passthrough, SSRF, local server exposure), MCP Inspector
 * CVE-2025-49596, LangChain CVE-2023-29374 / experimental-chain advisories, Keras CVE-2024-3660 (safe_mode),
 * Hugging Face trust_remote_code guidance, exposed-Ollama research.
 * Not repeated here: AI-APP-01..07 (#28201-28207: public LLM keys, model output to eval/SQL, shell/fs tools,
 * dangerouslyAllowBrowser, LangChain REPL tools), SAAS-07 (request data in the system prompt),
 * SEC-16 (dangerouslySetInnerHTML / innerHTML =), PY-SEC-40 (torch.load), pickle rules, LLM-COST-01 (max_tokens).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const indentOf = (l: string) => l.length - l.trimStart().length;
const IDENT = /^[A-Za-z_$][\w$]*$/;
const win = (lines: string[], idx: number, before: number, after: number) =>
  lines.slice(Math.max(0, idx - before), Math.min(lines.length, idx + after + 1)).join('\n');

/* ------------------------------------------------------------------------------------------------ */
/* Request-data taint (single file, regex based)                                                     */
/* ------------------------------------------------------------------------------------------------ */

interface Taint { src: string; names: string[] }

/** JS/TS: values that come straight from the HTTP request (body / query / params). */
function jsRequestTaint(lines: string[]): Taint {
  const objs = new Set<string>();
  const names = new Set<string>();
  const reqObj = String.raw`(?:await\s+(?:req|request|c\.req)\.json\(\)|(?:req|request|ctx\.request)\.(?:body|query|params))`;
  for (const l of lines) {
    let m: RegExpMatchArray | null;
    if ((m = l.match(new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*${reqObj}`)))) objs.add(m[1]);
    if ((m = l.match(new RegExp(String.raw`(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*${reqObj}`)))) {
      for (const part of m[1].split(',')) {
        const noDefault = part.replace(/=.*$/, '').trim();
        const alias = (noDefault.includes(':') ? noDefault.split(':')[1] : noDefault).trim().replace(/^\.\.\./, '');
        if (IDENT.test(alias)) names.add(alias);
      }
    }
    if ((m = l.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w.]*searchParams)\.get\(\s*['"][^'"]+['"]\s*\)/))) names.add(m[1]);
  }
  const direct = [
    String.raw`\b(?:req|request|ctx\.request)\.(?:body|query|params)(?:\.[A-Za-z_$][\w$]*|\[\s*['"][^'"]+['"]\s*\])`,
    String.raw`\b[\w.]*searchParams\.get\(\s*['"][^'"]+['"]\s*\)`,
    ...[...objs].map((o) => String.raw`\b${escapeRe(o)}(?:\??\.[A-Za-z_$][\w$]*|\[\s*['"][^'"]+['"]\s*\])`)
  ];
  // one hop: const ns = body.namespace
  for (const l of lines) {
    const m = l.match(new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:${direct.join('|')})\s*(?:\?\?|\|\||;|$)`));
    if (m) names.add(m[1]);
  }
  const all = [...direct, ...[...names].map((n) => String.raw`\b${escapeRe(n)}\b(?!\s*:)`)];
  return { src: all.map((p) => `(?:${p})`).join('|'), names: [...names] };
}

/** Python: FastAPI / Flask / Django request data. */
function pyRequestTaint(lines: string[]): Taint {
  const objs = new Set<string>();
  const names = new Set<string>();
  const skipTypes = /^(?:Request|Response|Session|AsyncSession|BackgroundTasks|WebSocket|User|HTTPAuthorizationCredentials|str|int|float|bool|dict|list|Any)$/;
  lines.forEach((l, i) => {
    if (!/^\s*@[\w.]+\.(?:get|post|put|patch|delete|api_route|route)\s*\(/.test(l)) return;
    for (let j = i + 1; j < Math.min(lines.length, i + 4); j++) {
      const d = lines[j].match(/^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/);
      if (!d) continue;
      for (const p of d[1].split(',')) {
        const m = p.trim().match(/^(\w+)\s*:\s*([A-Za-z_][\w.]*)\s*(?:=\s*(.*))?$/);
        if (m && !skipTypes.test(m[2]) && /^[A-Z]/.test(m[2]) && !/Depends\(/.test(m[3] || '')) objs.add(m[1]);
      }
      break;
    }
  });
  for (const l of lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*(?:await\s+)?request\.(?:get_json|json)\(\)/);
    if (m) objs.add(m[1]);
  }
  const direct = [
    String.raw`\brequest\.(?:args|form|values|GET|POST|query_params|data)(?:\.get\(\s*["'][^"']+["']|\[\s*["'][^"']+["']\s*\])`,
    String.raw`\b(?:await\s+)?request\.json\(\)\s*\[\s*["'][^"']+["']\s*\]`,
    ...[...objs].map((o) => String.raw`\b${escapeRe(o)}(?:\.(?!dict\b|model_dump\b|json\b)[A-Za-z_]\w*\b(?!\s*\()|\.get\(\s*["'][^"']+["']|\[\s*["'][^"']+["']\s*\])`)
  ];
  for (const l of lines) {
    const m = l.match(new RegExp(String.raw`^\s*([A-Za-z_]\w*)\s*=\s*(?:${direct.join('|')})\s*(?:or\s+["'][^"']*["']\s*)?$`));
    if (m) names.add(m[1]);
  }
  const all = [...direct, ...[...names].map((n) => String.raw`\b${escapeRe(n)}\b(?!\s*=)`)];
  return { src: all.map((p) => `(?:${p})`).join('|'), names: [...names] };
}

/** The tainted expression is compared / allowlist-checked somewhere in the file. */
function isAllowlistChecked(content: string, expr: string): boolean {
  const e = escapeRe(expr.trim());
  return new RegExp(String.raw`(?:includes|has|indexOf|some|find|hasOwnProperty|safeParse|parse)\(\s*${e}\s*[,)]|${e}\s*(?:===?|!==?)|(?:===?|!==?)\s*${e}\b|\b${e}\s+(?:not\s+)?in\s+[\w.\[(]|\[\s*${e}\s*\]`).test(content);
}

/* ------------------------------------------------------------------------------------------------ */
/* Agent / MCP tool handlers (model-chosen arguments)                                                */
/* ------------------------------------------------------------------------------------------------ */

interface ToolHandler { line: number; params: string[]; body: string[]; context: string }

function parseJsParams(raw: string): string[] {
  return raw.split(',').map((p) => {
    const noDefault = p.replace(/=.*$/, '').trim();
    return (noDefault.includes(':') ? noDefault.split(':')[1].trim() : noDefault).replace(/^\.\.\./, '');
  }).filter((p) => IDENT.test(p));
}

function bodyFrom(lines: string[], idx: number, max = 60): string[] {
  const body = [lines[idx]];
  const base = indentOf(lines[idx]);
  for (let i = idx + 1; i < lines.length && i < idx + max; i++) {
    if (lines[i].trim() && indentOf(lines[i]) <= base) break;
    body.push(lines[i]);
  }
  return body;
}

function jsToolHandlers(lines: string[]): ToolHandler[] {
  const out: ToolHandler[] = [];
  const seen = new Set<number>();
  const push = (idx: number, params: string[]) => {
    if (seen.has(idx) || !params.length) return;
    seen.add(idx);
    out.push({ line: idx, params, body: bodyFrom(lines, idx), context: lines.slice(Math.max(0, idx - 25), idx + 1).join('\n') });
  };
  lines.forEach((l, i) => {
    let m: RegExpMatchArray | null;
    if ((m = l.match(/\bexecute\s*:\s*async\s*\(\s*\{([^}]*)\}/)) || (m = l.match(/\basync\s+execute\s*\(\s*\{([^}]*)\}/)) || (m = l.match(/\btool\s*\(\s*async\s*\(\s*\{([^}]*)\}/))) {
      push(i, parseJsParams(m[1]));
    } else if ((m = l.match(/\b(?:execute|func)\s*:\s*async\s*\(\s*([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]]+\s*)?[,)]/))) {
      push(i, [m[1]]);
    } else if (/\.(?:tool|registerTool)\s*\(/.test(l)) {
      for (let j = i; j < Math.min(lines.length, i + 25); j++) {
        const h = lines[j].match(/\basync\s*\(\s*\{([^}]*)\}/);
        if (h) { push(j, parseJsParams(h[1])); break; }
      }
    }
  });
  return out;
}

function pyToolHandlers(lines: string[]): ToolHandler[] {
  const out: ToolHandler[] = [];
  lines.forEach((l, i) => {
    if (!/^\s*@(?:[\w.]+\.)?(?:tool|function_tool)\b/.test(l)) return;
    for (let j = i + 1; j < Math.min(lines.length, i + 4); j++) {
      const d = lines[j].match(/^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/);
      if (!d) continue;
      const params = d[1].split(',').map((p) => p.trim()).filter((p) => !/Literal\[/.test(p))
        .map((p) => p.replace(/[:=].*$/, '').replace(/^\*+/, '').trim()).filter((p) => IDENT.test(p) && !['self', 'ctx', 'context', 'cls'].includes(p));
      if (params.length) out.push({ line: j, params, body: bodyFrom(lines, j, 200), context: lines.slice(i, j + 1).join('\n') });
      break;
    }
  });
  return out;
}

/* ------------------------------------------------------------------------------------------------ */
/* Shared signals                                                                                    */
/* ------------------------------------------------------------------------------------------------ */

const JS_AGENT_FRAMEWORK = /(?:from\s+|require\(\s*)['"](?:ai|@ai-sdk\/[\w-]+|@modelcontextprotocol\/sdk[\w/.-]*|@langchain\/[\w/-]+|langchain[\w/-]*|@openai\/agents[\w/-]*|@anthropic-ai\/sdk[\w/-]*|@mastra\/core[\w/-]*|openai|mcp-handler)['"]/;
const PY_AGENT_FRAMEWORK = /\b(?:from|import)\s+(?:langchain\w*|langgraph|mcp|fastmcp|agents|openai|anthropic|crewai|llama_index|pydantic_ai|smolagents|autogen\w*)\b/;
const JS_MCP = /@modelcontextprotocol\/sdk|\bMcpServer\b|createMcpHandler|['"]mcp-handler['"]/;
const PY_MCP = /\b(?:from|import)\s+(?:mcp|fastmcp)\b|\bFastMCP\s*\(/;
const VECTOR_CONTEXT = /pinecone|qdrant|weaviate|chroma|pgvector|milvus|turbopuffer|@upstash\/vector|lancedb|vectorstores?|VectorStore|similarity_?[sS]earch|match_documents|as_?[rR]etriever|vector_store/;
const VECTOR_OP = /similarity_?[sS]earch\w*|\.namespace\(|['"]match_\w+['"]|as_?[rR]etriever|\btopK\b|\btop_k\b|includeMetadata|query_?[pP]oints|nearVector|nearText|search_kwargs|query_embeddings|query_texts|\.query\(\s*\{\s*(?:vector|queryVector|embedding|topK|data)\b/;
const SECRET_ENV_NAME = String.raw`[A-Z0-9_]*(?:API_KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|DATABASE_URL|CONNECTION_STRING|SERVICE_ROLE)[A-Z0-9_]*`;

/* ------------------------------------------------------------------------------------------------ */
/* Python                                                                                            */
/* ------------------------------------------------------------------------------------------------ */

function evaluatePython(lines: string[], content: string, hits: Hit[]): void {
  // LLM-V2-01: trust_remote_code=True executes the model repo's Python; unpinned revision = mutable code
  const trcIdx = lines.findIndex((l, i) => /\btrust_remote_code\s*=\s*True\b/.test(l) &&
    !/\brevision\s*=\s*(?!["'](?:main|master)["'])/.test(win(lines, i, 8, 8)));
  if (trcIdx !== -1) {
    hits.push({
      ruleId: 28301, code: 'LLM-V2-01', severity: 'MEDIUM', lineIdx: trcIdx,
      title: 'Hugging Face Model Loaded With trust_remote_code=True and No Pinned Revision',
      why: 'trust_remote_code=True downloads and executes the Python files in the model repository. Without a pinned commit revision, whoever controls (or compromises) that repo can push code that runs in your process on the next download (OWASP LLM03 Supply Chain).',
      fix: 'Prefer models supported natively by transformers (no remote code). If remote code is required, review it and pin revision="<full commit sha>" in the same call.'
    });
  }

  // LLM-V2-02: LangChain agent allowed to make arbitrary HTTP requests
  const reqIdx = lines.findIndex((l) => /\ballow_dangerous_requests\s*=\s*True\b/.test(l));
  if (reqIdx !== -1) {
    hits.push({
      ruleId: 28302, code: 'LLM-V2-02', severity: 'HIGH', lineIdx: reqIdx,
      title: 'LangChain Agent Allowed to Send Arbitrary HTTP Requests (allow_dangerous_requests)',
      why: 'allow_dangerous_requests=True gives the model a generic requests tool. A prompt-injected instruction can make the server call internal services or cloud metadata (http://169.254.169.254) and return the response (SSRF, OWASP LLM06 Excessive Agency).',
      fix: 'Replace the generic requests toolkit with narrow tools that call fixed endpoints with validated parameters, or route requests through an egress proxy that blocks private address ranges.'
    });
  }

  // LLM-V2-03: experimental LangChain chains that execute model output
  const chainIdx = lines.findIndex((l) => /\b(?:PALChain|LLMBashChain|LLMSymbolicMathChain|CPALChain)\s*(?:\.\s*from_\w+\s*)?\(/.test(l));
  if (chainIdx !== -1) {
    hits.push({
      ruleId: 28303, code: 'LLM-V2-03', severity: 'HIGH', lineIdx: chainIdx,
      title: 'LangChain Chain That Executes Model-Written Code (PAL / Bash / SymbolicMath)',
      why: 'PALChain runs generated Python, LLMBashChain runs generated shell commands and LLMSymbolicMathChain evaluates generated expressions on the host (CVE-2023-29374 class). Prompt injection in the question or retrieved content becomes code execution.',
      fix: 'Remove the chain, or run generated code only inside a disposable sandbox without credentials or network access; for math use a parser that cannot execute code.'
    });
  }

  // LLM-V2-04 (py): MCP stdio server command taken from the request
  const pyTaint = pyRequestTaint(lines);
  if (pyTaint.src) {
    const re = new RegExp(String.raw`\b(?:command|args)\s*=\s*\[?\s*(?:${pyTaint.src})`);
    const idx = lines.findIndex((l, i) => re.test(l) && /StdioServerParameters\s*\(|stdio_client\s*\(|StdioTransport\s*\(/.test(win(lines, i, 4, 0)));
    if (idx !== -1) pushStdioSpawn(hits, idx);
  }

  // LLM-V2-05 (py): MCP server forwards the caller's bearer token upstream
  if (PY_MCP.test(content)) {
    const src = String.raw`\brequest\.headers(?:\.get\(\s*|\[\s*)["']authorization["']|\bget_http_headers\(\)\s*(?:\.get\(\s*|\[\s*)["']authorization["']|\bget_access_token\(\)\s*\.\s*token\b|\baccess_token\s*\.\s*token\b|\bheaders(?:\.get\(\s*|\[\s*)["']authorization["']`;
    const derived = new Set<string>();
    for (const l of lines) {
      const m = l.match(new RegExp(String.raw`^\s*([A-Za-z_]\w*)\s*=\s*.*(?:${src})`, 'i'));
      if (m) derived.add(m[1]);
    }
    const value = [src, ...[...derived].map((d) => String.raw`\{?\b${escapeRe(d)}\b`)].join('|');
    const idx = lines.findIndex((l) => new RegExp(String.raw`["']authorization["']\s*:\s*(?:f["'][^"']*)?(?:${value})`, 'i').test(l));
    if (idx !== -1 && !/token[_-]?exchange|grant-type:token-exchange|on_behalf_of|exchange_token/i.test(content)) pushTokenPassthrough(hits, idx);
  }

  // LLM-V2-06 (py): HTTP MCP server on all interfaces without auth
  if (PY_MCP.test(content) && /transport\s*=\s*["'](?:sse|streamable-http|streamable_http|http)["']|streamable_http_app\s*\(|sse_app\s*\(|http_app\s*\(/.test(content) &&
    !/\bauth\s*=|token_verifier|AuthSettings|BearerAuthProvider|JWTVerifier|auth_provider|AuthProvider|verify_token|AuthenticationMiddleware|HTTPBearer|authorization|api_key/i.test(content)) {
    const idx = lines.findIndex((l, i) => /\bhost\s*=\s*["']0\.0\.0\.0["']/.test(l) && /\.run\s*\(|FastMCP\s*\(|uvicorn\.run\s*\(|\.run_\w+_async\s*\(/.test(win(lines, i, 4, 0)));
    if (idx !== -1) pushOpenMcp(hits, idx);
  }

  // LLM-V2-09 (py): agent / MCP tool fetches a model-chosen URL
  if (PY_AGENT_FRAMEWORK.test(content)) {
    for (const h of pyToolHandlers(lines)) {
      const bodyText = h.body.join('\n');
      if (SSRF_GUARD.test(h.context + '\n' + bodyText)) continue;
      const a = `(?:${h.params.map((p) => String.raw`\b${escapeRe(p)}\b`).join('|')})`;
      const sink = new RegExp(String.raw`\b(?:requests|httpx|session|client|http|aiohttp_session|s)\.(?:get|post|put|head|request|stream)\s*\(\s*(?:["'][A-Z]+["']\s*,\s*)?(?:${a}\s*[,)]|f["']\{${a}\})|\burlopen\s*\(\s*${a}\s*[,)]|\.goto\s*\(\s*${a}\s*[,)]|\b(?:WebBaseLoader|AsyncHtmlLoader|SeleniumURLLoader)\s*\(\s*\[?\s*${a}\b`);
      const off = h.body.findIndex((l) => sink.test(l));
      if (off !== -1) { pushToolSsrf(hits, h.line + off); break; }
    }
  }

  // LLM-V2-10 (py): client-chosen model id (visible free-text schema field) passed to the provider
  if (/^\s*model\s*:\s*(?:str|Optional\[str\]|str\s*\|\s*None)\b/m.test(content) && /\b(?:chat\.completions|completions|messages|responses)\.(?:create|stream|parse)\s*\(|\bcompletion\s*\(|\binit_chat_model\s*\(|\bChat(?:OpenAI|Anthropic|LiteLLM)\s*\(/.test(content)) {
    const idx = lines.findIndex((l) => {
      const m = l.match(/\bmodel(?:_name)?\s*=\s*(\w+)\.model\b(?!\s*\()/);
      return !!m && new RegExp(String.raw`\b${escapeRe(m[1])}\s*:\s*[A-Z]\w*`).test(content) && !isAllowlistChecked(content, `${m[1]}.model`);
    });
    if (idx !== -1) pushModelChoice(hits, idx);
  }

  // LLM-V2-11 (py): vector store namespace / filter taken from the request
  if (pyTaint.src && VECTOR_CONTEXT.test(content)) {
    const re = new RegExp(String.raw`(?:\b(?:namespace|filter|where|partition)\s*=\s*|["'](?:namespace|tenant_id|org_id|organization_id|workspace_id|user_id)["']\s*:\s*)(${pyTaint.src})`);
    const idx = lines.findIndex((l, i) => {
      const m = l.match(re);
      return !!m && VECTOR_OP.test(win(lines, i, 8, 8)) && !isAllowlistChecked(content, m[1]);
    });
    if (idx !== -1) pushVectorTenant(hits, idx);
  }

  // LLM-V2-12 (py): secret env var interpolated into a prompt
  const pyPrompt = /(?:\b(?:system_prompt|SYSTEM_PROMPT|system|instructions|prompt|PROMPT|template)\s*=\s*|["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*|SystemMessage\s*\(\s*(?:content\s*=\s*)?)f("""|'''|"|')([\s\S]*?)\1/g;
  const secretPy = new RegExp(String.raw`\{\s*(?:os\.environ\[\s*["']${SECRET_ENV_NAME}["']\s*\]|os\.(?:environ\.get|getenv)\(\s*["']${SECRET_ENV_NAME}["'][^)]*\)|settings\.${SECRET_ENV_NAME})`);
  for (const m of content.matchAll(pyPrompt)) {
    const s = m[2].match(secretPy);
    if (!s || m.index === undefined) continue;
    const at = m.index + m[0].indexOf(s[0]);
    pushSecretPrompt(hits, content.slice(0, at).split('\n').length - 1);
    break;
  }

  // LLM-V2-13 (py): provider base_url from the request while the server key is used
  if (pyTaint.src) {
    const re = new RegExp(String.raw`\bbase_url\s*=\s*(?:${pyTaint.src})`);
    const idx = lines.findIndex((l, i) => {
      if (!re.test(l)) return false;
      const call = win(lines, i, 4, 4);
      if (!/\b(?:Async)?(?:OpenAI|AzureOpenAI|Anthropic|ChatOpenAI|ChatAnthropic|Groq|Mistral)\s*\(/.test(call)) return false;
      const key = call.match(/\bapi_key\s*=\s*([^,)\n]+)/);
      return !key || !new RegExp(pyTaint.src).test(key[1]);
    });
    if (idx !== -1) pushBaseUrl(hits, idx);
  }

  // LLM-V2-14: Keras deserialization safety disabled
  const kerasIdx = lines.findIndex((l, i) => /\bsafe_mode\s*=\s*False\b/.test(l) && /load_model\s*\(|from_config\s*\(|deserialize\w*\s*\(/.test(win(lines, i, 4, 0))) ;
  const unsafeIdx = kerasIdx !== -1 ? kerasIdx : lines.findIndex((l) => /\benable_unsafe_deserialization\s*\(\s*\)/.test(l));
  if (unsafeIdx !== -1) {
    hits.push({
      ruleId: 28314, code: 'LLM-V2-14', severity: 'MEDIUM', lineIdx: unsafeIdx,
      title: 'Keras Model Loaded With Safe Mode Disabled',
      why: 'safe_mode=False (or enable_unsafe_deserialization()) lets a .keras file deserialize Lambda layers containing arbitrary Python bytecode, so loading a tampered model file executes code (CVE-2024-3660 class, OWASP LLM03).',
      fix: 'Keep safe_mode=True (the default), replace Lambda layers with registered custom layers, and only load model files from a trusted, integrity-checked source.'
    });
  }

  // LLM-V2-15: pickle-based model loaders on a downloaded file
  const downloaded = new Set<string>();
  for (const l of lines) {
    const m = l.match(/^\s*(\w+)\s*=\s*(?:\w+\.)*(?:hf_hub_download|cached_download|snapshot_download|urlretrieve|download)\s*\(/);
    if (m) downloaded.add(m[1]);
  }
  const dl = [String.raw`(?:\w+\.)*(?:hf_hub_download|snapshot_download|cached_download)\s*\(`, ...[...downloaded].map((d) => String.raw`\b${escapeRe(d)}\b`)].join('|');
  const loaderRe = new RegExp(String.raw`\b(?:joblib|dill|cloudpickle|pd|pandas)\.(?:load|read_pickle)\s*\(\s*(?:open\s*\(\s*)?(?:os\.path\.join\s*\(\s*|Path\s*\(\s*)?(?:${dl})`);
  const loadIdx = lines.findIndex((l) => loaderRe.test(l));
  if (loadIdx !== -1) {
    hits.push({
      ruleId: 28315, code: 'LLM-V2-15', severity: 'MEDIUM', lineIdx: loadIdx,
      title: 'Downloaded Model Deserialized With a Pickle-Based Loader (joblib / dill / read_pickle)',
      why: 'joblib, dill, cloudpickle and pandas.read_pickle unpickle the file, which runs any code embedded in it. A model fetched from a hub or URL at runtime is only as trustworthy as that repository (OWASP LLM03 Supply Chain).',
      fix: 'Distribute models in a non-executable format (safetensors, ONNX, skops with trusted types), or pin the download to a reviewed commit and verify its hash before loading.'
    });
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* JS / TS / Vue / Svelte                                                                            */
/* ------------------------------------------------------------------------------------------------ */

const SSRF_GUARD = /new URL\(|urlparse|urlsplit|\.hostname\b|netloc|ALLOWED_|allowlist|allowedHosts|allowed_hosts|allowed_domains|allowedDomains|isPrivate|is_private|ssrf|ipaddr|ip_address|is_global|startsWith\(\s*['"]https?:\/\/\w|startswith\(\s*\(?['"]https?:\/\/\w/i;

function evaluateJs(path: string, lines: string[], content: string, hits: Hit[]): void {
  const isMarkup = /\.(?:vue|svelte|astro|html)$/i.test(path);
  const taint = isMarkup ? null : jsRequestTaint(lines);

  // LLM-V2-02 (js): LangChain JS generic requests tools
  if (/['"](?:@langchain\/[\w/-]+|langchain[\w/-]*)['"]/.test(content)) {
    const idx = lines.findIndex((l) => /\bnew\s+Requests(?:Get|Post|Put|Patch|Delete)Tool\s*\(|\bnew\s+RequestsToolkit\s*\(/.test(l));
    if (idx !== -1) {
      hits.push({
        ruleId: 28302, code: 'LLM-V2-02', severity: 'HIGH', lineIdx: idx,
        title: 'LangChain Agent Allowed to Send Arbitrary HTTP Requests (allow_dangerous_requests)',
        why: 'The generic Requests tools let the model fetch any URL from your server. A prompt-injected instruction can make the agent call internal services or cloud metadata (http://169.254.169.254) and return the response (SSRF, OWASP LLM06 Excessive Agency).',
        fix: 'Replace the generic requests tools with narrow tools that call fixed endpoints with validated parameters, or route requests through an egress proxy that blocks private address ranges.'
      });
    }
  }

  // LLM-V2-04 (js): MCP stdio server command/args from the request (MCP Inspector CVE-2025-49596 pattern)
  if (taint && /StdioClientTransport|StdioServerParameters|getDefaultEnvironment/.test(content)) {
    const re = new RegExp(String.raw`\b(?:command|args)\s*:\s*(?:\[\s*)?(?:\.\.\.)?(?:${taint.src})`);
    const shorthand = taint.names.filter((n) => n === 'command' || n === 'args');
    const idx = lines.findIndex((l, i) => {
      if (!/new\s+StdioClientTransport\s*\(/.test(win(lines, i, 6, 0))) return false;
      return re.test(l) || shorthand.some((n) => new RegExp(String.raw`(?:^|[{,])\s*${n}\s*(?:,|\}|$)`).test(l));
    });
    if (idx !== -1) pushStdioSpawn(hits, idx);
  }

  // LLM-V2-05 (js): MCP server forwards the caller's bearer token upstream
  if (JS_MCP.test(content)) {
    const src = String.raw`\b(?:req|request|ctx\.request|c\.req)\.(?:headers\.authorization|headers\[\s*['"]authorization['"]\s*\]|headers\.get\(\s*['"]authorization['"]\s*\)|header\(\s*['"]authorization['"]\s*\))|\bauthInfo\??\.token\b`;
    const derived = new Set<string>();
    for (const l of lines) {
      const m = l.match(new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*(?:${src})`, 'i'));
      if (m) derived.add(m[1]);
    }
    const value = [src, ...[...derived].map((d) => String.raw`\b${escapeRe(d)}\b`)].join('|');
    const idx = lines.findIndex((l) => new RegExp(String.raw`['"]?\bauthorization['"]?\s*:\s*(?:\x60[^\x60]*\$\{\s*)?(?:[\w$]+\??\.)*(?:${value})`, 'i').test(l));
    if (idx !== -1 && !/token[_-]?exchange|grant-type:token-exchange|onBehalfOf|on_behalf_of|exchangeToken/i.test(content)) pushTokenPassthrough(hits, idx);
  }

  // LLM-V2-06 (js): HTTP MCP server on all interfaces without auth
  if (/StreamableHTTPServerTransport|SSEServerTransport|createMcpExpressApp|createMcpHandler/.test(content) &&
    !/requireBearerAuth|mcpAuthRouter|mcpAuthMetadataRouter|withMcpAuth|authenticate|authorization|verifyToken|verifyAccessToken|jwt|passport|clerk|\bauth\s*\(|bearer|x-api-key|basicAuth|authMiddleware/i.test(content)) {
    const idx = lines.findIndex((l) => /\.listen\(\s*[^,()]+,\s*['"]0\.0\.0\.0['"]|\bhost(?:name)?\s*:\s*['"]0\.0\.0\.0['"]/.test(l));
    if (idx !== -1) pushOpenMcp(hits, idx);
  }

  // LLM-V2-07: model output written into raw-HTML sinks not covered by SEC-16 (v-html, {@html}, innerHTML +=, insertAdjacentHTML)
  const llmUi = /useChat|useCompletion|useAssistant|@ai-sdk\/|from\s+['"]ai(?:\/[\w-]+)?['"]|chat\.completions|\/api\/(?:chat|completion|ai|assistant|llm|generate)\b|['"]assistant['"]|streamText|\bopenai\b|anthropic|\bllm\b/i;
  const sanitizer = /DOMPurify|dompurify|sanitize-html|sanitizeHtml|\bsanitize\s*\(|\bxss\s*\(|rehype-sanitize|isomorphic-dompurify/;
  if (llmUi.test(content) && !sanitizer.test(content)) {
    const mdLib = /\b(?:marked(?:\.parse)?|md\.render|markdownIt\(\)\.render|mdi\.render|converter\.makeHtml|snarkdown|micromark)\s*\(/;
    const modelValue = /\b(?:completion|aiResponse|ai_response|botReply|answer|reply|assistantMessage|llmOutput|chunk|delta|choices)\b|\b(?:message|msg|m|item|part)\.(?:content|text)\b|decoder\.decode\(/;
    const idx = lines.findIndex((l) => {
      const sinks = [
        l.match(/\bv-html\s*=\s*"([^"]+)"/), l.match(/\{@html\s+([^}]+)\}/),
        l.match(/\.innerHTML\s*\+=\s*([^;\n]+)/), l.match(/\.insertAdjacentHTML\(\s*['"][\w-]+['"]\s*,\s*([^;\n]+)\)/)
      ];
      return sinks.some((m) => !!m && (mdLib.test(m[1]) || modelValue.test(m[1])));
    });
    if (idx !== -1) {
      hits.push({
        ruleId: 28307, code: 'LLM-V2-07', severity: 'HIGH', lineIdx: idx,
        title: 'LLM Output Inserted as Raw HTML (v-html / {@html} / innerHTML +=)',
        why: 'Model output is attacker-influenced: indirect prompt injection in a web page, document or shared conversation can make the model emit <img src=x onerror=...> or a phishing form, which this sink renders as live HTML in the user\'s session (OWASP LLM05 Improper Output Handling).',
        fix: 'Render model output as text, or convert markdown and pass the result through DOMPurify.sanitize() before inserting it; for streaming, append text nodes (textContent) instead of innerHTML.'
      });
    }
  }

  // LLM-V2-08: react-markdown with rehype-raw on chat output without a sanitizer
  if (/['"]rehype-raw['"]/.test(content) && /useChat|useCompletion|@ai-sdk\/|from\s+['"]ai['"]|role\s*===?\s*['"]assistant['"]|\b(?:message|msg|m)\.content\b|completion|chatbot/i.test(content) && !sanitizer.test(content) && !/harden-react-markdown|rehypeSanitize/.test(content)) {
    const idx = lines.findIndex((l) => /rehypePlugins\s*=\s*\{[^}]*\brehypeRaw\b|rehypePlugins\s*:\s*\[[^\]]*\brehypeRaw\b/.test(l));
    if (idx !== -1) {
      hits.push({
        ruleId: 28308, code: 'LLM-V2-08', severity: 'MEDIUM', lineIdx: idx,
        title: 'Chat Markdown Rendered With rehype-raw and No Sanitizer',
        why: 'rehype-raw turns HTML inside the model\'s markdown into real elements. Prompt-injected output can then render iframes (srcdoc runs same-origin script), forms or tracking images in the user\'s session (OWASP LLM05).',
        fix: 'Drop rehype-raw for model output, or add rehype-sanitize after it (rehypePlugins={[rehypeRaw, rehypeSanitize]}) with a restrictive schema.'
      });
    }
  }

  if (isMarkup || !taint) return;

  // LLM-V2-09 (js): agent / MCP tool fetches a model-chosen URL
  if (JS_AGENT_FRAMEWORK.test(content)) {
    for (const h of jsToolHandlers(lines)) {
      const bodyText = h.body.join('\n');
      if (SSRF_GUARD.test(h.context + '\n' + bodyText)) continue;
      const params = h.params.filter((p) => !new RegExp(String.raw`\b${escapeRe(p)}\s*:\s*z\.(?:enum|literal|nativeEnum)\(`).test(h.context));
      if (!params.length) continue;
      const a = `(?:${params.map((p) => String.raw`\b${escapeRe(p)}\b`).join('|')})`;
      const sink = new RegExp(String.raw`(?:(?<![\w.$])(?:fetch|got|ky|needle)|\baxios(?:\.(?:get|post|put|delete|head|request))?|\bundici\.request|\bhttps?\.get)\s*\(\s*(?:${a}\s*[,)]|\x60\$\{\s*${a}\s*\})|\baxios\s*\(\s*\{[^}]*\burl\s*:\s*${a}\b|\.goto\s*\(\s*${a}\s*[,)]`);
      const off = h.body.findIndex((l) => sink.test(l));
      if (off !== -1) { pushToolSsrf(hits, h.line + off); break; }
    }
  }

  const llmCall = /\b(?:streamText|generateText|streamObject|generateObject|streamUI)\s*\(|\.(?:chat\.completions|completions|messages|responses)\.(?:create|stream|parse)\s*\(|\bnew\s+Chat(?:OpenAI|Anthropic|Groq|Mistral\w*)\s*\(/;

  // LLM-V2-10 (js): raw client-chosen model id passed to the provider
  if (!/\.(?:safeParse|parse)\s*\(/.test(content)) {
    const modelSink = new RegExp(String.raw`\bmodel\s*:\s*(?:[\w$.]+\(\s*)?(${taint.src})\s*\)?\s*(?:,|\}|\?\?|\|\||$)`);
    let idx = -1;
    lines.forEach((l, i) => {
      if (idx !== -1 || !llmCall.test(l)) return;
      for (let j = i; j < Math.min(lines.length, i + 20); j++) {
        const m = lines[j].match(modelSink);
        const short = taint.names.includes('model') && /(?:^|[{,])\s*model\s*(?:,|\}|$)/.test(lines[j]);
        const expr = m ? m[1] : short ? 'model' : '';
        if (expr && !isAllowlistChecked(content, expr)) { idx = j; break; }
      }
    });
    if (idx !== -1) pushModelChoice(hits, idx);
  }

  // LLM-V2-11 (js): vector store namespace / filter taken from the request
  if (VECTOR_CONTEXT.test(content)) {
    const re = new RegExp(String.raw`(?:\.namespace\(\s*|\b(?:namespace|filter|where|tenantId|tenant_id|orgId|org_id|organizationId|workspaceId|workspace_id|userId|user_id)\s*:\s*)(${taint.src})\s*(?:\)|,|\}|$)`);
    const idx = lines.findIndex((l, i) => {
      const m = l.match(re);
      return !!m && VECTOR_OP.test(win(lines, i, 8, 8)) && !isAllowlistChecked(content, m[1]);
    });
    if (idx !== -1) pushVectorTenant(hits, idx);
  }

  // LLM-V2-12 (js): secret env var interpolated into a prompt
  if (llmCall.test(content) || /\bSystemMessage\b|systemInstruction/.test(content)) {
    const promptRe = /(?:\b(?:system|instructions|systemInstruction|preamble|systemPrompt|SYSTEM_PROMPT|prompt)\s*[:=]\s*|role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*|new\s+SystemMessage\s*\(\s*)\x60([^\x60]*)\x60/g;
    const secretJs = new RegExp(String.raw`\$\{\s*(?:process\.env\.|import\.meta\.env\.|env\.)${SECRET_ENV_NAME}\b`);
    for (const m of content.matchAll(promptRe)) {
      const s = m[1].match(secretJs);
      if (!s || m.index === undefined) continue;
      pushSecretPrompt(hits, content.slice(0, m.index + m[0].indexOf(s[0])).split('\n').length - 1);
      break;
    }
  }

  // LLM-V2-13 (js): provider baseURL from the request while the server key is used
  {
    const re = new RegExp(String.raw`\bbase(?:URL|Url)\s*:\s*(${taint.src})\s*(?:,|\}|$)`);
    const short = taint.names.filter((n) => n === 'baseURL' || n === 'baseUrl');
    const idx = lines.findIndex((l, i) => {
      if (!re.test(l) && !short.some((n) => new RegExp(String.raw`(?:^|[{,])\s*${n}\s*(?:,|\}|$)`).test(l))) return false;
      const call = win(lines, i, 5, 5);
      if (!/\bnew\s+(?:OpenAI|AzureOpenAI|Anthropic|ChatOpenAI|ChatAnthropic|Groq)\s*\(|\bcreate(?:OpenAI|OpenAICompatible|Anthropic|Groq|Mistral|DeepSeek|XAI)\s*\(/.test(call)) return false;
      const key = call.match(/\bapiKey\s*:\s*([^,}\n]+)/);
      return !key || !new RegExp(taint.src).test(key[1]);
    });
    if (idx !== -1) pushBaseUrl(hits, idx);
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* Compose files                                                                                     */
/* ------------------------------------------------------------------------------------------------ */

function evaluateCompose(lines: string[], hits: Hit[]): void {
  // LLM-V2-16: Ollama API (no auth) published on every host interface
  const idx = lines.findIndex((l) => /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:\$\{[^}]*\}|\d+):11434(?:\/tcp)?["']?\s*$/.test(l) || /^\s*-\s*["']?11434["']?\s*$/.test(l) ||
    /^\s*published\s*:\s*["']?11434["']?\s*$/.test(l));
  if (idx === -1) return;
  const near = win(lines, idx, 6, 6);
  if (/host_ip\s*:\s*["']?127\.0\.0\.1/.test(near)) return;
  hits.push({
    ruleId: 28316, code: 'LLM-V2-16', severity: 'MEDIUM', lineIdx: idx,
    title: 'Ollama API Port Published on All Interfaces',
    why: 'Ollama\'s API has no authentication. Publishing 11434 without a host IP binds it on every interface (Docker also bypasses ufw), so anyone who can reach the host can run, pull and delete models and consume the GPU; tens of thousands of such servers are exposed on the internet.',
    fix: 'Do not publish the port (other services reach it as http://ollama:11434 on the compose network), or bind it to loopback ("127.0.0.1:11434:11434") and put an authenticating reverse proxy in front for remote use.'
  });
}

/* ------------------------------------------------------------------------------------------------ */
/* Shared hit builders                                                                               */
/* ------------------------------------------------------------------------------------------------ */

function pushStdioSpawn(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28304, code: 'LLM-V2-04', severity: 'CRITICAL', lineIdx,
    title: 'MCP stdio Server Command Taken From the Request (Remote Code Execution)',
    why: 'The stdio transport spawns `command` with `args` as a local process. Taking them from the HTTP request lets any caller (or a web page via CSRF / DNS rebinding) run arbitrary programs on the host, as in MCP Inspector CVE-2025-49596.',
    fix: 'Let clients pick a server id only, and map it to a fixed command and args from server-side configuration; require authentication and Origin checks on the proxy endpoint.'
  });
}

function pushTokenPassthrough(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28305, code: 'LLM-V2-05', severity: 'MEDIUM', lineIdx,
    title: 'MCP Server Forwards the Client\'s Bearer Token Upstream (Token Passthrough)',
    why: 'The MCP specification forbids token passthrough: the server accepts a token not issued to it and replays it to another API. This bypasses audience validation, rate limits and audit at the MCP server and makes it a confused deputy for stolen tokens.',
    fix: 'Validate that incoming tokens are issued for this MCP server (audience / resource indicator), then call the upstream API with the server\'s own credentials or a token obtained via OAuth token exchange.'
  });
}

function pushOpenMcp(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28306, code: 'LLM-V2-06', severity: 'MEDIUM', lineIdx,
    title: 'HTTP MCP Server Listens on All Interfaces Without Authentication',
    why: 'The MCP server is bound to 0.0.0.0 over Streamable HTTP / SSE and the file sets up no authentication, so anyone who can reach the port can list and invoke its tools with the server\'s credentials.',
    fix: 'Bind local servers to 127.0.0.1 (with DNS-rebinding protection / Origin validation) or use stdio; for remote servers require OAuth bearer tokens (requireBearerAuth / FastMCP auth=) before handling MCP requests.'
  });
}

function pushToolSsrf(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28309, code: 'LLM-V2-09', severity: 'HIGH', lineIdx,
    title: 'Agent / MCP Tool Fetches a Model-Supplied URL Without SSRF Checks',
    why: 'The URL is chosen by the model, which follows instructions from user messages and fetched content. Prompt injection can point the tool at cloud metadata (169.254.169.254), localhost admin ports or internal APIs and return the response (SSRF, OWASP LLM06).',
    fix: 'Parse the URL, allow only https and an allowlist of hosts (or resolve and reject private / link-local / loopback IPs and re-check after redirects), or send these requests through an egress proxy such as Smokescreen.'
  });
}

function pushModelChoice(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28310, code: 'LLM-V2-10', severity: 'MEDIUM', lineIdx,
    title: 'Client-Chosen Model ID Passed to the LLM Provider Unchecked',
    why: 'The model name comes from the request body unvalidated, so any caller can switch to the most expensive or unreleased models on your account (cost abuse, plan bypass, OWASP LLM10 Unbounded Consumption).',
    fix: 'Validate the requested model against a server-side allowlist (z.enum([...]) or ALLOWED_MODELS.includes(model)) tied to the user\'s plan, and fall back to a default otherwise.'
  });
}

function pushVectorTenant(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28311, code: 'LLM-V2-11', severity: 'HIGH', lineIdx,
    title: 'Vector Search Namespace / Tenant Filter Taken From the Request',
    why: 'The namespace or metadata filter that separates tenants in the vector store is supplied by the client, so a user can retrieve (and have the model summarize) other customers\' embedded documents (OWASP LLM08 Vector and Embedding Weaknesses).',
    fix: 'Derive the namespace / tenant filter from the authenticated session (user id, organization id from the verified token) on the server, never from request input.'
  });
}

function pushSecretPrompt(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28312, code: 'LLM-V2-12', severity: 'HIGH', lineIdx,
    title: 'Secret Environment Variable Interpolated Into an LLM Prompt',
    why: 'Anything in the prompt can be extracted by the user ("repeat your instructions") or leaked by the model, and it is stored in provider logs and tracing tools. A credential placed in the prompt is effectively public (OWASP LLM07 System Prompt Leakage).',
    fix: 'Keep credentials out of prompts. Give the model a tool whose server-side implementation uses the secret, so the model never sees it.'
  });
}

function pushBaseUrl(hits: Hit[], lineIdx: number): void {
  hits.push({
    ruleId: 28313, code: 'LLM-V2-13', severity: 'HIGH', lineIdx,
    title: 'LLM Client Base URL Taken From the Request (Server API Key Exfiltration / SSRF)',
    why: 'The provider SDK sends the server\'s API key as a bearer header to whatever base URL it is given. A caller who sets baseURL to their own host receives your key; pointing it at internal addresses turns the endpoint into an SSRF proxy.',
    fix: 'Select the provider from a fixed server-side map of base URLs. If users bring their own endpoint, also require their own API key and block private addresses.'
  });
}

/* ------------------------------------------------------------------------------------------------ */

export function evaluateLlmAppV2Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (/(?:^|\/)(?:node_modules|site-packages|\.venv|venv)\//.test(path) || /\.d\.ts$/i.test(path)) return { findings, logs };
  const raw = (file.content || cleanContent).replace(/\r/g, '');
  const hits: Hit[] = [];
  let reportLines: string[] = lines;

  if (/\.py$/i.test(path)) {
    // Python: the JS comment stripper does not know `#`; blank full-line comments, keep line numbers
    reportLines = raw.split('\n');
    const pyLines = reportLines.map((l) => (/^\s*#/.test(l) ? '' : l));
    evaluatePython(pyLines, pyLines.join('\n'), hits);
  } else if (/\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i.test(path)) {
    evaluateJs(path, lines, cleanContent, hits);
  } else if (/(?:^|\/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i.test(path)) {
    reportLines = raw.split('\n');
    evaluateCompose(reportLines.map((l) => (/^\s*#/.test(l) ? '' : l)), hits);
  } else {
    return { findings, logs };
  }

  const ts = new Date().toLocaleTimeString();
  const seen = new Set<number>();
  for (const h of hits) {
    if (seen.has(h.ruleId)) continue;
    seen.add(h.ruleId);
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `llmv2${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'AI & LLM Security',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (reportLines[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [LLM-V2] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
