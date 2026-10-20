/**
 * Missing-guard rules (MG-01.., Rule IDs 30401-30499): code that looks like an auth check but proves nothing.
 * The pattern rules catch `jwt.decode()`; these follow hand-written helpers (`parseToken()`, `getUserFromToken()`)
 * into their bodies and ask whether a signature is ever checked.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner/types';
import { SKIP, lineAt } from './logic-gemini-rules';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const JS = /\.[cm]?[jt]sx?$/i;
const PY = /\.py$/i;

/** Any of these anywhere in the file means a signature is checked somewhere: stay quiet. */
const JS_VERIFY = /\bcreateHmac\s*\(|\bsubtle\s*\.\s*verify\s*\(|\bjwtVerify\s*\(|\bjwt\s*\.\s*verify\s*\(|\bverifyJwt\w*\s*\(|\bcrypto\s*\.\s*verify\s*\(|\btimingSafeEqual\s*\(|\bcreateVerify\s*\(|\bverifySignature\w*\s*\(|\bjose\b|\bjsonwebtoken\b/;
const PY_VERIFY = /\bhmac\s*\.\s*(?:new|compare_digest|digest)\s*\(|\bjwt\s*\.\s*decode\s*\([^)]*\b(?:key|secret|algorithms)\b|\bverify(?:_signature|_token|_jwt)?\s*\(|\bjws\b|\bjose\b/;

/** Browser code may decode a JWT to show a name or an expiry; that is not an auth decision. */
const BROWSER = /^\s*['"]use client['"]|\blocalStorage\b|\bsessionStorage\b|\bdocument\s*\.\s*cookie\b|\bwindow\s*\./m;
const SERVER_FILE = /(?:^|\/)(?:middleware\.[cm]?[jt]s|app\/api\/|pages\/api\/|server\/|api\/|routes?\/|controllers?\/|handlers?\/|lib\/auth|auth\/)/i;
const SERVER_SIGNAL = /\bauthorization\b|\bbearer\b|\breq(?:uest)?\s*\.\s*headers\b|\bcookies\s*\(\s*\)|\bheaders\s*\(\s*\)|\bNextRequest\b|\bNextResponse\b|['"]use server['"]|\bexpress\b|\bfastify\b|\bhono\b|\bkoa\b/i;
/** Python web apps: a framework import or a request header read. Scripts and CLI tools decoding their own tokens are not auth checks. */
const PY_SERVER_SIGNAL = /^\s*(?:from|import)\s+(?:flask|fastapi|django|starlette|sanic|aiohttp|tornado|falcon|bottle|quart|litestar)\b|\brequest\s*\.\s*(?:headers|META|cookies)\b|\bHTTP_AUTHORIZATION\b|\bDepends\s*\(/m;

/** Names a `.split('.')` result is bound to: `parts = t.split('.')`, `[, payload] = t.split('.')`, `h, p, s = t.split(".")`. */
function splitNames(body: string): string[] {
  const names: string[] = [];
  for (const m of body.matchAll(/(?:\b(?:const|let|var)\s+)?(\[[^\]]*\]|\w+(?:\s*,\s*\w+)*)\s*=\s*[\w.()[\]'"?]+\.split\(\s*['"]\.['"]\s*\)/g)) {
    names.push(...m[1].replace(/[[\]]/g, '').split(',').map((s) => s.trim()).filter((s) => /^\w+$/.test(s)));
  }
  // One hop: `payload = parts[1] + '=='` (padding before the decode)
  for (const m of body.matchAll(/(?:\b(?:const|let|var)\s+)?(\w+)\s*=\s*([^\n;=][^\n;]*)/g)) {
    if (!names.includes(m[1]) && names.some((n) => new RegExp(String.raw`\b${n}\b`).test(m[2]))) names.push(m[1]);
  }
  return names;
}

/** The decode call reads a piece of the split token: the split itself, or a name bound from it. */
function decodesSplitPart(call: string, names: string[]): boolean {
  return /\.split\(\s*['"]\.['"]\s*\)/.test(call) || names.some((n) => new RegExp(String.raw`\b${n}\b`).test(call));
}

const JS_SPLIT = /\.split\(\s*['"]\.['"]\s*\)/;
const JS_B64 = /\batob\s*\(|\bBuffer\s*\.\s*from\s*\([^)]*['"]base64(?:url)?['"]|\bbase64url\s*\.\s*decode\s*\(/;
const JS_PARSE = /\bJSON\s*\.\s*parse\s*\(/;
const PY_SPLIT = /\.split\(\s*['"]\.['"]\s*\)/;
const PY_B64 = /\bbase64\s*\.\s*(?:urlsafe_)?b64decode\s*\(/;
const PY_PARSE = /\bjson\s*\.\s*loads\s*\(/;

/** Claims an app reads to decide who the caller is. */
const IDENTITY = /\.\s*(?:sub|userId|user_id|uid|role|roles|email|isAdmin|is_admin|tenantId|org_id|orgId)\b|\[\s*['"](?:sub|user_id|userId|uid|role|email|is_admin)['"]\s*\]/;
const AUTH_NAME = /token|jwt|session|auth|claim|user|verify|identity|caller/i;

interface Block { name: string; start: number; end: number }

/** The function returns the parsed payload itself (`return JSON.parse(...)`, or a variable assigned from it). */
function returnsPayload(body: string, js: boolean): boolean {
  const parse = js ? String.raw`JSON\s*\.\s*parse\s*\(` : String.raw`json\s*\.\s*loads\s*\(`;
  if (new RegExp(String.raw`\breturn\s+(?:\(\s*)?${parse}`).test(body)) return true;
  const vars = [...body.matchAll(new RegExp(String.raw`(?:\b(?:const|let|var)\s+)?(\w+)\s*(?::[^=\n]+)?=\s*(?:await\s+)?${parse}`, 'g'))].map((m) => m[1]);
  return vars.some((v) => new RegExp(String.raw`\breturn\s+${v}\b\s*(?:as\b|;|$|\n)`, 'm').test(body));
}

function matchBrace(c: string, open: number): number {
  let depth = 0;
  for (let i = open; i < c.length; i++) {
    if (c[i] === '{') depth++;
    else if (c[i] === '}' && --depth === 0) return i;
  }
  return -1;
}

/** JS/TS function bodies: declarations, block-bodied arrows and method shorthand. */
function jsBlocks(c: string): Block[] {
  const out: Block[] = [];
  const header = /\bfunction\s*\*?\s*(\w*)\s*\([^)]*\)[^{;]*\{|\b(\w+)\s*[:=]\s*(?:async\s*)?(?:function\s*\w*\s*)?\([^)]*\)\s*(?::\s*[^={]+)?(?:=>)?\s*\{|^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{/gm;
  for (const m of c.matchAll(header)) {
    const open = m.index! + m[0].length - 1;
    const close = matchBrace(c, open);
    if (close !== -1) out.push({ name: m[1] || m[2] || m[3] || '', start: open, end: close });
  }
  return out;
}

/** Python function bodies: from `def` to the next line indented at or below its level. */
function pyBlocks(c: string): Block[] {
  const out: Block[] = [];
  for (const m of c.matchAll(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm)) {
    const indent = m[1].length;
    let end = c.length;
    const rest = c.slice(m.index! + m[0].length);
    const next = rest.split('\n').slice(1);
    let offset = m.index! + m[0].length + rest.indexOf('\n') + 1;
    for (const line of next) {
      if (line.trim() && (line.length - line.trimStart().length) <= indent) { end = offset; break; }
      offset += line.length + 1;
    }
    out.push({ name: m[2], start: m.index!, end });
  }
  return out;
}

function enclosing(blocks: Block[], idx: number, c: string): Block {
  const inside = blocks.filter((b) => b.start <= idx && idx <= b.end);
  return inside.sort((a, b) => (a.end - a.start) - (b.end - b.start))[0] ?? { name: '', start: 0, end: c.length };
}

function checkUnverifiedTokenDecode(path: string, c: string, add: (h: Hit) => void) {
  const js = JS.test(path);
  const py = PY.test(path);
  if (!js && !py) return;
  if ((js ? JS_VERIFY : PY_VERIFY).test(c)) return;
  if (js && (BROWSER.test(c) || (!SERVER_FILE.test(path) && !SERVER_SIGNAL.test(c)))) return;
  if (py && !PY_SERVER_SIGNAL.test(c)) return;
  const [split, b64, parse] = js ? [JS_SPLIT, JS_B64, JS_PARSE] : [PY_SPLIT, PY_B64, PY_PARSE];
  if (!split.test(c) || !b64.test(c) || !parse.test(c)) return;

  const blocks = js ? jsBlocks(c) : pyBlocks(c);
  const seen = new Set<string>();
  for (const m of c.matchAll(new RegExp(b64.source, 'g'))) {
    const block = enclosing(blocks, m.index!, c);
    const body = c.slice(block.start, block.end + 1);
    if (!split.test(body) || !parse.test(body)) continue;
    // The decoded value must come from the split token (not some other base64 blob in the same function)
    const call = c.slice(m.index!, c.indexOf('\n', m.index!) === -1 ? c.length : c.indexOf('\n', m.index!));
    if (!decodesSplitPart(call, splitNames(body))) continue;
    // Identity use: claims read here, or the decoded payload handed back to the caller from an auth-named helper.
    // Reading only `exp` to refresh one's own token in time is not an auth decision.
    if (!IDENTITY.test(body) && !(AUTH_NAME.test(block.name) && returnsPayload(body, js))) continue;
    const key = `${block.start}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const fn = block.name ? `\`${block.name}()\`` : 'This code';
    add({
      ruleId: 30401, code: 'MG-01', severity: 'CRITICAL', lineIdx: lineAt(c, m.index!),
      title: 'Token Is Decoded by Hand and Trusted Without a Signature Check',
      why: `${fn} splits the token on "." and base64-decodes the payload, but nothing in this file checks the signature. Anyone can write a token with any user id or role in it, and this code will believe it.`,
      fix: js
        ? 'Verify the token before reading claims: jwtVerify() from jose, jwt.verify() from jsonwebtoken, or your auth provider\'s getUser(). Never trust a payload you decoded yourself.'
        : 'Verify the token before reading claims: jwt.decode(token, key, algorithms=["HS256"]) from PyJWT verifies the signature, or use your auth provider\'s SDK.',
    });
  }
}

export function evaluateMissingGuardRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const c = cleanContent;
  if (!c || c.length > 400_000 || SKIP.test(path)) return { findings, logs };
  const hits: Hit[] = [];
  checkUnverifiedTokenDecode(path, c, (h) => hits.push(h));

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `mg${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'Broken Authentication',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Followed the token handling in ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false,
    });
    logs.push(`[${ts}] [MISSING-GUARD] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
