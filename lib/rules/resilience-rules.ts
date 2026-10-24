/**
 * Retries that hammer a failing dependency (RES-01..02, Rule IDs 30341-30342). When an outside service slows down
 * or errors, a client that retries at once multiplies its own load on it; with many clients that is the retry
 * storm a circuit breaker or backoff exists to stop. Advice only (LOW): the code works until the dependency fails.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner/types';
import { SKIP } from './logic-gemini-rules';

interface Hit { ruleId: number; code: string; title: string; lineIdx: number; why: string; fix: string }

/** An outbound HTTP call: fetch, axios, got, ky, superagent, requests, httpx, aiohttp. */
const OUTBOUND_JS = /\b(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|superagent\.\w+|\w+Client\.(?:get|post|put|patch|delete|request))\s*\(/;
const OUTBOUND_PY = /\b(?:requests|httpx|session|client)\.(?:get|post|put|patch|delete|request)\s*\(|\baiohttp\b[\s\S]{0,80}\.(?:get|post)\s*\(/;
/** Anything that waits between attempts or hands retrying to a library that does. */
const WAITS = /setTimeout|\bsleep\s*\(|\bdelay\s*\(|backoff|\bwait\w*\s*\(|p-retry|pRetry|async-retry|\bretry\s*\(|exponential|jitter|tenacity|time\.sleep|asyncio\.sleep|setInterval/i;

/** Body of the `{ ... }` block that starts at or after `from` (index into content), or null. */
function braceBody(c: string, from: number): { body: string; end: number } | null {
  const open = c.indexOf('{', from);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < c.length && i - open < 6000; i++) {
    if (c[i] === '{') depth++;
    else if (c[i] === '}' && --depth === 0) return { body: c.slice(open + 1, i), end: i };
  }
  return null;
}

/** Lines indented deeper than the header line `idx` (a Python block). */
function pyBlock(lines: string[], idx: number): string {
  const indent = lines[idx].length - lines[idx].trimStart().length;
  const out: string[] = [];
  for (let j = idx + 1; j < lines.length && out.length < 80; j++) {
    const l = lines[j];
    if (l.trim() && l.length - l.trimStart().length <= indent) break;
    out.push(l);
  }
  return out.join('\n');
}

const lineAt = (c: string, index: number) => c.slice(0, index).split('\n').length - 1;

export function evaluateResilienceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const c = cleanContent;
  if (!c || c.length > 400_000 || SKIP.test(path) || /(?:^|\/)(?:scripts?|bin|tools)\//i.test(path)) return { findings, logs };
  const hits: Hit[] = [];
  const isJs = /\.[cm]?[jt]sx?$/i.test(path);
  const isPy = /\.py$/i.test(path);

  // RES-01: retry loop around an outbound call with nothing waiting between attempts
  const retryWhy = 'The loop retries the call as soon as it fails. When the service is slow or down, every client does the same, so the retries add load right when it can least take it and the outage lasts longer.';
  if (isJs && OUTBOUND_JS.test(c)) {
    // A retry loop: its counter or bound is about attempts / retries (not pages, redirect hops or items), and a
    // literal bound allows at least 3 attempts (one immediate retry is common and cheap)
    for (const m of c.matchAll(/\b(?:for\s*\(\s*(?:let|var)\s+(\w+)\s*=\s*\d+\s*;[^;)]*<(=?)\s*(\d+|\w*(?:retr|attempt|tries)\w*)[^)]*\)|while\s*\(\s*(?:!\s*\w+\s*&&\s*)?\w*(?:attempt|retr|tries)\w*\s*(?:<(=?)\s*(\d+)|[^)]*)\))/gi)) {
      const counter = m[1] ?? '';
      const bound = m[3] ?? m[5];
      if (m[1] && !/^(?:i|n|attempt\w*|retr\w*|tr(?:y|ies)\w*|tries)$/i.test(counter)) continue;
      if (bound && /^\d+$/.test(bound) && Number(bound) + ((m[2] ?? m[4]) ? 1 : 0) < 3) continue;
      const block = braceBody(c, m.index! + m[0].length);
      if (!block) continue;
      const b = block.body;
      // A retry: the call sits in try, success leaves the loop, failure is caught and the loop goes round again
      if (!OUTBOUND_JS.test(b) || !/\btry\s*\{/.test(b) || !/\bcatch\b/.test(b) || !/\b(?:return|break)\b/.test(b) || WAITS.test(b)) continue;
      hits.push({ ruleId: 30341, code: 'RES-01', title: 'Outside Call Retried in a Tight Loop With No Backoff', lineIdx: lineAt(c, m.index!), why: retryWhy,
        fix: 'Wait between attempts with exponential backoff and jitter (await sleep(2 ** attempt * 200 + Math.random() * 100)), or use p-retry / a circuit breaker such as opossum, and stop retrying errors that will not go away (4xx).' });
    }
  }
  if (isPy && OUTBOUND_PY.test(c)) {
    lines.forEach((l, i) => {
      const loop = /^\s*(?:for\s+(\w+)\s+in\s+range\s*\(\s*(?:\d+\s*,\s*)?([^)]*)\)|while\s+(?:not\s+\w+\s+and\s+)?\w*(?:attempt|retr|tries)\w*)/i.exec(l);
      // The raw line keeps its comment: `for _ in range(10):  # max redirect hops`
      if (!loop || /page|hop|redirect/i.test(lines[i] ?? '')) return;
      // Same as JS: an attempt / retry counter (or _ with a retry-sized bound), at least 3 attempts when the bound is a literal
      if (loop[1] && !/^(?:_\w*|i|n|attempt\w*|retr\w*|tr(?:y|ies)\w*)$/i.test(loop[1])) return;
      if (loop[2] !== undefined && (/page|hop|redirect|item|row|batch|chunk/i.test(loop[2]) || (/^\d+$/.test(loop[2].trim()) && Number(loop[2]) < 3) || !/^\s*(?:\d+|\w*(?:retr|attempt|tries)\w*)\s*$/i.test(loop[2]))) return;
      const b = pyBlock(lines, i);
      if (!OUTBOUND_PY.test(b) || !/^\s*try\s*:/m.test(b) || !/^\s*except\b/m.test(b) || !/\b(?:return|break)\b/.test(b) || WAITS.test(b)) return;
      hits.push({ ruleId: 30341, code: 'RES-01', title: 'Outside Call Retried in a Tight Loop With No Backoff', lineIdx: i, why: retryWhy,
        fix: 'Sleep with exponential backoff and jitter between attempts (time.sleep(2 ** attempt + random.random())), or use tenacity (@retry(wait=wait_exponential_jitter())), and stop retrying 4xx errors.' });
    });
  }

  // RES-02: axios-retry without retryDelay retries immediately (its default delay is zero)
  if (isJs && /\baxiosRetry\s*\(/.test(c)) {
    for (const m of c.matchAll(/\baxiosRetry\s*\(\s*[\w.]+\s*(?:,\s*\{|\))/g)) {
      const opts = m[0].endsWith('{') ? braceBody(c, m.index! + m[0].length - 1)?.body ?? '' : '';
      if (/\bretryDelay\b/.test(opts)) continue;
      hits.push({ ruleId: 30342, code: 'RES-02', title: 'axios-retry Retries With No Delay', lineIdx: lineAt(c, m.index!),
        why: 'axios-retry waits 0 ms between attempts unless retryDelay is set, so a failing service gets every retry at once from every client.',
        fix: 'Pass retryDelay: axiosRetry.exponentialDelay (it adds jitter), and keep retries small.' });
    }
  }

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `res${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'INFRA_DATABASE',
      title: `${h.code}: ${h.title}`,
      severity: 'LOW',
      category: 'Resilience',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Read the retry logic at ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false,
    });
    logs.push(`[${ts}] [RESILIENCE] LOW: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
