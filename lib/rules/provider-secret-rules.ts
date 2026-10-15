/**
 * Secret keys for SaaS providers small teams adopted after the first secret pack
 * (SEC-SECRET-188.., Rule IDs 5188-5299): LLM observability, vector DBs, realtime, notifications,
 * feature flags, background jobs. Keys with a documented prefix match on the prefix alone; keys
 * without one (plain hex, JWTs) only match when assigned to the provider's own variable name,
 * so a random hash elsewhere never fires.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { isDummyPlaceholder, maskSecretInLine } from './secrets-rules';

export interface ProviderSecretRuleResult {
  findings: Finding[];
  logs: string[];
}

interface ProviderSecret {
  id: number;
  provider: string;
  what: string;
  patterns: RegExp[];
  /** The file must mention the provider (for shapes that are not unique on their own). */
  fileHint?: RegExp;
  severity?: Finding['severity'];
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

/** NAME = "value" / NAME: 'value' / "NAME": "value" for the provider's own variable names. */
const assign = (names: string, value: string) =>
  new RegExp(`\\b(?:${names})\\b["']?\\s*[:=]\\s*["'\`](${value})["'\`]`, 'i');

const PROVIDERS: ProviderSecret[] = [
  { id: 5188, provider: 'Fal.ai', what: 'API key (key_id:key_secret)', patterns: [new RegExp(`\\b${UUID}:[0-9a-f]{32}\\b`)], fileHint: /\bfal\b|FAL_KEY|@fal-ai/i },
  { id: 5189, provider: 'Langfuse', what: 'secret key (sk-lf-…)', patterns: [new RegExp(`\\bsk-lf-${UUID}\\b`)] },
  { id: 5190, provider: 'Pinecone', what: 'API key (pcsk_…)', patterns: [/\bpcsk_[A-Za-z0-9]{4,12}_[A-Za-z0-9]{30,}\b/] },
  { id: 5191, provider: 'Convex', what: 'deploy key', patterns: [/\b(?:prod|preview|dev):[a-z0-9]+(?:-[a-z0-9]+)+\|[A-Za-z0-9+/=_-]{40,}/] },
  { id: 5192, provider: 'AssemblyAI', what: 'API key', patterns: [assign('ASSEMBLY_?AI_API_KEY', '[0-9a-f]{32}'), /new\s+AssemblyAI\(\s*\{\s*apiKey\s*:\s*["'`][0-9a-f]{32}["'`]/] },
  { id: 5193, provider: 'Dub', what: 'API key (dub_…)', patterns: [/\bdub_[A-Za-z0-9]{24,}\b/] },
  { id: 5194, provider: 'LiveKit', what: 'API secret', patterns: [assign('LIVEKIT_API_SECRET', '[A-Za-z0-9]{30,}'), /new\s+(?:RoomServiceClient|AccessToken|EgressClient|IngressClient|SipClient)\([^)]*["'`]API[A-Za-z0-9]{10,14}["'`]\s*,\s*["'`][A-Za-z0-9]{30,}["'`]/] },
  { id: 5195, provider: 'Novu', what: 'secret key', patterns: [assign('NOVU_(?:SECRET_KEY|API_KEY)', '[0-9a-f]{32}'), /new\s+Novu\(\s*["'`][0-9a-f]{32}["'`]/] },
  { id: 5196, provider: 'Unkey', what: 'root key (unkey_…)', patterns: [/\bunkey_[A-Za-z0-9]{20,}\b/] },
  { id: 5197, provider: 'Lemon Squeezy', what: 'API key', patterns: [assign('LEMON_?SQUEEZY_API_KEY|LS_API_KEY', 'eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}')] },
  { id: 5198, provider: 'Plunk', what: 'secret key', patterns: [assign('PLUNK_(?:SECRET_)?(?:API_)?KEY', 'sk_[A-Za-z0-9]{20,}')] },
  { id: 5199, provider: 'LangSmith', what: 'API key (lsv2_…)', patterns: [/\blsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}\b/] },
  { id: 5200, provider: 'Loops', what: 'API key', patterns: [assign('LOOPS_API_KEY', '[0-9a-f]{32}')] },
  { id: 5201, provider: 'Deepgram', what: 'API key', patterns: [assign('DEEPGRAM_API_KEY', '[0-9a-f]{40}')] },
  { id: 5203, provider: 'PostHog', what: 'personal API key (phx_…)', patterns: [/\bphx_[A-Za-z0-9]{40,}\b/] },
  { id: 5204, provider: 'Inngest', what: 'signing key', patterns: [/\bsignkey-(?:prod|test|branch)-[0-9a-f]{64}\b/] },
  { id: 5206, provider: 'Helicone', what: 'API key (sk-helicone-…)', patterns: [/\bsk-helicone-(?:eu-|cp-)?[a-z0-9]{7}(?:-[a-z0-9]{7}){3}\b/] },
  { id: 5207, provider: 'Knock', what: 'secret API key', patterns: [assign('KNOCK_(?:SECRET_)?API_KEY', 'sk_(?:test_|live_)?[A-Za-z0-9_-]{20,}')] },
  { id: 5208, provider: 'Attio', what: 'API token', patterns: [assign('ATTIO_(?:API_KEY|API_TOKEN|ACCESS_TOKEN)', '[0-9a-f]{64}')] },
  { id: 5210, provider: 'Axiom', what: 'API / personal token (xaat- / xapt-)', patterns: [new RegExp(`\\bxa[ap]t-${UUID}\\b`)] },
  { id: 5211, provider: 'Plain', what: 'API key (plainApiKey_…)', patterns: [/\bplainApiKey_[A-Za-z0-9_-]{20,}/] },
  { id: 5212, provider: 'Courier', what: 'auth token', patterns: [assign('COURIER_(?:AUTH_TOKEN|API_KEY)', 'pk_(?:prod|test)_[A-Za-z0-9]{20,}')] },
  { id: 5213, provider: 'OneSignal', what: 'REST API key (os_v2_…)', patterns: [/\bos_v2_(?:app|org)_[a-z0-9]{40,}\b/] },
  { id: 5214, provider: 'LaunchDarkly', what: 'server-side SDK key (sdk-…)', patterns: [new RegExp(`\\bsdk-${UUID}\\b`)] },
  { id: 5215, provider: 'WorkOS', what: 'API key', patterns: [assign('WORKOS_API_KEY', 'sk_(?:test_|live_)?[A-Za-z0-9]{30,}')] },
  { id: 5216, provider: 'Flagsmith', what: 'server-side environment key (ser.…)', patterns: [/\bser\.[A-Za-z0-9]{22,}\b/], fileHint: /flagsmith/i },
  { id: 5221, provider: 'Postmark', what: 'server token', patterns: [assign('POSTMARK_(?:SERVER_)?(?:API_)?(?:TOKEN|KEY)', UUID)] },
  { id: 5223, provider: 'Sentry', what: 'user auth token (sntryu_…)', patterns: [/\bsntryu_[0-9a-f]{64}\b/] },
  { id: 5225, provider: 'Trigger.dev', what: 'secret key (tr_…)', patterns: [/\btr_(?:dev|prod|stg|preview)_[A-Za-z0-9]{20,}\b/] },
  { id: 5226, provider: 'OpenFGA', what: 'API token / client secret', patterns: [assign('(?:OPEN)?FGA_(?:API_TOKEN|CLIENT_SECRET)', '[A-Za-z0-9_-]{20,}')] },
  { id: 5227, provider: 'Neon', what: 'API key (napi_…)', patterns: [/\bnapi_[a-z0-9]{60,}\b/] },
  { id: 5229, provider: 'Tinybird', what: 'auth token (p.eyJ…)', patterns: [/\bp\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/] },
  { id: 5230, provider: 'Upstash', what: 'Redis REST token', patterns: [assign('UPSTASH_REDIS_REST_TOKEN|KV_REST_API_TOKEN', 'A[A-Za-z0-9]{40,}=*')] },
  { id: 5233, provider: 'Daily', what: 'API key', patterns: [assign('DAILY_API_KEY', '[0-9a-f]{64}')] },
  { id: 5234, provider: 'Ably', what: 'API key (appId.keyId:secret)', patterns: [/["'`][A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{6}:[A-Za-z0-9_+/=-]{30,}["'`]/], fileHint: /\bably\b/i },
  { id: 5248, provider: 'PlanetScale', what: 'service token (pscale_tkn_ / pscale_oauth_)', patterns: [/\bpscale_(?:tkn|oauth)_[A-Za-z0-9_-]{32,}\b/] },
];

/** Docs and fake-key placeholders: x-runs, your_..., <...>, repeated digits or the alphabet in order. */
const PLACEHOLDER = /your[_-]|<[^>]*>|x{6,}|X{6,}|\.\.\.|1234567890|abcdefghij|0{8,}/;

export function evaluateProviderSecretRules(file: CodeFile, lines: string[], content: string, findingCounter: {
  count: number;
}): ProviderSecretRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  if (/(?:^|\/)node_modules\/|\.d\.ts$/i.test(file.path)) return { findings, logs };
  const ts = new Date().toLocaleTimeString();
  for (const p of PROVIDERS) {
    if (p.fileHint && !p.fileHint.test(content)) continue;
    if (!p.patterns.some((re) => re.test(content))) continue;
    const lineIdx = lines.findIndex((l) => p.patterns.some((re) => {
      const m = l.match(re);
      return !!m && !isDummyPlaceholder(l) && !PLACEHOLDER.test(m[1] ?? m[0]);
    }));
    if (lineIdx === -1) continue;
    const lineNum = lineIdx + 1;
    const code = `SEC-SECRET-${p.id - 5000}`;
    const title = `${p.provider} ${p.what} hardcoded`;
    const severity = p.severity ?? 'CRITICAL';
    const re = p.patterns.find((r) => r.test(lines[lineIdx]))!;
    findings.push({
      id: `psecret${p.id}-${Date.now()}-${findingCounter.count++}`,
      ruleId: p.id,
      type: 'SECURITY',
      title: `${code}: ${title}`,
      severity,
      category: 'Secret Isolation',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: maskSecretInLine(lines[lineIdx].trim(), new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, `A ${p.provider} ${p.what} is written into the source. Anyone with read access to the repository or the built bundle can use it.`],
      remediationPrompt: `Revoke this ${p.provider} key in the provider dashboard, issue a new one, and read it from a server-side environment variable instead of the source. (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] 🛑 ${severity}: ${code} ${title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
