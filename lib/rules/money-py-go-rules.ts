/**
 * Payment integrity rules for Python and Go backends (MONEY-01..04, Rule IDs 33001-33004).
 * The JS/TS versions (FINTECH-04 unsigned payment webhook, SAAS-04 client-set amount) do not read
 * Go request bodies or Python dict/keyword syntax, so the same two money bugs get their own checks here.
 * They report as suggestions until the benchmark proves them (they are not in canBlockRelease).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { CALLER_AUTH } from './shared/stack-signals';

interface Hit { ruleId: number; code: string; title: string; category: string; lineIdx: number; why: string; fix: string }

const PAYMENT_PROVIDER = /\bstripe\b|stripe-go|paddle|lemonsqueezy|lemon_squeezy|paypal|razorpay|braintree|mollie|paystack|polar\.sh|polar_sdk|checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid/i;
const TEST_PATH = /(?:^|\/)(?:tests?|spec|__tests__|testdata|fixtures?|mocks?)\/|_test\.(?:go|py)$|(?:^|\/)test_[^/]*\.py$|conftest\.py$/i;

const PY_WEBHOOK_CONTEXT = /@\w+\.(?:post|route|api_route)\(\s*['"][^'"]*webhook|\bdef\s+\w*webhook\w*\s*\(|path\(\s*['"][^'"]*webhook/i;
const PY_READS_BODY = /\brequest\.(?:body\b|data\b|get_data\s*\(|get_json\s*\(|json\b|POST\b)|await\s+request\.(?:body|json)\s*\(/;
const PY_VERIFIED = /construct_event|verify_webhook|verify_signature|validate_event|unwrap\s*\(|compare_digest|WebhookSignature|svix|standardwebhooks|\.verify\s*\(/i;

const GO_WEBHOOK_CONTEXT = /["'`][^"'`\n]*webhook[^"'`\n]*["'`]|\bfunc\s+(?:\([^)]*\)\s*)?\w*[Ww]ebhook\w*\s*\(/;
const GO_READS_BODY = /\bio(?:util)?\.ReadAll\(\s*\w+\.(?:Request\.)?Body|json\.NewDecoder\(\s*\w+\.(?:Request\.)?Body|\.(?:ShouldBindJSON|BindJSON|GetRawData|BodyParser)\s*\(|\bc\.Body\(\)/;
const GO_VERIFIED = /webhook\.ConstructEvent|ConstructEventWithOptions|ValidatePayload|hmac\.Equal|subtle\.ConstantTimeCompare|[Vv]erify[A-Za-z]*Signature|svix|standardwebhooks/;

export function evaluateMoneyPyGoRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const isPy = /\.py$/i.test(path);
  const isGo = /\.go$/i.test(path);
  if ((!isPy && !isGo) || TEST_PATH.test(path) || /(?:^|\/)(?:vendor|site-packages|\.venv|venv)\//.test(path)) return { findings, logs };
  if (!PAYMENT_PROVIDER.test(cleanContent)) return { findings, logs };
  const hits: Hit[] = [];
  const firstLine = (re: RegExp) => lines.findIndex((l) => re.test(l));

  // MONEY-01 / MONEY-02: payment webhook that reads the body and never checks the provider's signature
  const webhookPath = /webhook/i.test(path);
  if (isPy && (webhookPath || PY_WEBHOOK_CONTEXT.test(cleanContent)) && PY_READS_BODY.test(cleanContent) && !PY_VERIFIED.test(cleanContent) && !CALLER_AUTH.test(cleanContent)) {
    hits.push({
      ruleId: 33001, code: 'MONEY-01', category: 'Payment Webhook Security', lineIdx: firstLine(PY_READS_BODY),
      title: 'Payment Webhook Processed Without Signature Verification (Python)',
      why: 'The handler trusts the posted event without checking the provider signature, so anyone who finds the URL can send "payment succeeded" and get the order or credits for free.',
      fix: 'Verify the raw body with the provider SDK before acting on it, e.g. stripe.Webhook.construct_event(payload, request.headers["Stripe-Signature"], endpoint_secret), and return 400 when it fails.'
    });
  }
  if (isGo && (webhookPath || GO_WEBHOOK_CONTEXT.test(cleanContent)) && GO_READS_BODY.test(cleanContent) && !GO_VERIFIED.test(cleanContent)) {
    hits.push({
      ruleId: 33002, code: 'MONEY-02', category: 'Payment Webhook Security', lineIdx: firstLine(GO_READS_BODY),
      title: 'Payment Webhook Processed Without Signature Verification (Go)',
      why: 'The handler decodes the posted event without checking the provider signature, so anyone who finds the URL can send "payment succeeded" and get the order or credits for free.',
      fix: 'Read the raw body and verify it first, e.g. webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), endpointSecret), and return 400 when it fails.'
    });
  }

  // MONEY-03: Python payment amount taken from the request
  if (isPy && /\.(?:Session|PaymentIntent|Charge|InvoiceItem|Price)\.create\s*\(/.test(cleanContent)) {
    const requestVars = new Set<string>();
    for (const m of cleanContent.matchAll(/\b(\w+)\s*=\s*(?:await\s+)?request\.(?:json|data|form|POST|args|get_json)\b/g)) requestVars.add(m[1]);
    for (const m of cleanContent.matchAll(/\bdef\s+\w+\s*\(([^)]*)\)/g)) {
      for (const p of m[1].matchAll(/\b(\w+)\s*:\s*[A-Z]\w*(?:Request|In|Body|Payload|Create|Schema)\b/g)) requestVars.add(p[1]);
    }
    const vars = [...requestVars].map((v) => v.replace(/\W/g, '')).filter(Boolean);
    const source = [String.raw`request\.(?:json|data|form|POST|args)\s*(?:\[|\.get\()`, String.raw`request\.get_json\(\)\s*(?:\[|\.get\()`]
      .concat(vars.length ? [String.raw`\b(?:${vars.join('|')})\s*(?:\[|\.get\(|\.)`] : []).join('|');
    const amountFromRequest = new RegExp(String.raw`['"]?\b(?:unit_amount|amount)['"]?\s*[:=]\s*(?:int|float|Decimal|round)?\(?\s*(?:${source})`);
    const idx = firstLine(amountFromRequest);
    if (idx !== -1) {
      hits.push({
        ruleId: 33003, code: 'MONEY-03', category: 'Revenue Protection', lineIdx: idx,
        title: 'Payment Amount Controlled by the Client (Python)',
        why: 'The amount charged comes from the request body, so a customer can edit it in the browser and pay one cent for anything.',
        fix: 'Accept only a product or plan id from the client and look the amount up on the server (a PRICES table or the provider price id), never from the request.'
      });
    }
  }

  // MONEY-04: Go payment amount taken from the decoded request
  if (isGo && /stripe\.\w*(?:CheckoutSession|PaymentIntent|Charge|Price|InvoiceItem)\w*Params\b/.test(cleanContent)) {
    const decoded = new Set<string>();
    for (const m of cleanContent.matchAll(/json\.NewDecoder\(\s*\w+\.(?:Request\.)?Body\s*\)\.Decode\(\s*&(\w+)/g)) decoded.add(m[1]);
    for (const m of cleanContent.matchAll(/\.(?:ShouldBindJSON|BindJSON|BodyParser|Bind)\(\s*&(\w+)/g)) decoded.add(m[1]);
    if (decoded.size) {
      const amountFromBody = new RegExp(String.raw`\b(?:Amount|UnitAmount)\s*:\s*stripe\.Int64\(\s*(?:int64\(\s*)?(?:${[...decoded].join('|')})\.\w+`);
      const idx = firstLine(amountFromBody);
      if (idx !== -1) {
        hits.push({
          ruleId: 33004, code: 'MONEY-04', category: 'Revenue Protection', lineIdx: idx,
          title: 'Payment Amount Controlled by the Client (Go)',
          why: 'The amount charged comes from the decoded request body, so a customer can change it and pay one cent for anything.',
          fix: 'Decode only a product or plan id from the request and look the amount up on the server before building the Stripe params.'
        });
      }
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx >= 0 ? h.lineIdx + 1 : 1;
    findings.push({
      id: `money${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: 'HIGH',
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MONEY] HIGH: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
