/**
 * Payment integrity rules for Java/Kotlin (Spring), C# (ASP.NET), PHP (Laravel) and Ruby (Rails)
 * (MONEY-05..12, Rule IDs 33005-33012). Same two money bugs as MONEY-01..04 for Python and Go:
 * a payment webhook that acts on the posted event without checking the provider signature, and a
 * checkout amount read straight from the request. Suggestions until the benchmark proves them.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

type Lang = 'jvm' | 'csharp' | 'php' | 'ruby';
interface Hit { rule: { ruleId: number; title: string }; category: string; lineIdx: number; why: string; fix: string }

const PAYMENT_PROVIDER = /\bstripe\b|com\.stripe|paddle|lemonsqueezy|lemon_squeezy|paypal|razorpay|braintree|mollie|paystack|cashier|checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid/i;
const TEST_PATH = /(?:^|\/)(?:tests?|spec|specs|__tests__|testdata|fixtures?|mocks?|src\/test)\/|(?:Tests?|Spec)\.(?:java|kt|cs|php)$|_spec\.rb$|_test\.rb$/i;

const LANG: Record<Lang, RegExp> = { jvm: /\.(?:java|kt)$/i, csharp: /\.cs$/i, php: /\.php$/i, ruby: /\.rb$/i };

interface RuleMeta { ruleId: number; title: string; severity: 'HIGH' }
/** Written out per rule so the rule inventory (scripts/rule-audit.ts) picks each one up. */
const RULES: Record<Lang, { webhook: RuleMeta; amount: RuleMeta }> = {
  jvm: {
    webhook: { ruleId: 33005, title: 'MONEY-05: Payment Webhook Processed Without Signature Verification (Java/Kotlin)', severity: 'HIGH' },
    amount: { ruleId: 33006, title: 'MONEY-06: Payment Amount Controlled by the Client (Java/Kotlin)', severity: 'HIGH' },
  },
  csharp: {
    webhook: { ruleId: 33007, title: 'MONEY-07: Payment Webhook Processed Without Signature Verification (C#)', severity: 'HIGH' },
    amount: { ruleId: 33008, title: 'MONEY-08: Payment Amount Controlled by the Client (C#)', severity: 'HIGH' },
  },
  php: {
    webhook: { ruleId: 33009, title: 'MONEY-09: Payment Webhook Processed Without Signature Verification (PHP)', severity: 'HIGH' },
    amount: { ruleId: 33010, title: 'MONEY-10: Payment Amount Controlled by the Client (PHP)', severity: 'HIGH' },
  },
  ruby: {
    webhook: { ruleId: 33011, title: 'MONEY-11: Payment Webhook Processed Without Signature Verification (Ruby)', severity: 'HIGH' },
    amount: { ruleId: 33012, title: 'MONEY-12: Payment Amount Controlled by the Client (Ruby)', severity: 'HIGH' },
  },
};

const WEBHOOK_CONTEXT: Record<Lang, RegExp> = {
  jvm: /@(?:Post|Request)Mapping\([^)]*webhook/i,
  csharp: /\[(?:HttpPost|Route)\(\s*"[^"]*webhook/i,
  php: /function\s+\w*webhook\w*\s*\(|Route::post\(\s*['"][^'"]*webhook/i,
  ruby: /\bdef\s+\w*webhook\w*|\bpost\s+['"][^'"]*webhook/i,
};
const READS_BODY: Record<Lang, RegExp> = {
  jvm: /@RequestBody\b|getReader\s*\(\)|getInputStream\s*\(\)/,
  csharp: /Request\.Body\b|ReadToEndAsync\s*\(|\[FromBody\]/,
  php: /\$request->(?:all|input|getContent|json|get|post)\s*\(|php:\/\/input|\$_POST\[/,
  ruby: /request\.body\.read|request\.raw_post|\bparams\[|\bparams\.(?:require|permit|fetch|dig)\b|JSON\.parse\(\s*request/,
};
const VERIFIED: Record<Lang, RegExp> = {
  jvm: /constructEvent\s*\(|Mac\.getInstance|HmacUtils|MessageDigest\.isEqual|[Vv]erify\w*Signature|Stripe-Signature/,
  csharp: /ConstructEvent\s*\(|HMACSHA256|FixedTimeEquals|[Vv](?:erify|alidate)\w*Signature|Stripe-Signature/,
  php: /constructEvent\s*\(|hash_equals|hash_hmac|verifyHeader|VerifyWebhookSignature|extends\s+(?:Cashier)?WebhookController|Stripe-Signature|HTTP_STRIPE_SIGNATURE/i,
  ruby: /construct_event|secure_compare|OpenSSL::HMAC|verify\w*signature|StripeEvent|Stripe-Signature|HTTP_STRIPE_SIGNATURE/i,
};
const FIX_WEBHOOK: Record<Lang, string> = {
  jvm: 'Verify the raw body first, e.g. Webhook.constructEvent(payload, request.getHeader("Stripe-Signature"), endpointSecret), and return 400 when it throws.',
  csharp: 'Verify the raw body first, e.g. EventUtility.ConstructEvent(json, Request.Headers["Stripe-Signature"], endpointSecret), and return 400 when it throws.',
  php: 'Verify the raw body first, e.g. \\Stripe\\Webhook::constructEvent($payload, $request->header("Stripe-Signature"), $endpointSecret) (or extend Cashier\'s WebhookController), and return 400 when it fails.',
  ruby: 'Verify the raw body first, e.g. Stripe::Webhook.construct_event(request.body.read, request.env["HTTP_STRIPE_SIGNATURE"], endpoint_secret), and return 400 when it raises.',
};
const PAYMENT_CREATE: Record<Lang, RegExp> = {
  jvm: /PaymentIntentCreateParams|SessionCreateParams|ChargeCreateParams|PriceCreateParams/,
  csharp: /PaymentIntentCreateOptions|SessionLineItemPriceDataOptions|ChargeCreateOptions|PriceCreateOptions/,
  php: /PaymentIntent::create|Session::create|Charge::create|paymentIntents->create|checkout->sessions->create|charges->create/,
  ruby: /Stripe::(?:PaymentIntent|Checkout::Session|Charge|InvoiceItem|Price)\.create/,
};

/** Names of variables that hold the request body, per language. */
function requestVars(lang: Lang, content: string): string[] {
  const out = new Set<string>();
  const add = (re: RegExp) => { for (const m of content.matchAll(re)) out.add(m[1]); };
  if (lang === 'jvm') { add(/@RequestBody\s+(?:@\w+\s+)*(?:final\s+)?[\w<>,.?\s]+?\s+(\w+)\s*[,)]/g); add(/@RequestBody\s+(?:@\w+\s+)*(\w+)\s*:/g); }
  if (lang === 'csharp') add(/\[FromBody\]\s*[\w<>.?]+\s+(\w+)/g);
  if (lang === 'php') add(/(\$\w+)\s*=\s*(?:\$request->(?:all|input|json|validated)\s*\(|json_decode\(\s*@?file_get_contents\(\s*['"]php:\/\/input)/g);
  return [...out];
}

function amountPattern(lang: Lang, vars: string[]): RegExp | null {
  const v = vars.map((x) => x.replace(/\$/g, '\\$')).join('|');
  if (lang === 'jvm') return vars.length ? new RegExp(String.raw`\.set(?:Unit)?Amount\(\s*(?:Long\.valueOf\(\s*|\(long\)\s*)?(?:${v})\.(?:get\w*(?:Amount|Price|Total)\w*\s*\(\)|\w*(?:amount|price|total)\w*)`, 'i') : null;
  if (lang === 'csharp') return vars.length ? new RegExp(String.raw`\b(?:Unit)?Amount\s*=\s*(?:\(long\)\s*)?(?:${v})\.\w*(?:Amount|Price|Total)\w*`) : null;
  if (lang === 'php') return new RegExp(String.raw`['"](?:unit_)?amount['"]\s*=>\s*(?:\(int\)\s*|intval\(\s*)?(?:\$request->(?:input|get|post)\(\s*['"]\w+['"]|\$request->(?:amount|price|total)\b|\$_POST\[${v ? `|(?:${v})\[` : ''})`);
  return /\b(?:unit_)?amount:\s*(?:Integer\(\s*|\(?)?params(?:\[|\.require|\.fetch|\.dig)|['"](?:unit_)?amount['"]\s*=>\s*params\[/;
}

export function evaluateMoneyPolyglotRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const lang = (Object.keys(LANG) as Lang[]).find((l) => LANG[l].test(path));
  if (!lang || TEST_PATH.test(path) || /(?:^|\/)(?:vendor|node_modules|build|target|bin|obj)\//.test(path)) return { findings, logs };
  if (!PAYMENT_PROVIDER.test(cleanContent)) return { findings, logs };
  const hits: Hit[] = [];
  const firstLine = (re: RegExp) => lines.findIndex((l) => re.test(l));

  if ((/webhook/i.test(path) || WEBHOOK_CONTEXT[lang].test(cleanContent)) && READS_BODY[lang].test(cleanContent) && !VERIFIED[lang].test(cleanContent)) {
    hits.push({
      rule: RULES[lang].webhook, category: 'Payment Webhook Security', lineIdx: firstLine(READS_BODY[lang]),
      why: 'The handler trusts the posted event without checking the provider signature, so anyone who finds the URL can send "payment succeeded" and get the order or credits for free.',
      fix: FIX_WEBHOOK[lang],
    });
  }

  if (PAYMENT_CREATE[lang].test(cleanContent)) {
    const pattern = amountPattern(lang, requestVars(lang, cleanContent));
    const idx = pattern ? firstLine(pattern) : -1;
    if (idx !== -1) {
      hits.push({
        rule: RULES[lang].amount, category: 'Revenue Protection', lineIdx: idx,
        why: 'The amount charged comes from the request body, so a customer can change it and pay one cent for anything.',
        fix: 'Accept only a product or plan id from the client and look the amount up on the server (a price table or the provider price id), never from the request.',
      });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx >= 0 ? h.lineIdx + 1 : 1;
    findings.push({
      id: `money${h.rule.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.rule.ruleId,
      type: 'SECURITY',
      title: h.rule.title,
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
    logs.push(`[${ts}] [MONEY] HIGH: ${h.rule.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
