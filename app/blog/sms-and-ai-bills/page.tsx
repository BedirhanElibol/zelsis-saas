import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, ScanCta, ZelsisCatches } from '@/components/guides/GuideParts';
import { formatPostDate } from '../posts';

export const metadata: Metadata = {
  title: 'Your SMS and AI Bills Are Part of the Attack Surface - Zelsis Blog',
  description:
    'Endpoints that send an SMS code or call an LLM are billed per request. Without a limit, anyone who finds them can run up the bill. How SMS pumping and free-LLM abuse work, and the fixes.',
};

const PUBLISHED = '2026-10-21';
const H2 = 'text-xl font-semibold text-white';
const SECTION = 'space-y-3 border-t border-white/10 pt-6';

export default function SmsAndAiBillsPost() {
  return (
    <article className="space-y-6">
      <header className="space-y-2">
        <time dateTime={PUBLISHED} className="text-xs font-mono text-zinc-500">{formatPostDate(PUBLISHED)}</time>
        <h1 className="text-3xl font-bold text-white m-0">Your SMS and AI bills are part of the attack surface</h1>
      </header>
      <p className="text-zinc-300">
        Most endpoints cost you almost nothing per call. Two kinds are different. A route that sends a verification code by SMS pays the
        SMS provider for every message, and a route that calls an LLM pays the model provider for every token. If either one can be
        called without a limit, whoever finds it decides how large your bill gets.
      </p>

      <section className={SECTION}>
        <h2 className={H2}>SMS pumping</h2>
        <p className="text-zinc-300">
          A sign-up or login page sends a one-time code to whatever phone number it is given. Attackers point it at premium-rate numbers
          they get a share of the revenue from, and a script requests codes in a loop. Each message is cheap; the volume is not.
        </p>
        <p className="text-zinc-300">
          The best-known case is Twitter. In 2023 Elon Musk said the company was paying about $60 million a year for fake 2FA text
          messages that bots triggered. That is his figure, and it was not independently checked, but carriers and SMS providers
          describe the same pattern (
          <a href="https://gigazine.net/gsc_news/en/20230221-twitter-lost-60-million-dollars-2fa-sms" className="text-emerald-400 hover:text-emerald-300">
            Gigazine, citing Commsrisk
          </a>
          ).
        </p>
        <CodeBlock
          tone="bad"
          label="Anyone can trigger a paid SMS"
          code={`export async function POST(req: Request) {
  const { phone } = await req.json();
  await twilio.verify.v2.services(SID).verifications.create({ to: phone, channel: 'sms' });
  return Response.json({ sent: true });
}`}
        />
        <CodeBlock
          tone="good"
          label="Limited per number and per IP, CAPTCHA first"
          code={`export async function POST(req: Request) {
  const { phone, captchaToken } = await req.json();
  if (!(await verifyTurnstile(captchaToken))) return new Response('captcha', { status: 400 });
  const ip = req.headers.get('x-forwarded-for') ?? 'unknown';
  const [byPhone, byIp] = await Promise.all([smsLimit.limit(\`phone:\${phone}\`), smsLimit.limit(\`ip:\${ip}\`)]);
  if (!byPhone.success || !byIp.success) return new Response('slow down', { status: 429 });
  await twilio.verify.v2.services(SID).verifications.create({ to: phone, channel: 'sms' });
  return Response.json({ sent: true });
}`}
        />
        <p className="text-zinc-300">
          Also turn on your provider&apos;s fraud controls (Twilio Verify has geo permissions and fraud guard) and block country codes
          you do not serve. A limit in code helps; a spend cap at the provider is the backstop.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>An open LLM endpoint is a free LLM for everyone</h2>
        <p className="text-zinc-300">
          The same shape shows up in AI features. A route takes a prompt, calls the model with your API key and streams the answer back.
          Without authentication and a rate limit, that route is a proxy to the model that you pay for. People do find these and use them,
          and long prompts with long answers are the expensive kind.
        </p>
        <CodeBlock
          tone="good"
          label="Who is asking, how often, and how much"
          code={`export async function POST(req: Request) {
  const user = await requireUser(req);                    // no anonymous calls
  const { success } = await aiLimit.limit(user.id);       // per-user rate limit
  if (!success) return new Response('slow down', { status: 429 });
  const { prompt } = await req.json();
  return streamText({ model, prompt: prompt.slice(0, 4000), maxOutputTokens: 800 }).toTextStreamResponse();
}`}
        />
        <p className="text-zinc-300">
          Set a monthly budget or hard limit in the provider console as well. It will not stop abuse, but it caps how much a bad night can
          cost.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Retries multiply it</h2>
        <p className="text-zinc-300">
          A retry loop with no wait between attempts turns one failed call into several paid ones, and when the provider is slow every
          client retries at once. Wait between attempts with exponential backoff and jitter, and stop retrying errors that will not go away.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>What it could cost you</h2>
        <p className="text-zinc-300">
          We do not put a dollar figure on this for you, because it depends on your prices and on how fast your endpoint answers. The
          arithmetic is simple: the price of one request times the requests that get through in a minute, times the minutes before someone
          notices. When Zelsis finds one of these endpoints, the dashboard shows a small calculator next to it; enter your own price and rate
          and it works out an hour and a day of abuse. The numbers stay in your browser.
        </p>
      </section>

      <ZelsisCatches
        rules={[
          { id: 'XL-12', title: 'An endpoint that sends SMS with no rate limit, CAPTCHA or cooldown' },
          { id: 'WAF-02', title: 'A POST route that calls an LLM with no rate limit' },
          { id: 'LLM-COST-06', title: 'An LLM call retried in a loop with no wait between attempts' },
          { id: 'RES-01', title: 'Any outside call retried in a tight loop with no backoff' },
        ]}
      />

      <ScanCta />
    </article>
  );
}
