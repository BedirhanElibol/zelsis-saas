import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, ScanCta } from '@/components/guides/GuideParts';
import { formatPostDate } from '../posts';

export const metadata: Metadata = {
  title: 'Which Keys in a SaaS Stack Can Ship to the Browser - Zelsis Blog',
  description:
    'PostHog, Langfuse, LaunchDarkly and Flagsmith each give you a public key and a secret one with similar names. How to tell them apart, and which newer keys (Pinecone, Convex, Inngest, LangSmith, Neon) must stay on the server.',
};

const PUBLISHED = '2026-10-16';
const H2 = 'text-xl font-semibold text-white';
const SECTION = 'space-y-3 border-t border-white/10 pt-6';

export default function PublicVsSecretKeysPost() {
  return (
    <article className="space-y-6">
      <header className="space-y-2">
        <time dateTime={PUBLISHED} className="text-xs font-mono text-zinc-500">{formatPostDate(PUBLISHED)}</time>
        <h1 className="text-3xl font-bold text-white m-0">Which keys in a SaaS stack can ship to the browser</h1>
      </header>
      <p className="text-zinc-300">
        Most teams know the classic pair. A Stripe <code>pk_live_</code> key belongs in the frontend and an <code>sk_live_</code> key
        never does. The Supabase anon key is public and the service role key is not. The tools many teams added more recently follow the same idea, but the names are less obvious, and several of them hand you both kinds of key on the same settings
        page.
      </p>
      <p className="text-zinc-300">
        This week we added checks for these newer keys. Writing them meant sorting out, provider by provider, which key a browser may
        hold. Here is that list.
      </p>

      <section className={SECTION}>
        <h2 className={H2}>Same product, two keys</h2>
        <p className="text-zinc-300">
          These providers ship a key that is designed to be public next to one that gives full access. The prefixes differ by a letter or
          two.
        </p>
        <CodeBlock
          label="Public: fine in client code"
          code={`posthog.init('phc_...')                 // PostHog project API key: send events only
new Langfuse({ publicKey: 'pk-lf-...' })   // Langfuse public key
LDClient.initialize('<client-side ID>')    // LaunchDarkly client-side ID
flagsmith.init({ environmentID: '...' })   // Flagsmith client-side environment key`}
        />
        <CodeBlock
          tone="bad"
          label="Secret: server only"
          code={`phx_...        // PostHog personal API key: reads your analytics data and changes settings, within its scopes
sk-lf-...      // Langfuse secret key: reads all traces, including prompts and user input
sdk-...        // LaunchDarkly server-side SDK key: downloads every flag rule and segment
ser.<key>      // Flagsmith server-side environment key: downloads the full environment, segment rules included`}
        />
        <p className="text-zinc-300">
          The easy mistake is copying the wrong one into a <code>NEXT_PUBLIC_</code> or <code>VITE_</code> variable because both are
          labelled &quot;API key&quot; in the dashboard. Anything with those prefixes ends up in the JavaScript bundle, readable by every
          visitor.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Keys with no public twin</h2>
        <p className="text-zinc-300">
          These have no browser-safe version. If one shows up in client code or in the repository, treat it as leaked.
        </p>
        <CodeBlock
          tone="bad"
          code={`pcsk_...          // Pinecone: read, overwrite or delete your vector indexes
prod:name|...     // Convex deploy key: push new backend code to your deployment
signkey-prod-...  // Inngest signing key: send requests your app accepts as coming from Inngest
lsv2_pt_...       // LangSmith: read every traced prompt and response
napi_...          // Neon API key: manage projects, branches and databases
tr_prod_...       // Trigger.dev secret key: trigger and read your background jobs
unkey_...         // Unkey root key: create and revoke your customers' API keys
dub_...           // Dub API key: change where your short links point`}
        />
        <p className="text-zinc-300">
          Two of these are worse than they look. A leaked Convex deploy key lets someone replace your backend functions, so it is closer
          to a deploy credential than a data key. A leaked Unkey root key lets someone issue API keys for your own product to themselves.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>Keys with no prefix at all</h2>
        <p className="text-zinc-300">
          AssemblyAI, Deepgram, Loops, Novu, Attio and Daily use plain hex strings. Nothing about the value says what it is, so a scanner
          that flagged every 32 or 40 character hex string would also flag commit hashes, checksums and cache keys. We only report these
          when the value is assigned to the provider&apos;s own variable name or passed straight to its client:
        </p>
        <CodeBlock
          tone="bad"
          label="Reported"
          code={`const DEEPGRAM_API_KEY = "<40 hex characters>";
const client = new AssemblyAI({ apiKey: "<32 hex characters>" });`}
        />
        <CodeBlock
          label="Not reported"
          code={`const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY;
const sha = "<40 hex characters>"; // a git commit`}
        />
        <p className="text-zinc-300">
          The trade-off is that a key renamed to something generic like <code>KEY</code> slips through. We would rather miss that than
          send a team chasing commit hashes.
        </p>
      </section>

      <section className={SECTION}>
        <h2 className={H2}>If one of these is already in your repository</h2>
        <p className="text-zinc-300">
          Revoke it in the provider&apos;s dashboard first, then remove it from the code. Deleting the line does not help on its own: the
          key stays in git history and in every clone, fork and CI cache that already has it. Put the new key in a server-side environment
          variable (no <code>NEXT_PUBLIC_</code> or <code>VITE_</code> prefix) and call the provider from a route handler or server action
          instead of the browser.
        </p>
      </section>

      <ScanCta />
    </article>
  );
}
