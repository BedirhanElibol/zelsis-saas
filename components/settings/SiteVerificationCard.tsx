'use client';

import React, { useActionState, useEffect, useState } from 'react';
import { BadgeCheck, Check, Copy, Globe, Loader2, Trash2 } from 'lucide-react';
import { addSiteDomain, listSiteDomains, removeSiteDomain, verifySiteDomain } from '@/app/actions/site-verification';
import { PROBE_HEADER, initialSiteVerificationState, type SiteDomainSummary } from '@/lib/site-verification-state';
import { getActiveUserAuth } from '@/lib/supabase-client';

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="flex items-center gap-2 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-1.5">
      <code className="flex-1 text-[11px] text-zinc-300 break-all">{value}</code>
      <button type="button" onClick={copy} aria-label={`Copy ${label}`}
        className="shrink-0 p-1 rounded hover:bg-white/10 text-zinc-400 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
        {copied ? <Check size={13} className="text-emerald-400" aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
      </button>
    </div>
  );
}

/** Domain ownership for live-site scans: deep checks (dumps, credentials, admin consoles) run only on verified domains. */
export function SiteVerificationCard() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [domains, setDomains] = useState<SiteDomainSummary[]>([]);
  const [addState, addAction, adding] = useActionState(addSiteDomain, initialSiteVerificationState);
  const [verifyState, verifyAction, verifying] = useActionState(verifySiteDomain, initialSiteVerificationState);
  const [removeState, removeAction] = useActionState(removeSiteDomain, initialSiteVerificationState);

  // Reload after every action; state is set from the async callback, and dropped if the card unmounted meanwhile
  useEffect(() => {
    let alive = true;
    void getActiveUserAuth().then(async ({ accessToken: token }) => {
      const list = token ? await listSiteDomains(token) : [];
      if (alive) { setAccessToken(token); setDomains(list); }
    });
    return () => { alive = false; };
  }, [addState, verifyState, removeState]);

  if (!accessToken) return null;
  const last = [verifyState, addState, removeState].find((s) => s.status !== 'idle');

  return (
    <section className="bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Globe size={16} className="text-emerald-400" aria-hidden="true" />
        <h2 className="text-sm font-bold text-white">Verified domains for live scans</h2>
      </div>
      <p className="text-xs text-zinc-400 leading-relaxed">
        Every website scan checks headers, TLS, cookies and the JavaScript bundles. Deeper checks for exposed database dumps,
        cloud credentials, debug pages and admin consoles only run on domains you prove you own. Verifying a domain also
        covers its subdomains.
      </p>

      <form action={addAction} className="flex flex-col sm:flex-row gap-2">
        <input type="hidden" name="accessToken" value={accessToken} />
        <label htmlFor="site-domain" className="sr-only">Domain</label>
        <input id="site-domain" name="hostname" required placeholder="example.com"
          className="flex-1 bg-[#0A0A0A] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500" />
        <button type="submit" disabled={adding}
          className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 disabled:opacity-60 flex items-center justify-center gap-2 focus-visible:ring-2 focus-visible:ring-emerald-300 focus-visible:outline-none">
          {adding && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
          Add domain
        </button>
      </form>

      {last && <p role="status" className={`text-xs ${last.status === 'error' ? 'text-red-400' : 'text-emerald-400'}`}>{last.message}</p>}

      {domains.length > 0 && (
        <ul className="flex flex-col gap-3">
          {domains.map((d) => (
            <li key={d.hostname} className="border border-white/10 rounded-lg p-3 flex flex-col gap-2 text-xs">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  {d.verifiedAt
                    ? <BadgeCheck size={14} className="text-emerald-400 shrink-0" aria-hidden="true" />
                    : <Globe size={14} className="text-zinc-500 shrink-0" aria-hidden="true" />}
                  <span className="text-white font-medium truncate">{d.hostname}</span>
                  <span className={d.verifiedAt ? 'text-emerald-400' : 'text-amber-400'}>
                    {d.verifiedAt ? `verified ${new Date(d.verifiedAt).toLocaleDateString()} (${d.verifiedMethod === 'dns' ? 'DNS' : 'file'})` : 'not verified'}
                  </span>
                </div>
                <form action={removeAction} onSubmit={(e) => { if (!window.confirm(`Remove ${d.hostname}? Deep live checks stop for it.`)) e.preventDefault(); }}>
                  <input type="hidden" name="accessToken" value={accessToken} />
                  <input type="hidden" name="hostname" value={d.hostname} />
                  <button type="submit" aria-label={`Remove ${d.hostname}`}
                    className="p-1.5 rounded text-zinc-400 hover:text-red-400 hover:bg-white/5 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
                    <Trash2 size={14} aria-hidden="true" />
                  </button>
                </form>
              </div>

              {d.verifiedAt && d.probeKey && (
                <details className="text-zinc-400">
                  <summary className="cursor-pointer text-zinc-300 hover:text-white focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none rounded">
                    Firewall challenging deep checks? Allow the Zelsis probe header
                  </summary>
                  <div className="flex flex-col gap-2 mt-2">
                    <p>Deep checks request paths such as <code className="text-zinc-200">/.env</code> and <code className="text-zinc-200">/dump.sql</code>, which bot protection often challenges, so the scan reports them as unchecked. Each probe carries this header; keep the value private.</p>
                    <CopyValue label="header name" value={PROBE_HEADER} />
                    <CopyValue label="header value" value={d.probeKey} />
                    <p><span className="text-zinc-200">Vercel:</span> Firewall → Configure → New Rule: if Request Header <code className="text-zinc-200">{PROBE_HEADER}</code> equals the value, then Bypass. This skips your own and managed rules, but not Vercel&apos;s automatic per-IP challenge, which runs first; if checks still show as unchecked, ask Vercel support for a system bypass.</p>
                    <p><span className="text-zinc-200">Cloudflare:</span> Security → WAF → Custom rules: if the header equals the value, then Skip (managed rules and bot protection).</p>
                  </div>
                </details>
              )}

              {!d.verifiedAt && (
                <>
                  <p className="text-zinc-400">Option 1: serve this text at <code className="text-zinc-200">{d.fileUrl}</code></p>
                  <CopyValue label="verification token" value={d.token} />
                  <p className="text-zinc-400">Option 2: add a DNS TXT record on <code className="text-zinc-200">{d.hostname}</code></p>
                  <CopyValue label="TXT record value" value={d.dnsValue} />
                  <form action={verifyAction} className="self-start">
                    <input type="hidden" name="accessToken" value={accessToken} />
                    <input type="hidden" name="hostname" value={d.hostname} />
                    <button type="submit" disabled={verifying}
                      className="px-3 py-1.5 rounded-lg border border-emerald-500/40 text-emerald-300 font-bold hover:bg-emerald-500/10 disabled:opacity-60 flex items-center gap-2 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none">
                      {verifying && <Loader2 size={13} className="animate-spin" aria-hidden="true" />}
                      Verify
                    </button>
                  </form>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
